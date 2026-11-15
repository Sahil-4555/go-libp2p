package libp2pwebtransport_test

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	tpt "github.com/libp2p/go-libp2p/core/transport"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/p2p/security/noise"
	"github.com/libp2p/go-libp2p/p2p/transport/quicreuse"
	libp2pwebtransport "github.com/libp2p/go-libp2p/p2p/transport/webtransport"

	ma "github.com/multiformats/go-multiaddr"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
	"github.com/stretchr/testify/require"
)

// TestFailedRequestsEnableUnboundedInboundAccumulation shows the accumulation
// impact of M1 in a single process with real components: the bypass is not a
// one-off "limit+1", it lets a peer hold an unbounded number of simultaneously
// live inbound connections. With System.ConnsInbound=N it establishes N real
// connections, frees every one's inbound slot with a single failing request,
// and then admits N more while the first N remain live — 2N live against a
// limit of N. This is the property a distinct-host multi-node run would show,
// demonstrated here with the real resource manager, the real quicreuse
// ConnContext wiring, real QUIC, and real WebTransport+Noise handshakes.
func TestFailedRequestsEnableUnboundedInboundAccumulation(t *testing.T) {
	const N = 3

	limits := rcmgr.PartialLimitConfig{
		System: rcmgr.ResourceLimits{ConnsInbound: rcmgr.LimitVal(N)},
	}.Build(rcmgr.InfiniteLimits)
	rm, err := rcmgr.NewResourceManager(rcmgr.NewFixedLimiter(limits))
	require.NoError(t, err)
	defer rm.Close()

	cm := newConnManager(t, quicreuse.ConnContext(func(ctx context.Context, ci *quic.ClientInfo) (context.Context, error) {
		addr, err := quicreuse.ToQuicMultiaddr(ci.RemoteAddr, quic.Version1)
		if err != nil {
			addr = nil
		}
		scope, err := rm.OpenConnection(network.DirInbound, false, addr)
		if err != nil {
			return ctx, err
		}
		ctx = network.WithConnManagementScope(ctx, scope)
		context.AfterFunc(ctx, scope.Done)
		return ctx, nil
	}))

	serverID, serverKey := newIdentity(t)
	tr, err := libp2pwebtransport.New(serverKey, nil, cm, nil, rm)
	require.NoError(t, err)
	defer tr.(io.Closer).Close()
	ln, err := tr.Listen(ma.StringCast("/ip4/127.0.0.1/udp/0/quic-v1/webtransport"))
	require.NoError(t, err)
	defer ln.Close()
	endpoint := "https://" + ln.Addr().String() + "/.well-known/libp2p-webtransport?type=noise"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Background accepter: drain the listener so the server stays healthy and we
	// can count how many inbound connections are simultaneously live.
	var mu sync.Mutex
	var accepted []tpt.CapableConn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			accepted = append(accepted, c)
			mu.Unlock()
		}
	}()
	liveCount := func() int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, c := range accepted {
			if !c.IsClosed() {
				n++
			}
		}
		return n
	}

	dialQUIC := func() (*quic.Conn, error) {
		return quic.DialAddr(ctx, ln.Addr().String(),
			&tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}},
			&quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true, HandshakeIdleTimeout: time.Second})
	}

	// establish performs a full libp2p WebTransport + Noise handshake and returns
	// the live client handles (so the caller can send a later failing request).
	establish := func() (*quic.Conn, *webtransport.ClientConn, error) {
		qconn, err := dialQUIC()
		if err != nil {
			return nil, nil, err
		}
		cc, err := (&webtransport.Transport{}).NewClientConn(qconn)
		if err != nil {
			qconn.CloseWithError(0, "")
			return nil, nil, err
		}
		_, sess, err := cc.Dial(ctx, endpoint, nil)
		if err != nil {
			qconn.CloseWithError(0, "")
			return nil, nil, err
		}
		str, err := sess.OpenStreamSync(ctx)
		if err != nil {
			qconn.CloseWithError(0, "")
			return nil, nil, err
		}
		_, clientKey := newIdentity(t)
		n, err := noise.New(noise.ID, clientKey, nil)
		if err != nil {
			qconn.CloseWithError(0, "")
			return nil, nil, err
		}
		st, err := n.WithSessionOptions()
		if err != nil {
			qconn.CloseWithError(0, "")
			return nil, nil, err
		}
		if _, err := st.SecureOutbound(ctx, wtSessStream{Stream: str, sess: sess}, serverID); err != nil {
			qconn.CloseWithError(0, "")
			return nil, nil, err
		}
		return qconn, cc, nil
	}

	// Batch 1: establish N connections, filling the inbound limit exactly.
	var qconns []*quic.Conn
	var batch1 []*webtransport.ClientConn
	defer func() {
		for _, q := range qconns {
			q.CloseWithError(0, "")
		}
	}()
	for i := 0; i < N; i++ {
		q, cc, err := establish()
		require.NoErrorf(t, err, "establishing connection %d/%d within the limit", i+1, N)
		qconns = append(qconns, q)
		batch1 = append(batch1, cc)
	}
	require.Eventually(t, func() bool { return liveCount() == N }, 5*time.Second, 20*time.Millisecond,
		"the first N connections should be accepted and live")

	// Control: the limit is enforced; an extra connection is refused.
	if c, err := dialQUIC(); err == nil {
		c.CloseWithError(0, "")
		t.Fatal("an over-limit connection was accepted before any failing request")
	}

	// Free every live connection's inbound slot with one failing GET each.
	for _, cc := range batch1 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		require.NoError(t, err)
		rsp, err := cc.RoundTrip(req)
		require.NoError(t, err)
		rsp.Body.Close()
	}

	// Batch 2: try to establish N more while the first N are still live. On a
	// correct implementation every one of these is refused by the still-full
	// limit; establish() fails at the QUIC dial because OpenConnection is denied.
	overLimitAdmitted := 0
	for i := 0; i < N; i++ {
		q, _, err := establish()
		if err != nil {
			break
		}
		overLimitAdmitted++
		qconns = append(qconns, q)
	}

	// The original N connections must still be live (the failing requests must
	// not have torn them down).
	require.GreaterOrEqual(t, liveCount(), N, "the original N connections must remain live")

	// The limit must have held: no connection may be admitted beyond ConnsInbound.
	require.Zerof(t, overLimitAdmitted,
		"with ConnsInbound=%d and %d connections already live, a failing request on each freed its inbound slot and let %d more connections be admitted (%d simultaneously live against a limit of %d): unbounded inbound-limit bypass",
		N, N, overLimitAdmitted, N+overLimitAdmitted, N)
}
