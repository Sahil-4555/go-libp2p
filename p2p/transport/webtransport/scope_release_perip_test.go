package libp2pwebtransport_test

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
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

// TestFailedRequestDoesNotReleasePerIPConnLimiterSlot demonstrates that the M1
// bypass is not limited to the System.ConnsInbound gate: a failed request on an
// established connection also frees that connection's per-IP connLimiter slot.
//
// This is the in-process, real-component demonstration of the per-IP property
// that a distinct-source-IP multi-node run would otherwise show. It uses the
// real resource manager with an *infinite* System inbound limit (so the system
// gate is not what blocks anything) and a per-IP network-prefix limit of 1 for
// loopback (overriding rcmgr's default "localhost always succeeds" exemption),
// so the connLimiter is the only binding gate.
func TestFailedRequestDoesNotReleasePerIPConnLimiterSlot(t *testing.T) {
	// System inbound limit is infinite; the ONLY gate is the per-IP connLimiter.
	rm, err := rcmgr.NewResourceManager(
		rcmgr.NewFixedLimiter(rcmgr.InfiniteLimits),
		// Override the default loopback exemption: allow exactly one concurrent
		// connection from 127.0.0.0/8.
		rcmgr.WithNetworkPrefixLimit([]rcmgr.NetworkPrefixLimit{
			{Network: netip.MustParsePrefix("127.0.0.0/8"), ConnCount: 1},
		}, nil),
	)
	require.NoError(t, err)
	defer rm.Close()

	// Same wiring as config.go's default quicreuse.ConnManager: one shared rcmgr
	// connection scope per QUIC connection, released by context.AfterFunc on close.
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dialQUIC := func() (*quic.Conn, error) {
		return quic.DialAddr(ctx, ln.Addr().String(),
			&tls.Config{InsecureSkipVerify: true, NextProtos: []string{http3.NextProtoH3}},
			&quic.Config{EnableDatagrams: true, EnableStreamResetPartialDelivery: true, HandshakeIdleTimeout: time.Second})
	}

	// 1. Establish a regular libp2p WebTransport connection from loopback. It
	//    takes the single per-IP slot for 127.0.0.0/8.
	qconn, err := dialQUIC()
	require.NoError(t, err)
	defer qconn.CloseWithError(0, "")
	cc, err := (&webtransport.Transport{}).NewClientConn(qconn)
	require.NoError(t, err)
	_, sess, err := cc.Dial(ctx, endpoint, nil)
	require.NoError(t, err)
	str, err := sess.OpenStreamSync(ctx)
	require.NoError(t, err)
	_, clientKey := newIdentity(t)
	n, err := noise.New(noise.ID, clientKey, nil)
	require.NoError(t, err)
	st, err := n.WithSessionOptions()
	require.NoError(t, err)
	_, err = st.SecureOutbound(ctx, wtSessStream{Stream: str, sess: sess}, serverID)
	require.NoError(t, err)
	sconn, err := ln.Accept()
	require.NoError(t, err)
	defer sconn.Close()
	require.False(t, sconn.IsClosed())

	// Control: the per-IP limit is enforced; a second loopback connection is refused.
	if c, err := dialQUIC(); err == nil {
		c.CloseWithError(0, "")
		t.Fatal("second loopback connection accepted although per-IP limit is 1")
	}

	// 2. Send one failing request (GET, not CONNECT) on the same QUIC connection.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	require.NoError(t, err)
	rsp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	rsp.Body.Close()
	t.Logf("GET on the established QUIC connection returned %d", rsp.StatusCode)
	require.False(t, sconn.IsClosed(), "the established connection must still be up")

	// 3. The live connection must still hold its per-IP slot.
	if c, err := dialQUIC(); err == nil {
		c.CloseWithError(0, "")
		t.Fatal("a failed request released the per-IP connLimiter slot of the live connection: a second loopback connection was accepted although the per-IP limit is 1")
	}
}
