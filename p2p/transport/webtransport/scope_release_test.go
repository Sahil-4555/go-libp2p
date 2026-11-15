package libp2pwebtransport_test

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
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

type wtSessStream struct {
	*webtransport.Stream
	sess *webtransport.Session
}

func (c wtSessStream) LocalAddr() net.Addr  { return c.sess.LocalAddr() }
func (c wtSessStream) RemoteAddr() net.Addr { return c.sess.RemoteAddr() }

// TestFailedRequestDoesNotReleaseLiveConnScope reproduces the default libp2p
// configuration, where quicreuse's ConnContext opens one resource-manager
// connection scope per QUIC connection and stores it in the request context.
//
// The WebTransport HTTP handler calls connScope.Done() whenever a request on
// that QUIC connection fails. A peer that already has an established libp2p
// WebTransport connection can send one more (failing) request on the same QUIC
// connection, e.g. a GET to the WebTransport endpoint, and thereby release the
// scope of its live connection. The resource manager then stops counting that
// connection, so inbound connection limits can be bypassed.
func TestFailedRequestDoesNotReleaseLiveConnScope(t *testing.T) {
	// Allow exactly one inbound connection.
	limits := rcmgr.PartialLimitConfig{
		System: rcmgr.ResourceLimits{ConnsInbound: 1},
	}.Build(rcmgr.InfiniteLimits)
	rm, err := rcmgr.NewResourceManager(rcmgr.NewFixedLimiter(limits))
	require.NoError(t, err)
	defer rm.Close()

	// Same wiring as config.go's default quicreuse.ConnManager.
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

	// 1. Establish a regular libp2p WebTransport connection (WebTransport
	//    session + Noise handshake), counted against ConnsInbound.
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

	// Control: the limit is enforced, a second connection is refused.
	if c, err := dialQUIC(); err == nil {
		c.CloseWithError(0, "")
		t.Fatal("second inbound connection accepted although ConnsInbound=1")
	}

	// 2. Send one failing request (not a CONNECT) on the same QUIC connection.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	require.NoError(t, err)
	rsp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	rsp.Body.Close()
	t.Logf("GET on the established QUIC connection returned %d", rsp.StatusCode)
	require.False(t, sconn.IsClosed(), "the established connection must still be up")

	// 3. The live connection must still count against the limit.
	if c, err := dialQUIC(); err == nil {
		c.CloseWithError(0, "")
		t.Fatal("a failed request released the resource scope of the live connection: a second inbound connection was accepted although ConnsInbound=1")
	}
}
