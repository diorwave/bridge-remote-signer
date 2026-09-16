package consensus

import (
	"context"
	"io"
	"net"
	"time"

	"github.com/cometbft/cometbft/crypto"
	"github.com/cometbft/cometbft/libs/log"
	"github.com/cometbft/cometbft/libs/protoio"
	"github.com/cometbft/cometbft/privval"
	privvalproto "github.com/cometbft/cometbft/proto/tendermint/privval"
	"github.com/cometbft/cometbft/types"

	"github.com/tellor-io/bridge-remote-signer/metrics"
)

// MaxRemoteSignerMsgSize is the max decoded privval frame (CometBFT default).
const MaxRemoteSignerMsgSize = 1024 * 10

// RunDialClient maintains a TCP+SecretConnection to a CometBFT node's
// priv_validator_laddr and serves privval requests until disconnect, then
// reconnects. Multiple RunDialClient goroutines may share the same PrivValidator
// if it is wrapped with LockedPrivValidator.
func RunDialClient(
	ctx context.Context,
	targetAddr string,
	chainID string,
	connPrivKey crypto.PrivKey,
	pv types.PrivValidator,
	handler privval.ValidationRequestHandlerFunc,
	arbiter *PrimaryArbiter,
	logger log.Logger,
) {
	// When a primary arbiter is configured, only the elected node's sign
	// requests are honored (active-passive); others are refused without signing.
	if arbiter != nil {
		handler = gatedHandler(arbiter, targetAddr, handler)
	}
	dialer := privval.DialTCPFn(targetAddr, 8*time.Second, connPrivKey)
	metrics.SetTargetConnected(targetAddr, false) // start disconnected until the first dial succeeds
	runDialClient(ctx, dialer, chainID, pv, handler, logger.With("remote", targetAddr), func(connected bool) {
		metrics.SetTargetConnected(targetAddr, connected)
		switch {
		case connected:
		case arbiter != nil:
			arbiter.Release(targetAddr)
		}
	})
}

// notPrimaryResponse builds the refusal a non-primary node receives for a sign
// request, along with the height the request is for. For non-sign requests
// (pubkey, ping) it returns (_, _, false) so they always pass through.
func notPrimaryResponse(req privvalproto.Message) (privvalproto.Message, int64, bool) {
	switch r := req.Sum.(type) {
	case *privvalproto.Message_SignVoteRequest:
		return wrapMsg(&privvalproto.SignedVoteResponse{Error: remoteErr("not the primary signer")}), r.SignVoteRequest.Vote.Height, true
	case *privvalproto.Message_SignProposalRequest:
		return wrapMsg(&privvalproto.SignedProposalResponse{Error: remoteErr("not the primary signer")}), r.SignProposalRequest.Proposal.Height, true
	default:
		return privvalproto.Message{}, 0, false
	}
}

// gatedHandler wraps a validation handler so that vote/proposal requests are only
// signed when id is the primary signer (per the arbiter); otherwise it returns a
// "not the primary signer" error without signing. Pubkey/ping requests pass
// through unconditionally so the connection stays healthy.
func gatedHandler(arbiter *PrimaryArbiter, id string, next privval.ValidationRequestHandlerFunc) privval.ValidationRequestHandlerFunc {
	return func(pv types.PrivValidator, req privvalproto.Message, chainID string) (privvalproto.Message, error) {
		refusal, height, isSign := notPrimaryResponse(req)
		if isSign {
			if !arbiter.Acquire(id, height) {
				return refusal, nil
			}
			// The elected primary just had a consensus vote/proposal signed, so it is the
			// active signing node. Recording it here (rather than on bridge signatures, which
			// both nodes always send) makes signer_active_node track the consensus primary,
			// so it changes only on a real failover.
			metrics.RecordSign(id)
		}
		return next(pv, req, chainID)
	}
}

// runDialClient is the internal implementation that accepts an injectable dial
// function. Used directly in tests.
func runDialClient(
	ctx context.Context,
	dialFn func() (net.Conn, error),
	chainID string,
	pv types.PrivValidator,
	handler privval.ValidationRequestHandlerFunc,
	logger log.Logger,
	onState func(connected bool),
) {
	if onState == nil {
		onState = func(bool) {}
	}
	const (
		minBackoff = time.Second
		maxBackoff = 5 * time.Second
	)
	backoff := minBackoff

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := dialFn()
		if err != nil {
			onState(false)
			logger.Error("privval dial failed", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}

			// Exponential backoff: 1s → 2s → 4s … capped at 5s
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		logger.Info("privval connected")
		onState(true)
		backoff = minBackoff // reset on successful connection
		serveConn(ctx, conn, chainID, pv, handler, logger)
		_ = conn.Close()
		onState(false)
		logger.Info("privval connection closed, reconnecting")

		select {
		case <-ctx.Done():
			return
		case <-time.After(300 * time.Millisecond):
		}
	}
}

// serveConn handles one privval connection until disconnect or ctx cancellation.
// A goroutine closes conn when ctx is done so rd.ReadMsg() unblocks promptly.
func serveConn(
	ctx context.Context,
	conn net.Conn,
	chainID string,
	pv types.PrivValidator,
	handler privval.ValidationRequestHandlerFunc,
	logger log.Logger,
) {
	// Close conn on context cancellation to unblock any blocking read.
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	rd := protoio.NewDelimitedReader(conn, MaxRemoteSignerMsgSize)
	wr := protoio.NewDelimitedWriter(conn)
	deadline := 10 * time.Second

	for {
		_ = conn.SetReadDeadline(time.Now().Add(deadline))
		var req privvalproto.Message
		_, err := rd.ReadMsg(&req)
		if err != nil {
			if err != io.EOF && ctx.Err() == nil {
				logger.Error("privval read", "err", err)
			}
			return
		}

		res, handleErr := handler(pv, req, chainID)
		if handleErr != nil {
			logger.Error("privval handler", "err", handleErr)
		}

		_ = conn.SetWriteDeadline(time.Now().Add(deadline))
		if _, err := wr.WriteMsg(&res); err != nil {
			logger.Error("privval write", "err", err)
			return
		}
	}
}
