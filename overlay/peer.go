package overlay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"

	"github.com/pkg/errors"
	"github.com/stellar/go/xdr"
)

type PeerState int

const (
	PeerStateConnecting = iota
	PeerStateConnected
	PeerStateGotHello
	PeerStateGotAuth
	PeerStateClosing
)

// Another peer out there that we are connected to
type Peer struct {
	PeerState

	sendMacKey xdr.HmacSha256Key
	recvMacKey xdr.HmacSha256Key

	sendMacSeq uint64
	recvMacSeq uint64
}

func (p *Peer) sendMessage(msg *xdr.StellarMessage) {
	//TODO
	/*
			if (Logging::logTrace("Overlay"))
		        CLOG(TRACE, "Overlay")
		            << "("
		            << mApp.getConfig().toShortString(
		                   mApp.getConfig().NODE_SEED.getPublicKey())
		            << ") send: " << msgSummary(msg)
		            << " to : " << mApp.getConfig().toShortString(mPeerID);
	*/

	switch msg.Type {
	case xdr.MessageTypeErrorMsg:
		//SendErrorMeter.Mark() metric
	case xdr.MessageTypeHello:
		//SendHelloMeter.Mark()
		// ...
	}

	amsg := new(xdr.AuthenticatedMessage)
	amsg.V0.Message = *msg

	//TODO ensure this works
	if msg.Type != xdr.MessageTypeHello && msg.Type != xdr.MessageTypeErrorMsg {
		amsg.V0.Sequence = xdr.Uint64(p.sendMacSeq)

		seqBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(seqBytes, p.sendMacSeq)

		msgBytes, err := msg.MarshalBinary()
		if err != nil {
			panic(errors.Wrap(err, "failed to marshal stellar msg"))
		}

		h := hmac.New(sha256.New, p.sendMacKey.Key[:])
		_, err = h.Write(append(seqBytes, msgBytes...))
		if err != nil {
			panic(errors.Wrap(err, "failed to write hmac hash"))
		}

		copy(amsg.V0.Mac.Mac[:], h.Sum(nil))

		p.sendMacSeq++
	}

	//TODO figure out how to send tcp here
}
