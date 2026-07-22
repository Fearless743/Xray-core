package shadowquic

import (
	"net"
	"sync"
	"time"

	"github.com/metacubex/jls-quic-go"
	xnet "github.com/xtls/xray-core/common/net"
)

const packetInputQueue = 128

type association struct {
	parent  *connState
	mode    udpMode
	control *quic.Stream

	input chan receivedPacket

	mu         sync.Mutex
	sendIDs    map[string]uint16
	sendIDSet  map[uint16]struct{}
	recvIDSet  map[uint16]struct{}
	uniStreams map[string]*quic.SendStream

	closed    chan struct{}
	closeOnce sync.Once
}

func newAssociation(parent *connState, control *quic.Stream, mode udpMode) *association {
	a := &association{
		parent:     parent,
		mode:       mode,
		control:    control,
		input:      make(chan receivedPacket, packetInputQueue),
		sendIDs:    make(map[string]uint16),
		sendIDSet:  make(map[uint16]struct{}),
		recvIDSet:  make(map[uint16]struct{}),
		uniStreams: make(map[string]*quic.SendStream),
		closed:     make(chan struct{}),
	}
	go a.readControl()
	go func() {
		<-parent.ctx.Done()
		_ = a.Close()
	}()
	return a
}

func (a *association) readControl() {
	defer a.Close()

	for {
		addr, port, id, err := ReadUDPControl(a.control)
		if err != nil {
			return
		}
		dest := destinationFromAddrPort(addr, port, xnet.Network_UDP)
		a.mu.Lock()
		a.recvIDSet[id] = struct{}{}
		a.mu.Unlock()
		a.parent.storeRecv(id, a, dest)
	}
}

func (a *association) deliver(packet receivedPacket) {
	select {
	case a.input <- packet:
	case <-a.closed:
	default:
	}
}

func (a *association) writeTo(p []byte, dest xnet.Destination) (n int, err error) {
	if len(p) > maxUDPPacketSize {
		return 0, errPacketTooLarge
	}
	select {
	case <-a.closed:
		return 0, net.ErrClosed
	default:
	}

	addr, port := destinationToAddrPort(dest)
	key := addressKey(addr, port)

	a.mu.Lock()
	defer a.mu.Unlock()

	id, exists := a.sendIDs[key]
	if !exists {
		id, err = a.parent.allocSendID()
		if err != nil {
			return 0, err
		}
		if err = WriteUDPControl(a.control, addr, port, id); err != nil {
			a.parent.releaseSendIDs(map[uint16]struct{}{id: {}})
			return 0, err
		}
		a.sendIDs[key] = id
		a.sendIDSet[id] = struct{}{}
	}

	switch a.mode {
	case udpModeStream:
		stream := a.uniStreams[key]
		if stream == nil {
			stream, err = a.parent.quicConn.OpenUniStreamSync(a.parent.ctx)
			if err != nil {
				return 0, err
			}
			if err = WritePacketStreamHeader(stream, id); err != nil {
				_ = stream.Close()
				return 0, err
			}
			a.uniStreams[key] = stream
		}
		if err = WritePacketStreamPayload(stream, p); err != nil {
			return 0, err
		}
	default:
		packet, err := EncodeDatagram(id, p)
		if err != nil {
			return 0, err
		}
		if err = a.parent.quicConn.SendDatagram(packet); err != nil {
			return 0, err
		}
	}

	return len(p), nil
}

func (a *association) Close() error {
	a.closeOnce.Do(func() {
		close(a.closed)
		a.close()
	})
	return nil
}

func (a *association) close() {
	a.control.CancelRead(0)
	_ = a.control.SetWriteDeadline(time.Now())

	a.mu.Lock()
	sendIDSet := make(map[uint16]struct{}, len(a.sendIDSet))
	for id := range a.sendIDSet {
		sendIDSet[id] = struct{}{}
	}
	recvIDSet := make(map[uint16]struct{}, len(a.recvIDSet))
	for id := range a.recvIDSet {
		recvIDSet[id] = struct{}{}
	}
	for _, stream := range a.uniStreams {
		_ = stream.Close()
	}
	a.mu.Unlock()

	a.parent.releaseSendIDs(sendIDSet)
	a.parent.removeRecvIDs(a, recvIDSet)
	_ = a.control.Close()
}

func (a *association) LocalAddr() net.Addr {
	return a.parent.quicConn.LocalAddr()
}
