//go:build linux

package datalink

import (
	"fmt"
	"net"

	"github.com/mdlayher/packet"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	isispkt "github.com/takehaya/goisis/pkg/packet"
)

// llcFilter accepts only frames whose first two octets are the IS-IS LLC
// SAPs (0xFE 0xFE). On a SOCK_DGRAM/ETH_P_802_2 socket the payload begins at
// the LLC header, so this rejects every non-IS-IS 802.3 frame in the kernel.
var llcFilter = mustAssemble([]bpf.Instruction{
	bpf.LoadAbsolute{Off: 0, Size: 2},
	bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0xfefe, SkipTrue: 0, SkipFalse: 1},
	bpf.RetConstant{Val: 0x40000}, // accept up to 256 KiB
	bpf.RetConstant{Val: 0},       // drop
})

func mustAssemble(insns []bpf.Instruction) []bpf.RawInstruction {
	raw, err := bpf.Assemble(insns)
	if err != nil {
		panic(fmt.Sprintf("datalink: BPF assemble: %v", err))
	}
	return raw
}

// LinuxTransport carries IS-IS PDUs over an Ethernet interface using
// AF_PACKET. It works for both broadcast and point-to-point circuits: the
// 802.3/LLC framing is identical (verified against FRR), only the
// destination multicast group differs and is chosen by the caller. The
// transport joins all three IS-IS groups so it receives L1, L2, and
// AllISs (p2p) frames regardless of circuit type.
type LinuxTransport struct {
	conn *packet.Conn
	ifi  *net.Interface
	snpa isispkt.SNPA
}

// OpenLinux opens an AF_PACKET transport on the named interface. It requires
// CAP_NET_RAW.
func OpenLinux(ifname string) (Transport, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("datalink: interface %q: %w", ifname, err)
	}
	if len(ifi.HardwareAddr) != 6 {
		return nil, fmt.Errorf("datalink: interface %q has no 6-octet MAC", ifname)
	}

	conn, err := packet.Listen(ifi, packet.Datagram, unix.ETH_P_802_2, &packet.Config{Filter: llcFilter})
	if err != nil {
		return nil, fmt.Errorf("datalink: listen on %q: %w", ifname, err)
	}

	t := &LinuxTransport{conn: conn, ifi: ifi, snpa: isispkt.SNPA(ifi.HardwareAddr)}
	for _, group := range []isispkt.SNPA{AllL1ISs, AllL2ISs, AllISs} {
		if err := t.joinGroup(group); err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	return t, nil
}

// joinGroup adds a multicast MAC membership. mdlayher/packet exposes no API
// for PACKET_MR_MULTICAST, so it is set through the raw fd.
func (t *LinuxTransport) joinGroup(group isispkt.SNPA) error {
	rc, err := t.conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("datalink: syscall conn: %w", err)
	}
	mreq := unix.PacketMreq{
		Ifindex: int32(t.ifi.Index), //nolint:gosec // interface index fits int32
		Type:    unix.PACKET_MR_MULTICAST,
		Alen:    6,
	}
	copy(mreq.Address[:], group[:])
	var setErr error
	if err := rc.Control(func(fd uintptr) {
		setErr = unix.SetsockoptPacketMreq(int(fd), unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq)
	}); err != nil {
		return fmt.Errorf("datalink: control fd: %w", err)
	}
	if setErr != nil {
		return fmt.Errorf("datalink: join %v: %w", group, setErr)
	}
	return nil
}

// Send implements Transport: it prepends the LLC header and transmits to dst.
func (t *LinuxTransport) Send(dst isispkt.SNPA, pdu []byte) error {
	frame := make([]byte, 0, len(llcHeader)+len(pdu))
	frame = append(frame, llcHeader[:]...)
	frame = append(frame, pdu...)
	_, err := t.conn.WriteTo(frame, &packet.Addr{HardwareAddr: net.HardwareAddr(dst[:])})
	if err != nil {
		return fmt.Errorf("datalink: send: %w", err)
	}
	return nil
}

// Recv implements Transport: it returns the next IS-IS PDU with the LLC
// header stripped.
func (t *LinuxTransport) Recv() (Frame, error) {
	buf := make([]byte, t.ifi.MTU+len(llcHeader)+64)
	for {
		n, addr, err := t.conn.ReadFrom(buf)
		if err != nil {
			return Frame{}, ErrClosed
		}
		if n < len(llcHeader) {
			continue // too short to carry an LLC header
		}
		pa, ok := addr.(*packet.Addr)
		if !ok || len(pa.HardwareAddr) != 6 {
			continue
		}
		pdu := make([]byte, n-len(llcHeader))
		copy(pdu, buf[len(llcHeader):n])
		return Frame{PDU: pdu, Src: isispkt.SNPA(pa.HardwareAddr)}, nil
	}
}

// LocalSNPA implements Transport.
func (t *LinuxTransport) LocalSNPA() isispkt.SNPA { return t.snpa }

// MTU implements Transport.
func (t *LinuxTransport) MTU() int { return t.ifi.MTU }

// Close implements Transport.
func (t *LinuxTransport) Close() error { return t.conn.Close() }
