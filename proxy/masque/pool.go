package masque

import (
	"net/netip"
	"sync"
)

// addressPool allocates client addresses from a single tunnel prefix.
// Neither the network address nor the server address (the prefix address
// as configured, e.g. 10.0.0.1 in 10.0.0.1/24) are ever allocated.
type addressPool struct {
	prefix     netip.Prefix
	serverAddr netip.Addr
	next       netip.Addr
	used       map[netip.Addr]struct{}
	mu         sync.Mutex
}

func newAddressPool(prefix netip.Prefix) *addressPool {
	masked := prefix.Masked()
	p := &addressPool{
		prefix:     masked,
		serverAddr: prefix.Addr(),
		used:       make(map[netip.Addr]struct{}),
	}
	p.next = masked.Addr()
	return p
}

func (p *addressPool) skip(addr netip.Addr) bool {
	if addr == p.serverAddr {
		return true
	}
	// Skip the network address (all host bits zero).
	if addr == p.prefix.Masked().Addr() {
		return true
	}
	return false
}

// allocate returns the next free address, or false when exhausted.
func (p *addressPool) allocate() (netip.Addr, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := 0; i < 131072; i++ {
		if !p.prefix.Contains(p.next) {
			// Wrap around to reuse released addresses.
			p.next = p.prefix.Masked().Addr()
			continue
		}
		candidate := p.next
		p.next = p.next.Next()
		if !candidate.IsValid() || p.skip(candidate) {
			continue
		}
		if _, taken := p.used[candidate]; taken {
			continue
		}
		p.used[candidate] = struct{}{}
		return candidate, true
	}
	return netip.Addr{}, false
}

// release returns an address to the pool.
func (p *addressPool) release(addr netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, addr)
}

// contains reports whether addr belongs to this pool's prefix.
func (p *addressPool) contains(addr netip.Addr) bool {
	return addr.IsValid() && p.prefix.Contains(addr)
}
