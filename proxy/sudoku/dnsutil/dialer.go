package dnsutil

import (
	"context"
	"net"
)

// OutboundDialer returns a plain net.Dialer. mark is ignored (Xray integration).
func OutboundDialer(mark int) *net.Dialer {
	return &net.Dialer{}
}

// ResolveWithCache resolves host:port using the system resolver.
func ResolveWithCache(ctx context.Context, address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	if ip := net.ParseIP(host); ip != nil {
		return address, nil
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}
	if len(ips) == 0 {
		return "", &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return net.JoinHostPort(ips[0].IP.String(), port), nil
}
