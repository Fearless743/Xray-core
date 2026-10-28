package dnsutil

import (
	"context"
	"net"
)

// OutboundDialer returns a plain net.Dialer. mark is ignored (Xray integration).
func OutboundDialer(mark int) *net.Dialer {
	return &net.Dialer{}
}

// Resolve resolves host:port using the system resolver (v0.5.2.0 name; was ResolveWithCache).
func Resolve(ctx context.Context, address string) (string, error) {
	return ResolveWithCache(ctx, address)
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
