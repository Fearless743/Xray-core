package mux

import (
	"io"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestSessionCloseXUDPWithTimeoutWrapperReader(t *testing.T) {
	r, _ := pipe.New(pipe.WithoutSizeLimit())
	wrapped := &buf.TimeoutWrapperReader{Reader: r}
	m := NewSessionManager()
	s := &Session{ID: 1, parent: m, input: wrapped, XUDP: &XUDP{Status: Active}}
	m.Add(s)
	if err := s.Close(false); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := wrapped.Recover(); err != nil && err != io.EOF {
		t.Fatalf("Recover() error = %v, want EOF or nil", err)
	}
}
