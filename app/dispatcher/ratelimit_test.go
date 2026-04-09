package dispatcher

import (
	"context"
	"testing"

	bandwidthfeat "github.com/xtls/xray-core/features/bandwidth"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	featurepolicy "github.com/xtls/xray-core/features/policy"
	featurestats "github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"golang.org/x/time/rate"
)


type stubWriter struct{ calls int }
func (w *stubWriter) WriteMultiBuffer(mb buf.MultiBuffer) error { w.calls++; buf.ReleaseMulti(mb); return nil }
func (w *stubWriter) Close() error { return nil }
func (w *stubWriter) Interrupt() {}

type stubReader struct{}
func (stubReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, nil }
func (stubReader) Interrupt() {}

func TestApplyBandwidthLimitWrapsWriterOnly(t *testing.T) {
	bm := bandwidthfeat.New()
	bm.SetUserLimit("user@example.com", 1024)
	writer := &stubWriter{}
	reader := stubReader{}
	user := &protocol.MemoryUser{Email: "user@example.com"}
	wrapped := applyBandwidthLimit(context.Background(), writer, bm, user)
	if _, ok := wrapped.(*RateLimitWriter); !ok {
		t.Fatal("expected writer to be wrapped by RateLimitWriter")
	}
	if _, ok := any(reader).(stubReader); !ok {
		t.Fatal("reader type unexpectedly changed")
	}
}

func TestWrapLinkUsesBandwidthFeature(t *testing.T) {
	inst := new(core.Instance)
	bm := bandwidthfeat.New()
	bm.SetUserLimit("user@example.com", 1024)
	if err := inst.AddFeature(bm); err != nil {
		t.Fatalf("AddFeature(bandwidth) error = %v", err)
	}
	ctx := context.WithValue(context.Background(), core.XrayKey(1), inst)
	ctx = session.ContextWithInbound(ctx, &session.Inbound{User: &protocol.MemoryUser{Email: "user@example.com"}, Source: net.TCPDestination(net.IPAddress([]byte{127,0,0,1}), 1234)})
	link := &transport.Link{Reader: &buf.TimeoutWrapperReader{Reader: stubReader{}}, Writer: &stubWriter{}}
	_ = WrapLink(ctx, featurepolicy.DefaultManager{}, featurestats.NoopManager{}, link)
	if _, ok := link.Writer.(*RateLimitWriter); !ok {
		t.Fatal("expected WrapLink to wrap writer with bandwidth limiter")
	}
	if _, ok := link.Reader.(*buf.TimeoutWrapperReader); !ok {
		t.Fatal("expected reader wrapper to remain TimeoutWrapperReader")
	}
}


func TestRateLimitWriterRespectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := &RateLimitWriter{
		Writer:  &stubWriter{},
		Limiter: rate.NewLimiter(1, 1),
		Context: ctx,
	}
	b := buf.New()
	b.Extend(2)
	if err := w.WriteMultiBuffer(buf.MultiBuffer{b}); err == nil {
		t.Fatal("expected canceled context to abort wait")
	}
}
