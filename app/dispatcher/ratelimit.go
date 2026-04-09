package dispatcher

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

type RateLimitWriter struct {
	Writer  buf.Writer
	Limiter *rate.Limiter
	Context context.Context
}

func (w *RateLimitWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.Limiter != nil {
		ctx := w.Context
		if ctx == nil {
			ctx = context.Background()
		}
		if err := w.Limiter.WaitN(ctx, int(mb.Len())); err != nil {
			buf.ReleaseMulti(mb)
			return err
		}
	}
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *RateLimitWriter) Close() error { return common.Close(w.Writer) }
func (w *RateLimitWriter) Interrupt()   { common.Interrupt(w.Writer) }
