package ctx

import (
	"context"

	"github.com/xtls/xray-core/proxy/mieru/account"
)

type key int

const (
	validatorKey key = iota
	transportKey
	trafficPatternKey
)

func ContextWithValidator(ctx context.Context, v *account.Validator) context.Context {
	return context.WithValue(ctx, validatorKey, v)
}

func ValidatorFromContext(ctx context.Context) *account.Validator {
	v, _ := ctx.Value(validatorKey).(*account.Validator)
	return v
}

func ContextWithTransport(ctx context.Context, t string) context.Context {
	return context.WithValue(ctx, transportKey, t)
}

func TransportFromContext(ctx context.Context) string {
	t, _ := ctx.Value(transportKey).(string)
	return t
}

func ContextWithTrafficPattern(ctx context.Context, p string) context.Context {
	return context.WithValue(ctx, trafficPatternKey, p)
}

func TrafficPatternFromContext(ctx context.Context) string {
	p, _ := ctx.Value(trafficPatternKey).(string)
	return p
}
