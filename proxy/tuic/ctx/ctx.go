package ctx

import (
	"context"

	"github.com/xtls/xray-core/proxy/tuic/account"
)

type key int

const validatorKey key = iota

func ContextWithValidator(ctx context.Context, v *account.Validator) context.Context {
	return context.WithValue(ctx, validatorKey, v)
}

func ValidatorFromContext(ctx context.Context) *account.Validator {
	v, _ := ctx.Value(validatorKey).(*account.Validator)
	return v
}
