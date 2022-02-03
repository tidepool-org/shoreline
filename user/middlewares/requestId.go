package middlewares

import (
	"context"
	"net/http"
	"github.com/google/uuid"
)

type reqIdKeyType int
const reqIdKey  reqIdKeyType = iota

func GetRequestIdCtx(ctx context.Context) (string, bool) {
	reqId, ok := ctx.Value(reqIdKey).(string)
	return reqId, ok
}

func RequestIdMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
	
		reqId := uuid.New().String()
		ctx = context.WithValue(ctx, reqIdKey, reqId)

		next.ServeHTTP(w, r.WithContext(ctx))
	}

	return http.HandlerFunc(fn)
}