package middlewares

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

type traceSessionIdKeyType int
const traceSessionIdKey traceSessionIdKeyType = 1

func GetTraceSessionIdCtx(ctx context.Context) (string, bool) {
	traceSessionId, ok := ctx.Value(traceSessionIdKey).(string)
	return traceSessionId, ok
}

func TraceSessionIdMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		var traceSessionId string
		// can not reuse already declared header and sanatize functoin as it create a loop dependancies
		if traceSessionId = r.Header.Get("x-tidepool-trace-session"); traceSessionId == "" { // sanatize ?
			// first occurrence
			traceSessionId = uuid.New().String()
		}

		ctx = context.WithValue(ctx, traceSessionIdKey, traceSessionId)

		next.ServeHTTP(w, r.WithContext(ctx))
	}

	return http.HandlerFunc(fn)
}