package middlewares

import (
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/mdblp/shoreline/common/logging"
)

type handler struct{ Log *log.Entry }

func New(mainLog *log.Entry) (h handler) {
	return handler{
		Log: mainLog,
	}
}

func GetLogReq(r *http.Request) *log.Entry {
	return logging.FromContext(r.Context())
}

func (h handler) LoggingMiddleware(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		if traceSessionId, ok := GetTraceSessionIdCtx(ctx); ok {
			h.Log = h.Log.WithFields(log.Fields{"trace-session": traceSessionId})
		}
		if requestId, ok := GetRequestIdCtx(ctx); ok {
			h.Log = h.Log.WithFields(log.Fields{"request-id": requestId})
		}

		ctx = logging.WithLogger(ctx, h.Log)
		startTime := time.Now()

		next.ServeHTTP(w, r.WithContext(ctx))

		duration := time.Since(startTime).Milliseconds()
		reqMethod := r.Method
		reqUri := r.URL.Path
		statusCode := "NA" // not available in handlers...jsut created the field
		if reqUri != "/status" {
			log := log.Fields{
				"method":     reqMethod,
				"uri":        reqUri,
				"statusCode": statusCode,
				"duration":   duration,
			}
			h.Log.WithFields(log).Info()
		}
	}

	return http.HandlerFunc(fn)
}
