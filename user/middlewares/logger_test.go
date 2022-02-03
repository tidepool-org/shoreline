package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"

	"github.com/mdblp/shoreline/common/logging"
)

func Test_LoggingMiddleware_SetLogger(t *testing.T) {
	logger, _ := test.NewNullLogger()

	// arrange, test, assert, etc.
	request, err := http.NewRequest("Get", "/foo", nil)
	if err != nil {
		t.Fatalf("Failed to create new request with error %#v", err)
	} else if request == nil {
		t.Fatalf("Failure to request new request")
	}

	response := httptest.NewRecorder()

	router := mux.NewRouter()
	h := New(log.NewEntry(logger))
	router.Use(h.LoggingMiddleware)

	router.HandleFunc("/foo", func(w http.ResponseWriter, r *http.Request) {
		currentlog := logging.FromContext(r.Context())
		assert.Equal(t, 0, len(currentlog.Data))
	})

	//Act
	router.ServeHTTP(response, request)
}

func Test_LoggingMiddleware_SetLoggerWithTraceId(t *testing.T) {
	logger, _ := test.NewNullLogger()

	request, err := http.NewRequest("Get", "/foo", nil)
	if err != nil {
		t.Fatalf("Failed to create new request with error %#v", err)
	} else if request == nil {
		t.Fatalf("Failure to request new request")
	}

	response := httptest.NewRecorder()

	router := mux.NewRouter()
	h := New(log.NewEntry(logger))
	router.Use(TraceSessionIdMiddleware)
	router.Use(h.LoggingMiddleware)

	router.HandleFunc("/foo", func(w http.ResponseWriter, r *http.Request) {
		currentlog := logging.FromContext(r.Context())
		// We assert that a field is present in the logger
		assert.Equal(t, 1, len(currentlog.Data))
		assert.Contains(t, currentlog.Data, "trace-session")
	})

	//Act
	router.ServeHTTP(response, request)
}

func Test_LoggingMiddleware_SetLoggerWithRequestId(t *testing.T) {
	logger, _ := test.NewNullLogger()

	request, err := http.NewRequest("Get", "/foo", nil)
	if err != nil {
		t.Fatalf("Failed to create new request with error %#v", err)
	} else if request == nil {
		t.Fatalf("Failure to request new request")
	}

	response := httptest.NewRecorder()

	router := mux.NewRouter()
	h := New(log.NewEntry(logger))
	router.Use(RequestIdMiddleware)
	router.Use(h.LoggingMiddleware)

	router.HandleFunc("/foo", func(w http.ResponseWriter, r *http.Request) {
		currentlog := logging.FromContext(r.Context())
		assert.Equal(t, 1, len(currentlog.Data))
		assert.Contains(t, currentlog.Data, "request-id")
	})

	//Act
	router.ServeHTTP(response, request)
}

func Test_LoggingMiddleware_SetLoggerWith_TracingId_And_RequestId(t *testing.T) {
	logger, _ := test.NewNullLogger()

	request, err := http.NewRequest("Get", "/foo", nil)
	if err != nil {
		t.Fatalf("Failed to create new request with error %#v", err)
	} else if request == nil {
		t.Fatalf("Failure to request new request")
	}

	response := httptest.NewRecorder()

	router := mux.NewRouter()
	h := New(log.NewEntry(logger))
	router.Use(TraceSessionIdMiddleware)
	router.Use(RequestIdMiddleware)
	router.Use(h.LoggingMiddleware)

	router.HandleFunc("/foo", func(w http.ResponseWriter, r *http.Request) {
		currentlog := logging.FromContext(r.Context())
		assert.Equal(t, 2, len(currentlog.Data))
		assert.Contains(t, currentlog.Data, "request-id")
		assert.Contains(t, currentlog.Data, "trace-session")
	})

	//Act
	router.ServeHTTP(response, request)
}

func Test_GetLogCtx_WithNoLogger(t *testing.T) {
	ctx := context.Background()
	log := logging.FromContext(ctx)
	assert.NotNil(t, log)
}
