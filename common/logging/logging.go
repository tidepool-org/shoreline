package logging

import (
	"context"
	log "github.com/sirupsen/logrus"
)

type loggerKeyType int
const LoggerKey  loggerKeyType = iota

// WithLogger returns a new context with the provided logger. Use in
// combination with logger.WithField(s) for great effect.
func WithLogger(ctx context.Context, logger *log.Entry) context.Context{
	l := logger.WithContext(ctx)
	return context.WithValue(ctx, LoggerKey, l)
}

// FromContext retrieves the current logger from the context. If no logger is
// available, the default logger is returned.
func FromContext(ctx context.Context) *log.Entry {
	logger := ctx.Value(LoggerKey)
 
	if logger == nil {
	   log.Warn("Logger is missing in the context, create a backup one") // panics
	   logger = log.StandardLogger()
	   return log.NewEntry(logger.(*log.Logger))
	}
 
	return logger.(*log.Entry)
}