package log

import (
	"testing"

	"github.com/go-logr/logr"
)

// TestLogger is a logr.Logger that prints through a testing.T object.
// All log messages will be printed.
type TestLogger struct {
	T *testing.T

	vals  []interface{}
	names []string
}

var _ logr.Logger = TestLogger{}

func (log TestLogger) Info(msg string, args ...interface{}) {
	log.T.Logf("%s: %s: %v", log.names, msg, append(log.vals, args))
}

func (log TestLogger) Enabled() bool {
	return true
}

func (log TestLogger) Error(err error, msg string, args ...interface{}) {
	log.T.Logf("%s: %v -- %v", msg, err, args)
}

func (log TestLogger) V(v int) logr.Logger {
	return log
}

func (log TestLogger) WithName(name string) logr.Logger {
	return TestLogger{
		T:     log.T,
		vals:  log.vals,
		names: append(log.names, name),
	}
}

func (log TestLogger) WithValues(vals ...interface{}) logr.Logger {
	return TestLogger{
		T:     log.T,
		vals:  append(log.vals, vals),
		names: log.names,
	}
}
