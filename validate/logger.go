package validate

import (
	"github.com/sirupsen/logrus"
)

// logrusLogger adapts the process-wide logrus logger to the Logger interface.
//
// Backing the Logger with logrus.StandardLogger() means the level and
// formatter configured by Options.configureOutput() (-v, -silent, -no-color)
// apply to every log line the validator produces, instead of configuring a
// logger nobody reads.
//
// This replaces utils.NewLogger() from secinto/checkfix_utils.
type logrusLogger struct{}

// NewLogger returns a Logger backed by the standard logrus logger.
// The returned Logger is safe for concurrent use.
func NewLogger() Logger {
	return &logrusLogger{}
}

func (l *logrusLogger) Tracef(format string, args ...interface{}) {
	logrus.Tracef(format, args...)
}

func (l *logrusLogger) Debugf(format string, args ...interface{}) {
	logrus.Debugf(format, args...)
}

func (l *logrusLogger) Infof(format string, args ...interface{}) {
	logrus.Infof(format, args...)
}

func (l *logrusLogger) Warnf(format string, args ...interface{}) {
	logrus.Warnf(format, args...)
}

func (l *logrusLogger) Errorf(format string, args ...interface{}) {
	logrus.Errorf(format, args...)
}

func (l *logrusLogger) Fatalf(format string, args ...interface{}) {
	logrus.Fatalf(format, args...)
}

// SetLevel accepts a logrus.Level; other values are ignored so that the
// interface stays usable by callers that do not depend on logrus types.
func (l *logrusLogger) SetLevel(level interface{}) {
	if lvl, ok := level.(logrus.Level); ok {
		logrus.SetLevel(lvl)
	}
}

// SetFormatter accepts a logrus.Formatter; other values are ignored.
func (l *logrusLogger) SetFormatter(formatter interface{}) {
	if f, ok := formatter.(logrus.Formatter); ok {
		logrus.SetFormatter(f)
	}
}
