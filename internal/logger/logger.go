package logger

import (
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
)

var Log zerolog.Logger

// Init initializes the global logger
func Init(level string, auditFile string) error {
	// Parse log level
	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		logLevel = zerolog.InfoLevel
	}

	// Configure pretty console output for development
	output := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	}

	// Create multi-writer if audit file is specified
	var writers []io.Writer
	writers = append(writers, output)

	if auditFile != "" {
		f, err := os.OpenFile(auditFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		writers = append(writers, f)
	}

	multi := zerolog.MultiLevelWriter(writers...)

	Log = zerolog.New(multi).
		Level(logLevel).
		With().
		Timestamp().
		Caller().
		Logger()

	return nil
}

// Info logs an info message
func Info(msg string) {
	Log.Info().Msg(msg)
}

// Error logs an error message
func Error(msg string, err error) {
	Log.Error().Err(err).Msg(msg)
}

// Debug logs a debug message
func Debug(msg string) {
	Log.Debug().Msg(msg)
}

// Warn logs a warning message
func Warn(msg string) {
	Log.Warn().Msg(msg)
}