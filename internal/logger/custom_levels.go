package logger

import (
	"context"
	"log/slog"
	"os"

	"github.com/fatih/color"
)

// Define our custom levels
const (
	LevelTrace  = slog.Level(-8)
	LevelFatal  = slog.Level(12)
	StackFrames = 5 // number of stack frames to skip in Handler.Handle
)

var LevelNames = map[slog.Leveler]string{
	LevelTrace: "TRACE",
	LevelFatal: "FATAL",
}

var LevelStrings = map[string]slog.Leveler{
	"TRACE": LevelTrace,
	"FATAL": LevelFatal,
	"INFO":  slog.LevelInfo,
	"WARN":  slog.LevelWarn,
	"ERROR": slog.LevelError,
	"DEBUG": slog.LevelDebug,
}

var LevelColorsMap map[slog.Level]LevelColor = map[slog.Level]LevelColor{
	LevelTrace:      {Name: "TRACE", Color: color.FgGreen},
	LevelFatal:      {Name: "FATAL", Color: color.FgRed},
	slog.LevelInfo:  {Name: "INFO ", Color: color.FgBlue},
	slog.LevelWarn:  {Name: "WARN ", Color: color.FgYellow},
	slog.LevelError: {Name: "ERROR", Color: color.FgRed},
	slog.LevelDebug: {Name: "DEBUG", Color: color.FgMagenta},
}

// Log a message at the Trace level
func (l *Logger) Trace(msg string, args ...interface{}) {
	l.logWithSource(LevelTrace, msg, args...)
}

// Log a message at the Fatal level and exit
func (l *Logger) Fatal(msg string, args ...interface{}) {
	l.logWithSource(LevelFatal, msg, args...)
	os.Exit(1)
}

// logWithSource sets the __source attribute so that our Handler knows
// to modify the r.PC value to include the original caller.
func (l *Logger) logWithSource(level slog.Level, msg string, args ...interface{}) {
	ctx := context.Background()
	var allArgs []interface{}
	allArgs = append(allArgs, args...)

	if l.addSource {
		allArgs = append(allArgs, slog.Int(FrameMarker, StackFrames))
	}
	l.Logger.Log(ctx, level, msg, allArgs...)
}
