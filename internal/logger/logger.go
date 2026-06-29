package logger

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
)

// splitHandler routes info-level logs to stdout and warn/error logs to stderr.
type splitHandler struct {
	stdout slog.Handler
	stderr slog.Handler
}

func (h *splitHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.stdout.Enabled(ctx, level) || h.stderr.Enabled(ctx, level)
}

func (h *splitHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		return h.stderr.Handle(ctx, r)
	}

	return h.stdout.Handle(ctx, r)
}

func (h *splitHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &splitHandler{
		stdout: h.stdout.WithAttrs(attrs),
		stderr: h.stderr.WithAttrs(attrs),
	}
}

func (h *splitHandler) WithGroup(name string) slog.Handler {
	return &splitHandler{
		stdout: h.stdout.WithGroup(name),
		stderr: h.stderr.WithGroup(name),
	}
}

// Init configures the default slog logger with source locations (short file:line).
func Init() {
	opts := &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelInfo,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				if source, ok := a.Value.Any().(*slog.Source); ok {
					a.Value = slog.StringValue(filepath.Base(source.File) + ":" + strconv.Itoa(source.Line))
				}
			}

			return a
		},
	}

	handler := &splitHandler{
		stdout: slog.NewTextHandler(os.Stdout, opts),
		stderr: slog.NewTextHandler(os.Stderr, opts),
	}
	slog.SetDefault(slog.New(handler))
}

// Fatal logs an error and exits with status 1.
func Fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}
