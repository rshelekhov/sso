package usecase

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strings"

	"github.com/rshelekhov/sso/internal/lib/constant/key"
	"github.com/rshelekhov/sso/internal/lib/constant/le"
)

func handleError(
	ctx context.Context,
	log *slog.Logger,
	err le.LocalError,
	errDetails error,
	attrs ...slog.Attr,
) {
	_, file, line, ok := getCaller()
	if !ok {
		file = "unknown file"
		line = -1
	}

	// op := runtime.FuncForPC(pc).Name()
	location := fmt.Sprintf("%s:%d", file, line)

	errorMessage := "err is nil"
	if errDetails != nil {
		errorMessage = errDetails.Error()
	}

	baseAttrs := []slog.Attr{
		slog.String(key.Error, errorMessage),
		slog.String(key.Location, location),
	}

	allAttrs := append(baseAttrs, attrs...)
	log.LogAttrs(ctx, slog.LevelError, err.Error(), allAttrs...)
}

func getCaller() (pc uintptr, file string, line int, ok bool) {
	pcs := make([]uintptr, 10)
	n := runtime.Callers(2, pcs)
	if n == 0 {
		return
	}

	frames := runtime.CallersFrames(pcs[:n])

	frame, more := frames.Next()
	if !more {
		return
	}

	for {
		frame, more = frames.Next()
		if strings.Contains(frame.Function, "sso") {
			return frame.PC, frame.File, frame.Line, true
		}
		if !more {
			break
		}
	}

	return 0, "unknown file", -1, false
}
