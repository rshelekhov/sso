package e

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
)

func HandleError(
	ctx context.Context,
	log *slog.Logger,
	errTitle error,
	err error,
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
	if err != nil {
		errorMessage = err.Error()
	}

	allAttrs := []slog.Attr{
		slog.String("error", errorMessage),
		slog.String("location", location),
	}

	allAttrs = append(allAttrs, attrs...)
	log.LogAttrs(ctx, slog.LevelError, errTitle.Error(), allAttrs...)
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
