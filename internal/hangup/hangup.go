// Package hangup keeps a process started with SIGHUP ignored, as under
// nohup, ignoring it.
//
// signal.Notify and signal.NotifyContext install a handler for SIGHUP even
// when it was ignored at start, so a process that asks for it would stop, or
// pass it on, when its terminal closes, which is what nohup is for avoiding.
package hangup

import (
	"os"
	"os/signal"
	"syscall"
)

// ignoredAtStart is whether SIGHUP was ignored when the process started. It
// is read during package initialization, before anything can call
// signal.Notify, since a handler stops the signal being ignored.
var ignoredAtStart = signal.Ignored(syscall.SIGHUP)

// Signals returns sigs without SIGHUP when it was ignored at start, so it
// stays ignored, and sigs unchanged otherwise. The result may be empty, and
// signal.Notify with no signals means every signal, so callers must check.
func Signals(sigs ...os.Signal) []os.Signal {
	return filter(ignoredAtStart, sigs)
}

// filter returns sigs without SIGHUP when ignored is set.
func filter(ignored bool, sigs []os.Signal) []os.Signal {
	out := make([]os.Signal, 0, len(sigs))
	for _, s := range sigs {
		if ignored && s == syscall.SIGHUP {
			continue
		}
		out = append(out, s)
	}
	return out
}
