package main

import (
	"errors"

	"git.gensokyo.uk/security/fortify/internal/app"
	"git.gensokyo.uk/security/fortify/internal/fmsg"
)

func logWaitError(err error) {
	var e *fmsg.BaseError
	if !fmsg.AsBaseError(err, &e) {
		fmsg.Println("wait failed:", err)
	} else {
		// Wait only returns either *app.ProcessError or *app.StateStoreError wrapped in a *app.BaseError
		var se *app.StateStoreError
		if !errors.As(err, &se) {
			// does not need special handling
			fmsg.Print(e.Message())
		} else {
			// inner error are either unwrapped store errors
			// or joined errors returned by *appSealTx revert
			// wrapped in *app.BaseError
			var ej app.RevertCompoundError
			if !errors.As(se.InnerErr, &ej) {
				// does not require special handling
				fmsg.Print(e.Message())
			} else {
				errs := ej.Unwrap()

				// every error here is wrapped in *app.BaseError
				for _, ei := range errs {
					var eb *fmsg.BaseError
					if !errors.As(ei, &eb) {
						// unreachable
						fmsg.Println("invalid error type returned by revert:", ei)
					} else {
						// print inner *app.BaseError message
						fmsg.Print(eb.Message())
					}
				}
			}
		}
	}
}

func logBaseError(err error, message string) {
	var e *fmsg.BaseError

	if fmsg.AsBaseError(err, &e) {
		fmsg.Print(e.Message())
	} else {
		fmsg.Println(message, err)
	}
}
