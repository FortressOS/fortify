package sandbox_test

import (
	"os"
	"testing"

	"git.gensokyo.uk/security/fortify/sandbox"
)

func TestExecutable(t *testing.T) {
	for i := 0; i < 16; i++ {
		if got := sandbox.MustExecutable(); got != os.Args[0] {
			t.Errorf("MustExecutable: %q, want %q",
				got, os.Args[0])
		}
	}
}
