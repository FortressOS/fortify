package sandbox

import (
	"encoding/json"
	"log"
	"os"
)

var (
	assert     = log.New(os.Stderr, "sandbox: ", 0)
	printfFunc = assert.Printf
	fatalfFunc = assert.Fatalf
)

func printf(format string, v ...any) { printfFunc(format, v...) }
func fatalf(format string, v ...any) { fatalfFunc(format, v...) }

func MustAssertMounts(name, hostMountsFile, wantFile string) {
	hostMounts := make([]*Mntent, 0, 128)
	if err := IterMounts(hostMountsFile, func(e *Mntent) {
		hostMounts = append(hostMounts, e)
	}); err != nil {
		fatalf("cannot parse host mounts: %v", err)
	}

	var want []Mntent
	if f, err := os.Open(wantFile); err != nil {
		fatalf("cannot open %q: %v", wantFile, err)
	} else if err = json.NewDecoder(f).Decode(&want); err != nil {
		fatalf("cannot decode %q: %v", wantFile, err)
	} else if err = f.Close(); err != nil {
		fatalf("cannot close %q: %v", wantFile, err)
	}

	for i := range want {
		if want[i].Opts == "host_passthrough" {
			for _, ent := range hostMounts {
				if want[i].FSName == ent.FSName {
					want[i].Opts = ent.Opts
					goto out
				}
			}
			fatalf("host passthrough missing %q", want[i].FSName)
		out:
		}
	}

	i := 0
	if err := IterMounts(name, func(e *Mntent) {
		if i == len(want) {
			fatalf("got more than %d entries", i)
		}
		if *e != want[i] {
			fatalf("entry %d\n got: %s\nwant: %s", i,
				e, &want[i])
		}

		printf("%s", e)
		i++
	}); err != nil {
		fatalf("cannot iterate mounts: %v", err)
	}
}
