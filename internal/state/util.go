package state

import (
	"errors"
	"maps"
)

var (
	ErrDuplicate = errors.New("store contains duplicates")
)

// Join returns joined state entries of all active aids.
func Join(s Store) (Entries, error) {
	var (
		aids    []int
		entries = make(Entries)

		el      int
		res     Entries
		loadErr error
	)

	if ln, err := s.List(); err != nil {
		return nil, err
	} else {
		aids = ln
	}

	for _, aid := range aids {
		if _, err := s.Do(aid, func(c Cursor) {
			res, loadErr = c.Load()
		}); err != nil {
			return nil, err
		}

		if loadErr != nil {
			return nil, loadErr
		}

		// save expected length
		el = len(entries) + len(res)
		maps.Copy(entries, res)
		if len(entries) != el {
			return nil, ErrDuplicate
		}
	}

	return entries, nil
}
