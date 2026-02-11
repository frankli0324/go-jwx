package jwx

import (
	"errors"

	"github.com/frankli0324/go-jsontk"
)

func expect[T []byte | string](iter *jsontk.Iterator, tk *jsontk.Token, s string, t *T, f func() (T, bool)) (ok bool) {
	if tk.Type != jsontk.STRING {
		iter.Error = errors.New("expected " + s + " to be string")
	} else if *t, ok = f(); !ok {
		iter.Error = errors.New("field " + s + " contains invalid string")
	}
	return
}
