package jwx

import (
	"errors"

	"github.com/frankli0324/go-jsontk"
)

func nextString(iter *jsontk.Iterator, s string, k *jsontk.Token) []byte {
	if iter.NextToken(k).Type != jsontk.STRING {
		iter.Error = errors.New("expected " + s + " to be string")
		return nil
	}
	v, ok := k.UnquoteBytes()
	if !ok {
		iter.Error = errors.New("field " + s + " contains invalid string")
		return nil
	}
	return v
}
