package jwx

import (
	"errors"
	"strings"

	"github.com/frankli0324/go-jsontk"
)

func nextString(iter *jsontk.Iterator, s string, k *jsontk.Token) string {
	if iter.NextToken(k).Type != jsontk.STRING {
		iter.Error = errors.New("expected " + s + " to be string")
		return ""
	}
	v, ok := k.Unquote()
	if !ok {
		iter.Error = errors.New("field " + s + " contains invalid string")
		return ""
	}
	return strings.Clone(v)
}
