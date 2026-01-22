package jwx

import (
	"bytes"
	"errors"

	"github.com/frankli0324/go-jsontk"
)

func init() {
	kbuilders["oct"] = func() JsonWebKeyBuilder { return &octBuilder{} }
}

type octBuilder []byte

func (b *octBuilder) SetParam(k *jsontk.Token, iter *jsontk.Iterator) (err error) {
	switch k.UnsafeString() {
	case "k":
		if iter.Peek() != jsontk.STRING {
			return errors.New("invalid format")
		}
		v, ok := iter.NextToken(k).UnquoteBytes()
		if !ok {
			return errors.New("invalid string")
		}
		*b = bytes.Clone(v)
	default:
		iter.Skip()
	}
	return nil
}

func (b *octBuilder) Build() (any, error) {
	if *b == nil {
		return nil, errors.New("missing param k")
	}
	return []byte(*b), nil
}
