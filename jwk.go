package jwx

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/frankli0324/go-jsontk"
)

type JsonWebKeySet []JsonWebKey

func (ks *JsonWebKeySet) UnmarshalJSON(data []byte) error {
	iter := jsontk.Iterator{}
	iter.Reset(data)
	return iter.NextObject(func(key *jsontk.Token) bool {
		switch key.UnsafeString() {
		case "keys":
			*ks = make(JsonWebKeySet, 0, 10)
			iter.NextArray(func(int) bool {
				*ks = append(*ks, JsonWebKey{})
				if t, s, l := iter.Skip(); t == jsontk.INVALID {
					iter.Error = errors.New("invalid object in keys array")
				} else {
					iter.Error = (*ks)[len(*ks)-1].UnmarshalJSON(data[s : s+l])
				}
				return iter.Error == nil
			})
		default:
			iter.Skip()
		}
		return iter.Error == nil
	})
}

type JsonWebKey struct {
	kid []byte
	kty string
	alg []byte

	// `key` would be used by the corresponding JsonWebAlgorithm to alg
	key any
}

type JsonWebKeyBuilder interface {
	SetParam(k *jsontk.Token, v *jsontk.Iterator) error
	Build() (any, error)
}

var kbuilders = map[string]func() JsonWebKeyBuilder{}

// UnmarshalJSON reads a key from its JSON representation.
func (k *JsonWebKey) UnmarshalJSON(data []byte) (err error) {
	iter := jsontk.Iterator{}
	iter.Reset(data)
	if err := iter.NextObject(func(key *jsontk.Token) (ok bool) {
		switch s := key.UnsafeString(); s {
		case "kid":
			return expect(&iter, iter.NextToken(key), s, &k.kid, key.UnquoteBytes)
		case "kty":
			return expect(&iter, iter.NextToken(key), s, &k.kty, key.UnsafeUnquote)
		case "alg":
			return expect(&iter, iter.NextToken(key), s, &k.alg, key.UnquoteBytes)
		default:
			iter.Skip()
		}
		return iter.Error == nil
	}); err != nil {
		return err
	}
	k.kid = bytes.Clone(k.kid)
	k.kty = strings.Clone(k.kty)
	k.alg = bytes.Clone(k.alg)
	builder, ok := kbuilders[k.kty]
	if !ok {
		return fmt.Errorf("%w, unsupported kty: %s", errors.ErrUnsupported, k.kty)
	}
	p := builder()
	iter.Reset(data)
	if err := iter.NextObject(func(key *jsontk.Token) bool {
		iter.Error = p.SetParam(key, &iter)
		return iter.Error == nil
	}); err != nil {
		return err
	}
	if vk, err := p.Build(); err != nil {
		return err
	} else {
		k.key = vk
	}
	return nil
}
