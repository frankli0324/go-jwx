package jwx

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/frankli0324/go-jsontk"
)

type JsonWebKeySet struct {
	Keys []*JsonWebKey `json:"keys"`
}

type JsonWebKey struct {
	kid string
	kty string
	alg string

	// `key` should only be used by the corresponding signVerifier for caching key objects
	key any
}

type JsonWebKeyBuilder interface {
	SetParam(k string, v *jsontk.Iterator) error
	Build() (any, error)
}

var kbuilders = map[string]func() JsonWebKeyBuilder{}

// UnmarshalJSON reads a key from its JSON representation.
func (k *JsonWebKey) UnmarshalJSON(data []byte) (err error) {
	iter := jsontk.Iterator{}
	iter.Reset(data)
	if err := iter.NextObject(func(key *jsontk.Token) bool {
		s := key.String()
		switch s {
		case "kid":
			k.kid = nextString(&iter, s, key)
		case "kty":
			k.kty = nextString(&iter, s, key)
		case "alg":
			k.alg = nextString(&iter, s, key)
		default:
			iter.Skip()
		}
		return iter.Error == nil
	}); err != nil {
		return err
	}
	builder, ok := kbuilders[k.kty]
	if !ok {
		return fmt.Errorf("%w, unsupported kty: %s", errors.ErrUnsupported, k.kty)
	}
	p := builder()
	iter.Reset(data)
	if err := iter.NextObject(func(key *jsontk.Token) bool {
		s := key.String()
		iter.Error = p.SetParam(s, &iter)
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

func ParseJWKSBytes(jwkSet []byte) (res *JsonWebKeySet, err error) {
	res = new(JsonWebKeySet)
	return res, json.Unmarshal(jwkSet, res)
}
