package jwx

import (
	"encoding/json"

	"github.com/frankli0324/go-jsontk"
)

type JsonWebKeySet struct {
	Keys []*JsonWebKey `json:"keys"`
}

type JsonWebKey struct {
	kid string
	kty string
	alg string
	raw jsontk.JSON

	// `key` should only be used by the corresponding signVerifier for caching key objects
	key any
}

// registers the sign and verify operations on different `kty`s.
var signVerifiers = map[string]signVerifier{}

type signVerifier interface {
	Sign(k *JsonWebKey, input []byte) (sig []byte, err error)
	Verify(k *JsonWebKey, input, sig []byte) error
}

// UnmarshalJSON reads a key from its JSON representation.
func (k *JsonWebKey) UnmarshalJSON(data []byte) (err error) {
	tk, err := jsontk.Tokenize(data)
	if err != nil {
		return err
	}

	if kty, err := tk.Get("kty").String(); err != nil {
		return err
	} else {
		k.kty = kty
	}

	if alg, err := tk.Get("alg").String(); err != nil {
		return err
	} else {
		k.alg = alg
	}
	k.raw = tk
	return nil
}

func ParseJWKSBytes(jwkSet []byte) (res *JsonWebKeySet, err error) {
	res = new(JsonWebKeySet)
	return res, json.Unmarshal(jwkSet, res)
}
