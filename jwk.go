package jwx

import (
	"encoding/json"
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
	raw jsontk.JSON

	// `key` should only be used by the corresponding signVerifier for caching key objects
	key any
}

// UnmarshalJSON reads a key from its JSON representation.
func (k *JsonWebKey) UnmarshalJSON(data []byte) (err error) {
	tk, err := jsontk.Tokenize(data)
	if err != nil {
		return err
	}

	k.kid, err = tk.Get("kid").String()
	if err != nil {
		return fmt.Errorf("unable to parse kid, err:%w", err)
	}
	k.kty, err = tk.Get("kty").String()
	if err != nil {
		return fmt.Errorf("unable to parse kty, err:%w", err)
	}
	k.alg, err = tk.Get("alg").String()
	if err != nil {
		return fmt.Errorf("unable to parse alg, err:%w", err)
	}

	if v, err := parseJWK(k.kty, tk); err != nil {
		return err
	} else {
		k.key = v
	}

	k.raw = tk
	return nil
}

func ParseJWKSBytes(jwkSet []byte) (res *JsonWebKeySet, err error) {
	res = new(JsonWebKeySet)
	return res, json.Unmarshal(jwkSet, res)
}
