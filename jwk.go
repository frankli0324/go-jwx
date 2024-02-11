package jwx

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"

	"github.com/frankli0324/go-jsontk"
)

type JsonWebKeySet struct {
	Keys []*JsonWebKey `json:"keys"`
}

type JsonWebKey struct {
	kid string
	kty string
	alg string
	key any
}

// registers the sign and verify operations on different `kty`s.
var signVerifiers = map[string]SignVerifier{}

type SignVerifier interface {
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

	switch k.kty {
	case "RSA":
		n, e := decodeB64URLBytes(tk.Get("n")), decodeB64URLBytes(tk.Get("e"))
		if n == nil || e == nil {
			return errors.New("invalid RSA jwk, missing or invalid n or e")
		}
		k.key = &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}
	default:
		return errors.New("not supported kty:" + k.kty)
	}
	return nil
}

func ParseJWKSBytes(jwkSet []byte) (res *JsonWebKeySet, err error) {
	res = new(JsonWebKeySet)
	return res, json.Unmarshal(jwkSet, res)
}

func decodeB64URLBytes(j jsontk.JSON) []byte {
	s, err := j.String()
	if err != nil {
		return nil
	}
	v, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return v
}
