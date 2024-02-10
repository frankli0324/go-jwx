package jwx

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"

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

func (k *JsonWebKey) Verify(jwt *JsonWebSignature) error {
	switch k.kty {
	case "RSA":
		return VerifyRSA(k, jwt)
	}
	return errors.New("not supported kty:" + k.kty)
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
		n, e := decodeURLBytes(tk.Get("n")), decodeURLBytes(tk.Get("e"))
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

func decodeURLBytes(j jsontk.JSON) []byte {
	s, err := j.String()
	if err != nil {
		return nil
	}
	s = strings.TrimRight(s, "=")
	v, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return v
}
