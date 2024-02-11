package jwx

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"

	"github.com/frankli0324/go-jsontk"
)

func init() {
	signVerifiers["RSA"] = rsaSignVerifier{}
}

type rsaSignVerifier struct{}

func (s rsaSignVerifier) decodeB64URLBytes(j jsontk.JSON) []byte {
	str, err := j.String()
	if err != nil {
		return nil
	}
	v, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return nil
	}
	return v
}

func (s rsaSignVerifier) getPubkey(k *JsonWebKey) (*rsa.PublicKey, error) {
	if k.key != nil {
		if pubkey, ok := k.key.(*rsa.PublicKey); ok {
			return pubkey, nil
		} else {
			return nil, errors.New("invalid jwk constructed")
		}
	}
	n, e := s.decodeB64URLBytes(k.raw.Get("n")), s.decodeB64URLBytes(k.raw.Get("e"))
	if n == nil || e == nil {
		return nil, errors.New("invalid RSA jwk, missing or invalid n or e")
	}
	key := &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(new(big.Int).SetBytes(e).Int64()),
	}
	k.key = key
	return key, nil
}

func (s rsaSignVerifier) Sign(k *JsonWebKey, input []byte) (sig []byte, err error) {
	return nil, errors.ErrUnsupported
}

func (s rsaSignVerifier) Verify(k *JsonWebKey, input, sig []byte) error {
	var hash crypto.Hash

	switch k.alg {
	case "RS256", "PS256":
		hash = crypto.SHA256
	case "RS384", "PS384":
		hash = crypto.SHA384
	case "RS512", "PS512":
		hash = crypto.SHA512
	default:
		return errors.New("invalid alg")
	}

	pubkey, err := s.getPubkey(k)
	if err != nil {
		return err
	}

	hasher := hash.New()
	hasher.Write(input)
	hashed := hasher.Sum(nil)

	switch k.alg {
	case "RS256", "RS384", "RS512":
		return rsa.VerifyPKCS1v15(pubkey, hash, hashed, sig)
	case "PS256", "PS384", "PS512":
		return rsa.VerifyPSS(pubkey, hash, hashed, sig, nil)
	}

	return errors.New("invalid alg")
}
