package jwx

import (
	"crypto"
	"crypto/rsa"
	"errors"
)

func init() {
	signVerifiers["RSA"] = rsaSignVerifier{}
}

type rsaSignVerifier struct{}

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
	pubkey, ok := k.key.(*rsa.PublicKey)
	if !ok {
		return errors.New("invalid jwk constructed")
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
