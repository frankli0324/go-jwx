package jwx

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
)

var algorithms = map[string]JsonWebAlgorithm{
	"RS256": rsaAlgorithm{crypto.SHA256, rsa.VerifyPKCS1v15},
	"PS256": rsaAlgorithm{crypto.SHA256, rsaVerifyPSSBounded},
	"RS384": rsaAlgorithm{crypto.SHA384, rsa.VerifyPKCS1v15},
	"PS384": rsaAlgorithm{crypto.SHA384, rsaVerifyPSSBounded},
	"RS512": rsaAlgorithm{crypto.SHA512, rsa.VerifyPKCS1v15},
	"PS512": rsaAlgorithm{crypto.SHA512, rsaVerifyPSSBounded},
}

func rsaVerifyPSSBounded(pub *rsa.PublicKey, hash crypto.Hash, hashed, sig []byte) error {
	return rsa.VerifyPSS(pub, hash, hashed, sig, nil)
}

type JsonWebAlgorithm interface {
	Verify(key *JsonWebKey, input, sig []byte) error
	Sign(key *JsonWebKey, input []byte) ([]byte, error)
}

type rsaAlgorithm struct {
	hash   crypto.Hash
	verify func(pub *rsa.PublicKey, hash crypto.Hash, hashed []byte, sig []byte) error
}

func (s rsaAlgorithm) Verify(key *JsonWebKey, input, sig []byte) error {
	if key.kty != "RSA" {
		return fmt.Errorf("invalid kty, expected RSA, got %s", key.kty)
	}
	hasher := s.hash.New()
	hasher.Write(input)
	hashed := hasher.Sum(nil)
	if k, ok := key.key.(*rsa.PublicKey); ok {
		return s.verify(k, s.hash, hashed, sig)
	}
	if k, ok := key.key.(*rsa.PrivateKey); ok {
		return s.verify(&k.PublicKey, s.hash, hashed, sig)
	}
	return errors.New("invalid JWK, kty is RSA but got no rsa.PublicKey")
}

func (s rsaAlgorithm) Sign(key *JsonWebKey, input []byte) ([]byte, error) {
	return nil, errors.ErrUnsupported
}
