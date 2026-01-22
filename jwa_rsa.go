package jwx

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
)

func init() {
	algorithms["RS256"] = rsaPKCSAlgorithm(crypto.SHA256)
	algorithms["PS256"] = rsaPSSAlgorithm(crypto.SHA256)
	algorithms["RS384"] = rsaPKCSAlgorithm(crypto.SHA384)
	algorithms["PS384"] = rsaPSSAlgorithm(crypto.SHA384)
	algorithms["RS512"] = rsaPKCSAlgorithm(crypto.SHA512)
	algorithms["PS512"] = rsaPSSAlgorithm(crypto.SHA512)
}

type rsaPKCSAlgorithm crypto.Hash
type rsaPSSAlgorithm crypto.Hash

func (s rsaPKCSAlgorithm) Verify(key *JsonWebKey, input, sig []byte) error {
	if key.kty != "RSA" {
		return fmt.Errorf("invalid kty, expected RSA, got %s", key.kty)
	}
	hasher := (crypto.Hash)(s).New()
	hasher.Write(input)
	hashed := hasher.Sum(nil)
	if k, ok := key.key.(*rsa.PublicKey); ok {
		return rsa.VerifyPKCS1v15(k, (crypto.Hash)(s), hashed, sig)
	}
	if k, ok := key.key.(*rsa.PrivateKey); ok && k != nil {
		return rsa.VerifyPKCS1v15(&k.PublicKey, (crypto.Hash)(s), hashed, sig)
	}
	return errors.New("invalid JWK, kty is RSA but got no rsa.PublicKey")
}

func (s rsaPKCSAlgorithm) Sign(key *JsonWebKey, input []byte) ([]byte, error) {
	return nil, errors.ErrUnsupported
}

func (s rsaPSSAlgorithm) Verify(key *JsonWebKey, input, sig []byte) error {
	if key.kty != "RSA" {
		return fmt.Errorf("invalid kty, expected RSA, got %s", key.kty)
	}
	hasher := (crypto.Hash)(s).New()
	hasher.Write(input)
	hashed := hasher.Sum(nil)
	if k, ok := key.key.(*rsa.PublicKey); ok {
		return rsa.VerifyPSS(k, (crypto.Hash)(s), hashed, sig, nil)
	}
	if k, ok := key.key.(*rsa.PrivateKey); ok && k != nil {
		return rsa.VerifyPSS(&k.PublicKey, (crypto.Hash)(s), hashed, sig, nil)
	}
	return errors.New("invalid JWK, kty is RSA but got no rsa.PublicKey")
}

func (s rsaPSSAlgorithm) Sign(key *JsonWebKey, input []byte) ([]byte, error) {
	return nil, errors.ErrUnsupported
}
