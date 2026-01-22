package jwx

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
)

func init() {
	algorithms["HS256"] = hmacAlgorithm(crypto.SHA256)
	algorithms["HS384"] = hmacAlgorithm(crypto.SHA384)
	algorithms["HS512"] = hmacAlgorithm(crypto.SHA512)
}

var hmacrev = [crypto.SHA512 + 1]string{
	crypto.SHA256: "HS256",
	crypto.SHA384: "HS384",
	crypto.SHA512: "HS512",
}

type hmacAlgorithm crypto.Hash

func (s hmacAlgorithm) Verify(key *JsonWebKey, input, sig []byte) error {
	out, err := s.Sign(key, input)
	if err != nil {
		return err
	}
	if !bytes.Equal(out, sig) {
		return errors.New("mismatch")
	}
	return nil
}

func (s hmacAlgorithm) Sign(key *JsonWebKey, input []byte) ([]byte, error) {
	if key.kty != "oct" {
		return nil, fmt.Errorf("invalid kty, expected oct, got %s", key.kty)
	}
	if key.alg != nil && string(key.alg) != hmacrev[s] {
		// https://datatracker.ietf.org/doc/html/rfc7518#section-6.4 SHOULD
		return nil, fmt.Errorf("invalid kty, expected oct, got %s", key.kty)
	}
	h := (crypto.Hash)(s).New()
	h.Write(input)
	return h.Sum(nil), nil
}
