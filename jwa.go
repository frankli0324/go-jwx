package jwx

import "errors"

var algorithms = map[string]JsonWebAlgorithm{}

// JsonWebAlgorithm represents an algorithm defined in https://datatracker.ietf.org/doc/html/rfc7518.
// it's used for signing and verifying JsonWebSignatures and JsonWebEncryptions with JsonWebKeys.
type JsonWebAlgorithm interface {
	Verify(key *JsonWebKey, input, sig []byte) error
	Sign(key *JsonWebKey, input []byte) ([]byte, error)
	// Encrypt
	// Decrypt
}

type dummyAlgorithm struct{}

func (d dummyAlgorithm) Verify(key *JsonWebKey, input, sig []byte) error {
	return errors.ErrUnsupported
}

func (d dummyAlgorithm) Sign(key *JsonWebKey, input []byte) ([]byte, error) {
	return []byte{}, errors.ErrUnsupported
}
