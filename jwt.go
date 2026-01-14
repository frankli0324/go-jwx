package jwx

import (
	"errors"
	"strings"
)

type JsonWebToken struct {
	envelope *JsonWebSignature
}

func (t *JsonWebToken) Parse(tk string) (err error) {
	parts := strings.Count(tk, ".")
	if parts == 1 {
		return errors.New("invalid")
	}
	if parts == 2 {
		tk += "."
	}
	t.envelope = new(JsonWebSignature)
	if err := t.envelope.ParseCompact(tk); err != nil {
		return err
	}
	return err
}

// func (t *JsonWebToken) Claims() []byte {
// 	return t.envelope.Payload()
// }

// func (t *JsonWebToken) verifyClaims() error {
// 	_, err := t.claims.Get("exp").Int64()
// 	return err
// }

func (t *JsonWebToken) VerifyKeySet(k *JsonWebKeySet) error {
	if err := t.envelope.VerifyKeySet(k); err != nil {
		return err
	}
	return nil
	// return t.verifyClaims()
}
