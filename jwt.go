package jwx

import (
	"errors"
	"strings"

	"github.com/frankli0324/go-jsontk"
)

type JsonWebToken struct {
	claims   *jsontk.JSON
	envelope *JsonWebSignature
}

func (t *JsonWebToken) Header(k string) *jsontk.JSON {
	return t.envelope.signatures[0].header.Get(k)
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
	t.claims, err = jsontk.Tokenize(t.envelope.Payload())
	return err
}

func (t *JsonWebToken) verifyClaims() error {
	_, err := t.claims.Get("exp").Int64()
	return err
}

func (t *JsonWebToken) VerifyKeySet(k *JsonWebKeySet) error {
	if err := t.envelope.VerifyKeySet(k); err != nil {
		return err
	}
	return t.verifyClaims()
}
