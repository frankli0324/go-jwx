package jwx

import (
	"errors"
	"strings"

	"github.com/frankli0324/go-jsontk"
)

type JsonWebToken struct {
	envelope JsonWebSignature
	claims   map[string]int // key to payload offset
}

func (t *JsonWebToken) Parse(tk string) (err error) {
	dots := strings.Count(tk, ".")
	if dots == 1 {
		tk += "."
	} else if dots != 2 {
		return errors.New("invalid jwt format")
	}
	if err := t.envelope.ParseCompact(tk); err != nil {
		return err
	}
	iter := jsontk.Iterator{}
	iter.Reset(t.envelope.Payload())
	t.claims = make(map[string]int)
	if err := iter.NextObject(func(key *jsontk.Token) bool {
		_, t.claims[key.String()], _ = iter.Skip()
		return iter.Error == nil
	}); err != nil {
		return err
	}
	return nil
}

// subject to removal
func (t *JsonWebToken) RawClaims() []byte {
	return t.envelope.Payload()
}

func (t *JsonWebToken) Claim(key string, iter *jsontk.Iterator) bool {
	idx, ok := t.claims[key]
	if !ok {
		return false
	}
	iter.Reset(t.RawClaims()[idx:])
	return true
}

func (t *JsonWebToken) VerifyClaims() error {
	iter := jsontk.Iterator{}
	for k, verify := range claims {
		if !t.Claim(k, &iter) {
			continue
		}
		if err := verify(t, &iter); err != nil {
			return err
		}
	}
	return nil
}

func (t *JsonWebToken) VerifyKeySet(k JsonWebKeySet) error {
	if err := t.envelope.VerifyKeySet(k); err != nil {
		return err
	}
	return nil
}
