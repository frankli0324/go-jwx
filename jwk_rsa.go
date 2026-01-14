package jwx

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"

	"github.com/frankli0324/go-jsontk"
)

func init() {
	kbuilders["RSA"] = func() JsonWebKeyBuilder { return &rsaBuilder{} }
}

type rsaBuilder rsa.PublicKey

func (b *rsaBuilder) SetParam(k string, iter *jsontk.Iterator) error {
	if iter.Peek() != jsontk.STRING || (k != "n" && k != "e") {
		iter.Skip()
		return nil
	}
	t := iter.NextToken(nil)
	val, err := base64.RawURLEncoding.DecodeString(t.String())
	if err != nil {
		return err
	}
	switch k {
	case "n":
		b.N = new(big.Int).SetBytes(val)
	case "e":
		b.E = int(new(big.Int).SetBytes(val).Int64())
	}
	return nil
}

func (b *rsaBuilder) Build() (any, error) {
	if b.N == nil || b.E == 0 {
		return nil, errors.New("missing n or e")
	}
	return (*rsa.PublicKey)(b), nil
}
