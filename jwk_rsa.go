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

type rsaBuilder rsa.PrivateKey

func (b *rsaBuilder) SetParam(k *jsontk.Token, iter *jsontk.Iterator) (err error) {
	p := k.UnsafeString()
	var num big.Int
	switch p {
	case "n", "e", "d", "p", "q", "dp", "dq", "qi":
		if iter.Peek() != jsontk.STRING {
			return errors.New("invalid format")
		}
		n, ok := iter.NextToken(k).UnsafeUnquote()
		if !ok {
			return errors.New("invalid string for field: " + p)
		}
		val, err := base64.RawURLEncoding.DecodeString(n)
		if err != nil {
			return err
		}
		num.SetBytes(val)
	case "oth":
		iter.NextArray(func(idx int) bool {
			iter.Skip()
			return iter.Error == nil
		})
	}
	switch p {
	case "n":
		b.N = &num
	case "e":
		b.E = int(num.Int64())
	case "d":
		b.D = &num
	}
	return nil
}

func (b *rsaBuilder) Build() (any, error) {
	if b.N == nil || b.E == 0 {
		return nil, errors.New("missing n or e")
	}
	return (*rsa.PublicKey)(&b.PublicKey), nil
	// TODO: private key
}
