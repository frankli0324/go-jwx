package jwx

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/frankli0324/go-jsontk"
)

var jwkParsers = map[string]func(tk jsontk.JSON) (any, error){
	"RSA": func(tk jsontk.JSON) (any, error) {
		n, e := decodeB64URLBytes(tk.Get("n")), decodeB64URLBytes(tk.Get("e"))
		if n == nil || e == nil {
			return nil, errors.New("invalid RSA jwk, missing or invalid n or e")
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}, nil
	},
}

func parseJWK(kty string, tk jsontk.JSON) (any, error) {
	if p, ok := jwkParsers[kty]; ok {
		return p(tk)
	}
	return nil, fmt.Errorf("%w, unsupported kty: %s", errors.ErrUnsupported, kty)
}
