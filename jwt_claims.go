package jwx

import (
	"errors"
	"time"

	"github.com/frankli0324/go-jsontk"
)

var claims = map[string]func(*JsonWebToken, *jsontk.Iterator) error{}

func init() {
	claims["exp"] = func(_ *JsonWebToken, iter *jsontk.Iterator) error {
		var t jsontk.Token
		if iter.NextToken(&t).Type != jsontk.NUMBER {
			return errors.New("invalid exp")
		}
		v, err := t.Number().Int64()
		if err != nil {
			return err
		}
		if v < time.Now().Unix() {
			return errors.New("token expired")
		}
		return nil
	}
}
