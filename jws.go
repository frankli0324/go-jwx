package jwx

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/frankli0324/go-jsontk"
)

type JsonWebSignature struct {
	header, payload jsontk.JSON
	rawHdr, rawPld  string
	signature       []byte
}

func ParseCompactJWS(token string) (*JsonWebSignature, error) {
	res := strings.SplitN(token, ".", 3)
	if len(res) != 3 {
		return nil, errors.New("invalid token")
	}
	jwt := &JsonWebSignature{}
	if hdr, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(res[0], "=")); err != nil {
		return nil, fmt.Errorf("parse jwt error, decode header base64 error, err:%w", err)
	} else if hres, err := jsontk.Tokenize(hdr); err != nil {
		return nil, fmt.Errorf("parse jwt error, decode header json error, err:%w", err)
	} else {
		jwt.rawHdr = res[0]
		jwt.header = hres
	}
	if pld, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(res[1], "=")); err != nil {
		return nil, fmt.Errorf("parse jwt error, decode claim base64 error, err:%w", err)
	} else if pres, err := jsontk.Tokenize(pld); err != nil {
		return nil, fmt.Errorf("parse jwt error, decode claim json error, err:%w", err)
	} else {
		jwt.rawPld = res[1]
		jwt.payload = pres
	}
	if sig, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(res[2], "=")); err != nil {
		return nil, fmt.Errorf("parse jwt error, decode signature base64 error, err:%w", err)
	} else {
		jwt.signature = sig
	}
	return jwt, nil
}

// Header returns unverified header
func (t *JsonWebSignature) Header() jsontk.JSON {
	return t.header
}

// Payload returns unverified payload
func (t *JsonWebSignature) Payload() jsontk.JSON {
	return t.payload
}

func (t *JsonWebSignature) authedBytes() []byte {
	return []byte(t.rawHdr + "." + t.rawPld)
}

func (t *JsonWebSignature) Verify(jwks JsonWebKeySet) error {
	kid, err := t.header.Get("kid").String()
	if err != nil {
		kid = ""
	}
	for _, jwk := range jwks.Keys {
		if jwk.kid == kid {
			return jwk.Verify(t)
		}
	}
	return errors.New("no jwk available")
}
