package jwx

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/frankli0324/go-jsontk"
)

type jsonComponent struct {
	jsontk.JSON
	raw []byte
}

type jwsSignature struct {
	protected jsonComponent // protected header
	header    jsonComponent // unprotected header
	signature []byte
}

// JsonWebSignature follows structure defined in full
// jws serialization defined in rfc7515#section-7.2.1
type JsonWebSignature struct {
	signatures []jwsSignature
	payload    []byte
}

func NewJsonWebSignature(payload []byte) *JsonWebSignature {
	return &JsonWebSignature{payload: payload}
}

// ParseCompact parses a compact serialized token defined in rfc7515#section-7.1
func (s *JsonWebSignature) ParseCompact(jws string) error {
	res := strings.SplitN(jws, ".", 3)
	if len(res) != 3 {
		return errors.New("invalid jws format")
	}
	if pld, err := base64.RawURLEncoding.DecodeString(res[1]); err != nil {
		return fmt.Errorf("parse jws error, decode payload base64 error, err:%w", err)
	} else {
		s.payload = pld
	}

	s.signatures = []jwsSignature{{}}
	if hdr, err := base64.RawURLEncoding.DecodeString(res[0]); err != nil {
		return fmt.Errorf("parse jws error, decode header base64 error, err:%w", err)
	} else if hres, err := jsontk.Tokenize(hdr); err != nil {
		return fmt.Errorf("parse jws error, decode header json error, err:%w", err)
	} else {
		s.signatures[0].protected.raw = hdr
		s.signatures[0].protected.JSON = hres
	}
	if sig, err := base64.RawURLEncoding.DecodeString(res[2]); err != nil {
		return fmt.Errorf("parse jws error, decode signature base64 error, err:%w", err)
	} else {
		s.signatures[0].signature = sig
	}
	return nil
}

// ParseJSONGeneral parses a json serialized token defined in rfc7515#section-7.2.1
func (s *JsonWebSignature) ParseJSONGeneral(jws string) error {
	return errors.ErrUnsupported
}

// ParseJSONFlattened parses a json serialized token defined in rfc7515#section-7.2.2
func (s *JsonWebSignature) ParseJSONFlattened(jws string) error {
	return errors.ErrUnsupported
}

func (s *JsonWebSignature) Sign(header map[string]string, key *JsonWebKey) error {
	return errors.ErrUnsupported
}

func (sig *jwsSignature) verifyInner(jwk *JsonWebKey, payload []byte) error {
	hlen := base64.RawURLEncoding.EncodedLen(len(sig.protected.raw))
	plen := base64.RawURLEncoding.EncodedLen(len(payload))
	authedData := make([]byte, hlen+plen+1)
	base64.RawURLEncoding.Encode(authedData, sig.protected.raw)
	authedData[hlen] = '.'
	base64.RawURLEncoding.Encode(authedData[hlen+1:], payload)
	if sv, ok := signVerifiers[jwk.kty]; ok {
		if err := sv.Verify(jwk, authedData, sig.signature); err != nil {
			return err
		}
		return nil
	}
	return errors.ErrUnsupported
}

func (s *JsonWebSignature) VerifyKeySingle(jwk *JsonWebKey) error {
	if len(s.signatures) == 0 {
		return errors.New("unsigned signature")
	}

	for _, sig := range s.signatures {
		if err := sig.verifyInner(jwk, s.payload); err != nil {
			return err
		}
	}
	return nil
}

func (s *JsonWebSignature) VerifyKeySet(jwks *JsonWebKeySet) error {
	if len(s.signatures) == 0 {
		return errors.New("unsigned signature")
	}

	for _, sig := range s.signatures {
		kid, _ := sig.header.Get("kid").String()
		var key *JsonWebKey = nil
		for _, jwk := range jwks.Keys {
			if jwk.kid == kid {
				key = jwk
				break
			}
		}
		if key == nil {
			return fmt.Errorf("no jwk available, want kid:%s", kid)
		}

		if err := sig.verifyInner(key, s.payload); err != nil {
			return err
		}
	}
	return nil
}
