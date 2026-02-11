package jwx

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/frankli0324/go-jsontk"
)

// https://datatracker.ietf.org/doc/html/rfc7515#section-9.1
type jwsHeader struct {
	alg string
	kid []byte
	raw []byte
}

// Parse decodes data parameter as JWS header in json form defined in rfc7515#section-9.1
// the data must not be modified in any way after being passed to [Parse]
func (h *jwsHeader) Parse(data []byte, protected bool) error {
	h.raw = data
	iter := jsontk.Iterator{}
	iter.Reset(data)
	return iter.NextObject(func(key *jsontk.Token) (ok bool) {
		switch k := key.UnsafeString(); k {
		case "alg":
			return expect(&iter, iter.NextToken(key), k, &h.alg, key.UnsafeUnquote)
		case "kid":
			return expect(&iter, iter.NextToken(key), k, &h.kid, key.UnquoteBytes)
		default:
			iter.Skip()
		}
		return iter.Error == nil
	})
}

type jwsSignature struct {
	protected jwsHeader

	signature []byte
}

func (sig *jwsSignature) Verify(jwk *JsonWebKey, payload []byte) error {
	alg := sig.protected.alg
	if alg == "" {
		return fmt.Errorf("invalid JWS, alg is required on a signature")
	}
	authedData := sig.encodeAuthedData(payload)
	if v, ok := algorithms[alg]; ok {
		if err := v.Verify(jwk, authedData, sig.signature); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("%w, unsupported alg in JWS: %s", errors.ErrUnsupported, alg)
	}
	return nil
}

// JsonWebSignature follows structure defined in full
// jws serialization defined in rfc7515#section-7.2.1
type JsonWebSignature struct {
	signatures []jwsSignature
	payload    []byte
}

func (s *JsonWebSignature) Payload() []byte {
	return s.payload
}

func (s *JsonWebSignature) Signed() bool {
	return len(s.signatures) != 0
}

// ParseCompact parses a compact serialized token defined in rfc7515#section-7.1
func (s *JsonWebSignature) ParseCompact(jws string) error {
	res := strings.Split(jws, ".")
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
	} else if err := s.signatures[0].protected.Parse(hdr, true); err != nil {
		return err
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

func (sig *jwsSignature) encodeAuthedData(payload []byte) []byte {
	hlen := base64.RawURLEncoding.EncodedLen(len(sig.protected.raw))
	plen := base64.RawURLEncoding.EncodedLen(len(payload))
	authedData := make([]byte, hlen+plen+1)
	base64.RawURLEncoding.Encode(authedData, sig.protected.raw)
	authedData[hlen] = '.'
	base64.RawURLEncoding.Encode(authedData[hlen+1:], payload)
	return authedData
}

func (s *JsonWebSignature) Verify(jwk *JsonWebKey) error {
	if len(s.signatures) == 0 {
		return errors.New("unsigned JWS")
	}

	for _, sig := range s.signatures {
		if err := sig.Verify(jwk, s.payload); err != nil {
			return err
		}
	}
	return nil
}

func (s *JsonWebSignature) VerifyKeySet(jwks JsonWebKeySet) error {
	// read: https://datatracker.ietf.org/doc/html/rfc7515#section-6
	if len(s.signatures) == 0 {
		return errors.New("unsigned JWS")
	}

	for _, sig := range s.signatures {
		kid := sig.protected.kid
		var key *JsonWebKey
		if kid != nil {
			for _, jwk := range jwks {
				if bytes.Equal(jwk.kid, kid) {
					key = &jwk
					break
				}
			}
		} else if len(jwks) > 0 { // TODO: make key selection customizable
			key = &jwks[0]
		}

		if key == nil {
			return fmt.Errorf("no JWK available")
		}

		if err := sig.Verify(key, s.payload); err != nil {
			return err
		}
	}
	return nil
}
