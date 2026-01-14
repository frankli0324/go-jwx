package jwx

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/frankli0324/go-jsontk"
)

// https://datatracker.ietf.org/doc/html/rfc7515#section-9.1
type jwsHeader struct {
	kid string
	alg string
	raw []byte
}

func (h *jwsHeader) Parse(data []byte, protected bool) error {
	iter := jsontk.Iterator{}
	iter.Reset(data)
	return iter.NextObject(func(key *jsontk.Token) bool {
		switch k := key.String(); k {
		case "kid":
			h.kid = nextString(&iter, k, key)
		case "alg":
			h.alg = nextString(&iter, k, key)
		default:
			iter.Skip()
		}
		return iter.Error == nil
	})
}

type jwsSignature struct {
	header    jwsHeader
	signature []byte
}

func (sig *jwsSignature) Verify(jwk *JsonWebKey, payload []byte) error {
	alg := sig.header.alg
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

func NewJsonWebSignature(payload []byte) *JsonWebSignature {
	return &JsonWebSignature{payload: payload}
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
	} else if err := s.signatures[0].header.Parse(hdr, true); err != nil {
		return err
	} else {
		s.signatures[0].header.raw = hdr
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
	hlen := base64.RawURLEncoding.EncodedLen(len(sig.header.raw))
	plen := base64.RawURLEncoding.EncodedLen(len(payload))
	authedData := make([]byte, hlen+plen+1)
	base64.RawURLEncoding.Encode(authedData, sig.header.raw)
	authedData[hlen] = '.'
	base64.RawURLEncoding.Encode(authedData[hlen+1:], payload)
	return authedData
}

func (s *JsonWebSignature) VerifyKeySingle(jwk *JsonWebKey) error {
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

func (s *JsonWebSignature) VerifyKeySet(jwks *JsonWebKeySet) error {
	if len(s.signatures) == 0 {
		return errors.New("unsigned JWS")
	}

	for _, sig := range s.signatures {
		header := sig.header
		if header.alg == "" {
			return fmt.Errorf("invalid JWS, alg is required on a signature")
		}
		var key *JsonWebKey
		for _, jwk := range jwks.Keys {
			if jwk.kid == header.kid {
				key = jwk
				break
			}
		}
		if key == nil {
			return fmt.Errorf("no JWK available, want kid:%s", header.kid)
		}

		if err := sig.Verify(key, s.payload); err != nil {
			return err
		}
	}
	return nil
}
