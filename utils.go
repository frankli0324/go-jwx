package jwx

import (
	"encoding/base64"

	"github.com/frankli0324/go-jsontk"
)

func decodeB64URLBytes(j *jsontk.JSON) []byte {
	str, err := j.String()
	if err != nil {
		return nil
	}
	v, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		return nil
	}
	return v
}
