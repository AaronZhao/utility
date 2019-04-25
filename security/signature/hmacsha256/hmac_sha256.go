package hmacsha256

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"github.com/aaronzhao/security/signature"
)

type HmacSha256 struct {
	data []byte
	key string
}

func (h *HmacSha256) Encode( ) string {

	hmac := hmac.New(sha256.New, []byte(h.key))
	hmac.Write( h.data )
	bs := hmac.Sum(nil)
	return base64.StdEncoding.EncodeToString(bs)
}

func( h *HmacSha256) Init( data []byte, key string ){
	h.data = data
	h.key = key
}


func New( ) signature.Encoder {
	return new(HmacSha256)
}