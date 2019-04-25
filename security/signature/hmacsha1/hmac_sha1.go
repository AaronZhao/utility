package hmacsha1

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"github.com/aaronzhao/security/signature"
)

type HmacSha1 struct {
	data []byte
	key string
}

func (h *HmacSha1) Encode( ) string {

	hmac := hmac.New(sha1.New, []byte(h.key))
	hmac.Write( h.data )
	bs := hmac.Sum(nil)
	return base64.StdEncoding.EncodeToString(bs)
}

func (h *HmacSha1) Init(data []byte, key string ){
	h.data = data
	h.key = key
}


func New() signature.Encoder {
	return new(HmacSha1)
}