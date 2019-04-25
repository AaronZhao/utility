package signature

type Encoder interface {
	Encode() string
	Init([]byte,string)
}
