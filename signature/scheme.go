package signature

import (
	"io"
	"math/big"
)

type Scheme interface {
	KeyGen(rand io.Reader) (pk *big.Int, sk *big.Int)
	Sign(rand io.Reader, msg []byte, sk *big.Int) (sig []byte)
	Verify(msg []byte, pb *big.Int, sig []byte) (valid bool)
}
