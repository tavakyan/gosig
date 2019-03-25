package signature

import (
	"bytes"
	"crypto/dsa"
	"encoding/gob"
	"io"
	"math/big"
)

// TODO: Add getters for X, Y, etc. if needed
type Params struct {
	innerKeys  *dsa.PrivateKey
	innerSizes dsa.ParameterSizes
}
type ParamSizesWrapper dsa.ParameterSizes

const (
	L1024N160_WRAP ParamSizesWrapper = iota
	L2048N224_WRAP
	L2048N256_WRAP
	L3072N256_WRAP
)

type Signature struct {
	R *big.Int
	S *big.Int
}

// TODO: Add NewCustomParams and consider moving KeyGen Gen.Params into New function

// Generate Params given parameter sizes wrapper
func NewParams(sizes ParamSizesWrapper) (params *Params) {
	s := dsa.ParameterSizes(sizes)
	params = &Params{innerKeys: nil, innerSizes: s}
	return params
}

// Generate a public and private key pair given a RNG
func (p *Params) KeyGen(rand io.Reader) (pk *big.Int, sk *big.Int) {
	// Need to generate params before we can generate key pair
	err := dsa.GenerateParameters(&p.innerKeys.Parameters, rand, p.innerSizes)
	if err != nil {
		// panic
	}
	// Generate key pair
	err = dsa.GenerateKey(p.innerKeys, rand)
	if err != nil {
		// panic
	}
	// Extract Y and X which correspond to public & private key respectively
	return p.innerKeys.Y, p.innerKeys.X
}

// Sign a message using secret key and RNG and returned serialized signature
func (p *Params) Sign(rand io.Reader, msg []byte, sk *big.Int) []byte {
	// Validate key pair already exists
	if p.innerKeys.Y == nil || p.innerKeys.X == nil {
		// panic
	}
	// Sign the message
	r, s, err := dsa.Sign(rand, p.innerKeys, msg)
	if err != nil {
		// panic
	}
	// Create signature object
	sig := Signature{R: r, S: s}
	// Encode signature object into a buffer
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err = enc.Encode(sig)
	if err != nil {
		// panic
	}
	// return byte from encoded buffer
	return buffer.Bytes()
}

// Verify a message using a public key and serialized signature
// Return true if it belongs to public key, false otherwise
func (p *Params) Verify(msg []byte, pk *big.Int, sig []byte) (valid bool) {
	// Create new byte buffer decoder ...
	buffer := bytes.NewBuffer(sig)
	dec := gob.NewDecoder(buffer)
	// Decode into signature object
	var sigObj Signature
	err := dec.Decode(sigObj)
	if err != nil {
		// panic
	}
	// Extract from signature object
	r, s := sigObj.R, sigObj.S
	// Return whether signature is verified for the pk
	return dsa.Verify(&p.innerKeys.PublicKey, msg, r, s)
}
