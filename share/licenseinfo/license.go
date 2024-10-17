package licenseinfo

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"math/big"
)

const stdLicensePubKeyString = "BAEg6UBZkrnVy3BRMEUj1owyS/ApFrDt7lW2f2xyxHRPjjWtMfXmO0eaQwXcer46U5ZqHJ13TYhh2yH81Cqc3kLaDAEKraOw8xicvI/n2DtwTwMUzCQnRrycZrIP1NPqCzVAGBbffBdwRErz5fOzDcOve5C9/ZYnxB0fCCxWaTgR7fc0sA=="

// signedLicenseInfo represents a signed license
// signedLicenseInfo struct is shared with the NeuVector controller
// signedLicenseInfo struct MUST not be modified unless coordinated with the implementation in the NeuVector controller because the struct is encoded with gob during license issuing
type signedLicenseInfo struct {
	Data []byte
	R    *big.Int
	S    *big.Int
}

func encrypt(encryptionKey, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], text)
	return ciphertext, nil
}

func EncryptToBase64(encryptionKey, text []byte) (string, error) {
	if ciphertext, err := encrypt(encryptionKey, text); err == nil {
		return base64.StdEncoding.EncodeToString(ciphertext), nil
	} else {
		return "", err
	}
}

func decrypt(encryptionKey, text []byte) ([]byte, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	if len(text) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)
	return text, nil
}

func DecryptFromBase64(encryptionKey []byte, b64 string) (string, error) {
	text, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}

	if text, err = decrypt(encryptionKey, text); err == nil {
		return string(text), nil
	} else {
		return "", err
	}
}

// to verify whether an encrypted signed license code is valid or not. Caller provides the public signing key & encryption key
func VerifyLicenseSignature(licCode string, pubKey *ecdsa.PublicKey, symmetricKey []byte) (string, error) { // returns license json string
	var err error

	if pubKey == nil || len(symmetricKey) == 0 {
		return "", fmt.Errorf("decrypt error!")
	}

	decrypted, err := DecryptFromBase64(symmetricKey, licCode)
	if err != nil || len(decrypted) == 0 {
		return "", fmt.Errorf("decrypt error! error=%v", err)
	}

	l, err := LicenseFromB64String(decrypted)
	if err != nil {
		return "", fmt.Errorf("get license error! error=%v", err)
	}

	if ok, err := l.Verify(pubKey); ok {
		return string(l.Data), nil
	} else {
		return "", fmt.Errorf("license invalid! data=%s, error=%v", string(l.Data), err)
	}
}

func GetLicenseInfo(license string, symmetricKey []byte) (string, error) { // returns license json string
	var err error
	var licValue string
	var pubKey *ecdsa.PublicKey

	pubKey, err = PublicKeyFromB64String(stdLicensePubKeyString, false)
	if err == nil {
		licValue, err = VerifyLicenseSignature(license, pubKey, symmetricKey)
	}

	return licValue, err
}

// --------------------------------------------------------------------------------------------------------------
func ObjToBytes(obj interface{}) ([]byte, error) {
	var buffBin bytes.Buffer

	encoderBin := gob.NewEncoder(&buffBin)
	if err := encoderBin.Encode(obj); err != nil {
		return nil, err
	}

	return buffBin.Bytes(), nil
}

func ObjToB64String(obj interface{}) (string, error) {
	b, err := ObjToBytes(obj)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

func ObjFromBytes(obj interface{}, b []byte) error {
	buffBin := bytes.NewBuffer(b)
	decoder := gob.NewDecoder(buffBin)

	return decoder.Decode(obj)
}

func ObjFromB64String(obj interface{}, s string) error {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}

	return ObjFromBytes(obj, b)
}

// LicenseFromB64String returns a signedLicenseInfo from a non-encrypted base64 encoded string.
func LicenseFromB64String(str string) (*signedLicenseInfo, error) {
	l := &signedLicenseInfo{}
	return l, ObjFromB64String(l, str)
}

// --------------------------------------------------------------------------------------------------------------
// PublicKeyFromBytes returns a public key from a []byte.
func PublicKeyFromBytes(b []byte, metered bool) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	if metered {
		curve = elliptic.P256()
	} else {
		curve = elliptic.P521()
	}
	x, y := elliptic.Unmarshal(curve, b)
	if x == nil {
		return nil, errors.New("Invalid key.")
	}

	k := ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	return &k, nil
}

// PublicKeyFromB64String returns a public key from a base64 encoded string.
func PublicKeyFromB64String(str string, metered bool) (*ecdsa.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}

	return PublicKeyFromBytes(b, metered)
}

// --------------------------------------------------------------------------------------------------------------
func (l *signedLicenseInfo) hash() ([]byte, error) {
	h256 := sha256.New()

	if _, err := h256.Write(l.Data); err != nil {
		return nil, err
	}
	return h256.Sum(nil), nil
}

// Verify the signedLicenseInfo with the public key
func (l *signedLicenseInfo) Verify(k *ecdsa.PublicKey) (bool, error) {
	h, err := l.hash()
	if err != nil {
		return false, err
	}

	return ecdsa.Verify(k, h, l.R, l.S), nil
}

// ToBytes transforms the public key to a base64 []byte.
func (l *signedLicenseInfo) ToBytes() ([]byte, error) {
	return ObjToBytes(l)
}

// ToB64String transforms the public key to a base64 string.
func (l *signedLicenseInfo) ToB64String() (string, error) {
	return ObjToB64String(l)
}
