package common

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

type Marshaller interface {
	Marshal(data interface{}) ([]byte, error)
	GetEmptyFieldsToEncrypt() utils.Set
}
type Unmarshaller interface {
	Unmarshal(raw []byte, data interface{}) error
	Uncloak(data interface{}) error
	GetEmptyEncryptedFields() utils.Set
	GetFailToDecryptFields() utils.Set
	GetDecryptedFieldsNumber() int
}

const (
	cloakTag     = "cloak"
	cloakMask    = "mask"
	emptyMask    = "empty"
	cloakEncrypt = "encrypt"
	cloakDecrypt = "decrypt"
)

const (
	saltSize  = 16
	nonceSize = 12

	saltHexSize  = 32
	nonceHexSize = 24

	keyLength = 32
	keyIter   = 600000

	DekSeedLength = 32

	saltedHashPrefix   = "s-"
	cipherTypeA        = "a"
	cipherBundleFormat = "%s-%s-%s-%s-%s" // "{cipherTypeA}-{keyVersion}-{hex(salt)}-{hex(nonce)}-{hex(cipherText)}"
	cipherBundleParts  = 5
)

type tMarshallResult struct {
	emptyFieldsToEncrypt utils.Set // all to-cloak fields that have empty string value
}

func (md *tMarshallResult) Reset() {
	if md.emptyFieldsToEncrypt == nil {
		md.emptyFieldsToEncrypt = utils.NewSet()
	} else {
		md.emptyFieldsToEncrypt.Clear()
	}
}

func (md *tMarshallResult) AddEmptyFieldToEncrypt(field string) {
	if md.emptyFieldsToEncrypt != nil {
		md.emptyFieldsToEncrypt.Add(field)
	}
}

func (md *tMarshallResult) GetEmptyFieldsToEncrypt() utils.Set {
	if md.emptyFieldsToEncrypt != nil && md.emptyFieldsToEncrypt.Cardinality() > 0 {
		return md.emptyFieldsToEncrypt.Clone()
	}
	return nil
}

type tUnmarshallResult struct {
	emptyEncryptedFields  utils.Set // all cloaked fields that have empty string value
	failedToDecryptFields utils.Set // all cloaked fields that cannot be decrypted
	decryptedFieldsNumber int
}

func (ud *tUnmarshallResult) Reset() {
	if ud.emptyEncryptedFields == nil {
		ud.emptyEncryptedFields = utils.NewSet()
	} else {
		ud.emptyEncryptedFields.Clear()
	}

	if ud.failedToDecryptFields == nil {
		ud.failedToDecryptFields = utils.NewSet()
	} else {
		ud.failedToDecryptFields.Clear()
	}
}

func (ud *tUnmarshallResult) AddEmptyEncryptedField(field string) {
	if ud.emptyEncryptedFields != nil {
		ud.emptyEncryptedFields.Add(field)
	}
}

func (ud *tUnmarshallResult) AddFailedToDecryptField(field string) {
	if ud.failedToDecryptFields != nil {
		ud.failedToDecryptFields.Add(field)
	}
}

func (ud *tUnmarshallResult) IncreaseDecryptedFields() {
	ud.decryptedFieldsNumber++
}

func (ud *tUnmarshallResult) GetEmptyEncryptedFields() utils.Set {
	if ud.emptyEncryptedFields != nil && ud.emptyEncryptedFields.Cardinality() > 0 {
		return ud.emptyEncryptedFields.Clone()
	}
	return nil
}

func (ud *tUnmarshallResult) GetFailToDecryptFields() utils.Set {
	if ud.failedToDecryptFields != nil && ud.failedToDecryptFields.Cardinality() > 0 {
		return ud.failedToDecryptFields.Clone()
	}
	return nil
}

func (ud *tUnmarshallResult) GetDecryptedFieldsNumber() int {
	return ud.decryptedFieldsNumber
}

type EmptyMarshaller struct{}
type MaskMarshaller struct{}
type EncryptMarshaller struct {
	result tMarshallResult
}
type DecryptUnmarshaller struct {
	result tUnmarshallResult
}

// specifically for import / restore purpose
type MigrateDecryptUnmarshaller struct {
	ReEncryptRequired bool // set to true when any sensitive field needs to be re-encrypted by the new encryption mechanism
	result            tUnmarshallResult
}

type EncKeys map[string][]byte // map key is enc key version(the bigger the newer). value is the passphrase
type nvDEK struct {
	version string
	dekSeed string
}

func (m nvDEK) isAvailable() bool {
	return len(m.dekSeed) == keyLength
}

var dekSeedMutex sync.RWMutex
var currentDekSeed nvDEK                                      // for the current dekSeed for encrypting data
var dekSeedsCache map[string]string = make(map[string]string) // hash values of all passphrases in k8s secret neuvector-store-secret

func getCurrentDekSeed() nvDEK {
	dekSeedMutex.RLock()
	defer dekSeedMutex.RUnlock()
	return currentDekSeed
}

func getVersionedDekSeed(version string) string {
	dekSeedMutex.RLock()
	defer dekSeedMutex.RUnlock()
	return dekSeedsCache[version]
}

func InitAesGcmKey(encKeys EncKeys, currEncKeyVer string) error {
	if len(encKeys) == 0 {
		return ErrInvalidPassphrase
	}
	dekSeedsCacheTemp := make(map[string]string, len(encKeys))
	if passphrase, ok := encKeys[currEncKeyVer]; !ok || len(passphrase) < DekSeedLength {
		return ErrInvalidPassphrase
	}

	for keyVersion, passphrase := range encKeys {
		if len(passphrase) >= DekSeedLength {
			h := sha256.New()
			h.Write(passphrase)
			dekSeedsCacheTemp[keyVersion] = string(h.Sum(nil))
		}
	}

	if len(dekSeedsCacheTemp[currEncKeyVer]) < DekSeedLength {
		return ErrInvalidPassphrase
	}

	dekSeedMutex.Lock()
	dekSeedsCache = dekSeedsCacheTemp
	currentDekSeed = nvDEK{
		version: currEncKeyVer,
		dekSeed: dekSeedsCache[currEncKeyVer],
	}
	dekSeedMutex.Unlock()

	return nil
}

func AddAesGcmKey(keyVersion string, passphrase []byte) error {
	if len(passphrase) >= DekSeedLength {
		h := sha256.New()
		h.Write(passphrase)
		dekSeed := string(h.Sum(nil))

		dekSeedMutex.Lock()
		dekSeedsCache[keyVersion] = dekSeed
		currentDekSeed = nvDEK{
			version: keyVersion,
			dekSeed: dekSeed,
		}
		dekSeedMutex.Unlock()
		return nil
	}
	return ErrDEKSeedUnavailable
}

func IsDEKSeedAvailable() bool {
	dekSeed := getCurrentDekSeed()
	return dekSeed.isAvailable()
}

func HashPassword(password string, salt []byte) (string, error) {
	if len(salt) == 0 {
		salt = make([]byte, saltSize) // http://www.ietf.org/rfc/rfc2898.txt
		if _, err := rand.Read(salt); err != nil {
			return "", fmt.Errorf("failed to generate salt: %w", err)
		}
	}

	hashedPassword, err := pbkdf2.Key(sha256.New, password, salt, keyIter, keyLength)
	if err != nil {
		return "", fmt.Errorf("failed to generate hash: %w", err)
	}

	cipherBundle := fmt.Sprintf("%s%s-%s",
		saltedHashPrefix, hex.EncodeToString(salt), hex.EncodeToString(hashedPassword))

	return cipherBundle, nil
}

func aesGcmEncrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", ErrEmptyValue
	}
	dekSeed := getCurrentDekSeed()
	if !dekSeed.isAvailable() {
		return "", ErrDEKSeedUnavailable
	}

	salt := make([]byte, saltSize) // http://www.ietf.org/rfc/rfc2898.txt
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}
	dek, err := pbkdf2.Key(sha256.New, currentDekSeed.dekSeed, salt, keyIter, keyLength)
	if err != nil {
		return "", fmt.Errorf("failed to derive DEK: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	additionalData := append(salt, nonce...)
	cipherText := aesGCM.Seal(nil, nonce, []byte(plaintext), additionalData)
	cipherBundle := fmt.Sprintf(cipherBundleFormat, cipherTypeA,
		currentDekSeed.version, hex.EncodeToString(salt), hex.EncodeToString(nonce), hex.EncodeToString(cipherText))

	return cipherBundle, nil
}

func aesGcmDecrypt(cipherBundle string) (string, error) {
	if cipherBundle == "" {
		return "", ErrEmptyValue
	}

	ss := strings.Split(cipherBundle, "-")
	if len(ss) != cipherBundleParts || ss[0] != cipherTypeA || (len(ss[2]) != saltHexSize || len(ss[3]) != nonceHexSize) {
		return "", ErrUnsupported
	}

	if _, err := strconv.ParseUint(ss[1], 10, 64); err != nil {
		return "", fmt.Errorf("invalid version: %s", ss[1])
	}

	dekSeed := getVersionedDekSeed(ss[1])
	if len(dekSeed) != keyLength {
		return "", ErrDEKSeedUnavailable
	}

	salt, err := hex.DecodeString(ss[2])
	if err != nil || len(salt) != saltSize {
		return "", fmt.Errorf("invalid salt: %v(len=%d)", err, len(salt))
	}

	nonce, err := hex.DecodeString(ss[3])
	if err != nil || len(nonce) != nonceSize {
		return "", fmt.Errorf("invalid nonce: %v(len=%d)", err, len(nonce))
	}

	cipherText, err := hex.DecodeString(ss[4])
	if err != nil {
		return "", fmt.Errorf("invalid data: %w", err)
	}

	dek, err := pbkdf2.Key(sha256.New, dekSeed, salt, keyIter, keyLength)
	if err != nil {
		return "", fmt.Errorf("failed to derive DEK: %w", err)
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	additionalData := append(salt, nonce...)
	data, err := aesGCM.Open(nil, nonce, cipherText, additionalData)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %w", err)
	}

	return string(data), nil
}

func IsSaltedPasswordHash(hash string) bool {
	if strings.HasPrefix(hash, saltedHashPrefix) {
		return len(strings.Split(hash, "-")) == 3
	}

	return false
}

func (m EmptyMarshaller) Marshal(data interface{}) ([]byte, error) {
	if u, err := marshal(emptyMask, data, tMarshallResult{}); err != nil {
		return nil, err
	} else {
		return json.Marshal(u)
	}
}

func (m EmptyMarshaller) GetEmptyFieldsToEncrypt() utils.Set {
	return nil
}

func (m MaskMarshaller) Marshal(data interface{}) ([]byte, error) {
	if u, err := marshal(cloakMask, data, tMarshallResult{}); err != nil {
		return nil, err
	} else {
		return json.Marshal(u)
	}
}

func (m *EncryptMarshaller) Marshal(data interface{}) ([]byte, error) {
	m.result.Reset()
	if u, err := marshal(cloakEncrypt, data, m.result); err != nil {
		return nil, err
	} else {
		return json.Marshal(u)
	}
}

func (m *EncryptMarshaller) GetEmptyFieldsToEncrypt() utils.Set {
	return m.result.GetEmptyFieldsToEncrypt()
}

func (m *DecryptUnmarshaller) Unmarshal(raw []byte, data interface{}) error {
	if err := json.Unmarshal(raw, data); err != nil {
		return err
	} else {
		m.result.Reset()
		return unmarshal(cloakDecrypt, data, nil, m.result)
	}
}

func (m *DecryptUnmarshaller) Uncloak(data interface{}) error {
	m.result.Reset()
	return unmarshal(cloakDecrypt, data, nil, m.result)
}

func (m *DecryptUnmarshaller) GetEmptyEncryptedFields() utils.Set {
	return m.result.GetEmptyEncryptedFields()
}

func (m *DecryptUnmarshaller) GetFailToDecryptFields() utils.Set {
	return m.result.GetFailToDecryptFields()
}

func (m *DecryptUnmarshaller) GetDecryptedFieldsNumber() int {
	return m.result.decryptedFieldsNumber
}

func (m *MigrateDecryptUnmarshaller) Unmarshal(raw []byte, data interface{}) error {
	if err := json.Unmarshal(raw, data); err != nil {
		return err
	} else {
		m.result.Reset()
		return unmarshal(cloakDecrypt, data, &m.ReEncryptRequired, m.result)
	}
}

func (m *MigrateDecryptUnmarshaller) Uncloak(data interface{}) error {
	m.result.Reset()
	return unmarshal(cloakDecrypt, data, &m.ReEncryptRequired, m.result)
}

func (m *MigrateDecryptUnmarshaller) GetEmptyEncryptedFields() utils.Set {
	return m.result.GetEmptyEncryptedFields()
}

func (m *MigrateDecryptUnmarshaller) GetFailToDecryptFields() utils.Set {
	return m.result.GetFailToDecryptFields()
}

func (m *MigrateDecryptUnmarshaller) GetDecryptedFieldsNumber() int {
	return m.result.decryptedFieldsNumber
}

type MarshalInvalidTypeError struct {
	t    reflect.Kind
	data interface{}
}

func (e MarshalInvalidTypeError) Error() string {
	return fmt.Sprintf("marshaller: Unable to marshal type %s. Struct required.", e.t)
}

// --

// marshal() creates a map for json.Marshal calls to use, so the original data is not modified;
// unmarshal() modifies the data in place, so it is used for json.Unmarshal calls.

// TODO: These two functions go through the entire data structure. It incurs unnecessary overhead
// if the data doesn't need to be masked. We could build an list of data structures that do not
// require mask, so after the first time, the same data type will not be subject to the overhead.

func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice:
		return reflect.DeepEqual(v.Interface(), reflect.Zero(v.Type()).Interface())
	case reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Interface, reflect.Ptr:
		return v.IsNil()
	}
	return false
}

func parseTag(tag string) (string, utils.Set) {
	tokens := strings.Split(tag, ",")
	if len(tokens) == 0 {
		return "", utils.NewSet()
	}
	return tokens[0], utils.NewSetFromSliceKind(tokens[1:])
}

func unmarshal(cloak string, data interface{}, reEncryptRequired *bool, unmarshalResult tUnmarshallResult) error {
	v := reflect.ValueOf(data)
	t := v.Type()

	if t.Kind() == reflect.Ptr {
		// follow pointer
		t = t.Elem()
	}
	if v.Kind() == reflect.Ptr {
		// follow pointer
		v = v.Elem()
	}

	if t.Kind() != reflect.Struct {
		return unmarshalValue(cloak, v, reEncryptRequired, unmarshalResult)
	}

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		val := v.Field(i)

		jsonTag, jsonOpts := parseTag(field.Tag.Get("json"))

		// If no json tag is provided, use the field Name
		if jsonTag == "" {
			jsonTag = field.Name
		}

		if jsonTag == "-" {
			continue
		}
		// skip unexported fields
		if !val.IsValid() || !val.CanInterface() {
			continue
		}

		if val.Kind() == reflect.Ptr {
			val = val.Elem()
		}

		// we can skip the group checkif if the field is a composition field
		if val.Kind() == reflect.String {
			if jsonOpts.Contains(cloakTag) {
				switch cloak {
				case cloakDecrypt:
					if val.CanSet() {
						var s string
						var err error
						if strVal := val.Interface().(string); strVal != "" {
							if idx := strings.Index(strVal, "-"); idx < 0 {
								// it's encrypted by the fixed default key.
								if s = utils.DecryptPassword(strVal); s != "" {
									if reEncryptRequired != nil {
										*reEncryptRequired = true
									}
									unmarshalResult.IncreaseDecryptedFields()
								} else {
									s = strVal
								}
							} else {
								// it's encrypted by variant DEK
								if s, err = aesGcmDecrypt(strVal); err != nil {
									if err != ErrDEKSeedUnavailable && err != ErrEmptyValue {
										log.WithFields(log.Fields{"error": err, "jsonTag": jsonTag}).Error()
									}
									if err == ErrEmptyValue {
										unmarshalResult.AddEmptyEncryptedField(jsonTag)
									} else {
										unmarshalResult.AddFailedToDecryptField(jsonTag)
									}
									s = strVal
								} else {
									unmarshalResult.IncreaseDecryptedFields()
								}
							}
						}
						val.SetString(s)
					}
				}
			}
		}

		if val.CanAddr() {
			err := unmarshalValue(cloak, val.Addr(), reEncryptRequired, unmarshalResult)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func unmarshalValue(cloak string, v reflect.Value, reEncryptRequired *bool, unmarshalResult tUnmarshallResult) error {
	// return nil on nil pointer struct fields
	if !v.IsValid() || !v.CanInterface() {
		return nil
	}

	k := v.Kind()
	if k == reflect.Ptr {
		v = v.Elem()
		k = v.Kind()
	}

	if k == reflect.Interface || k == reflect.Struct {
		if v.CanAddr() {
			return unmarshal(cloak, v.Addr().Interface(), reEncryptRequired, unmarshalResult)
		} else {
			return nil
		}
	}

	if k == reflect.Slice {
		l := v.Len()
		for i := 0; i < l; i++ {
			err := unmarshalValue(cloak, v.Index(i), reEncryptRequired, unmarshalResult)
			if err != nil {
				return err
			}
		}
		return nil
	}
	if k == reflect.Map {
		mapKeys := v.MapKeys()
		if len(mapKeys) == 0 {
			return nil
		}
		if mapKeys[0].Kind() != reflect.String {
			return MarshalInvalidTypeError{t: mapKeys[0].Kind(), data: v.Interface()}
		}
		for _, key := range mapKeys {
			err := unmarshalValue(cloak, v.MapIndex(key), reEncryptRequired, unmarshalResult)
			if err != nil {
				return err
			}
		}
		return nil
	}
	return nil
}

func marshal(cloak string, data interface{}, marshalResult tMarshallResult) (interface{}, error) {
	v := reflect.ValueOf(data)
	t := v.Type()

	if t.Kind() == reflect.Ptr {
		// follow pointer
		t = t.Elem()
	}
	if v.Kind() == reflect.Ptr {
		// follow pointer
		v = v.Elem()
	}

	if t.Kind() != reflect.Struct {
		return marshalValue(cloak, v, marshalResult)
	}

	dest := make(map[string]interface{})

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		val := v.Field(i)

		jsonTag, jsonOpts := parseTag(field.Tag.Get("json"))

		// If no json tag is provided, use the field Name
		if jsonTag == "" {
			jsonTag = field.Name
		}

		if jsonTag == "-" {
			continue
		}
		if jsonOpts.Contains("omitempty") && isEmptyValue(val) {
			continue
		}
		// skip unexported fields
		if !val.IsValid() || !val.CanInterface() {
			continue
		}

		if val.Kind() == reflect.Ptr {
			val = val.Elem()
		}

		isEmbeddedField := field.Anonymous && val.Kind() == reflect.Struct

		// we can skip the group checkif if the field is a composition field
		if val.Kind() == reflect.String {
			if jsonOpts.Contains(cloakTag) {
				switch cloak {
				case emptyMask:
					m := ""
					val = reflect.ValueOf(m)
				case cloakMask:
					// Don't use SetString as val might not be addressable
					m := api.RESTMaskedValue
					val = reflect.ValueOf(m)
				case cloakEncrypt:
					var m string
					if strVal := val.Interface().(string); strVal != "" {
						if currentDekSeed.isAvailable() {
							var err error
							if m, err = aesGcmEncrypt(strVal); err != nil {
								if err != ErrDEKSeedUnavailable && err != ErrEmptyValue {
									log.WithFields(log.Fields{"err": err, "jsonTag": jsonTag}).Error()
								}
								if err == ErrEmptyValue {
									marshalResult.AddEmptyFieldToEncrypt(jsonTag)
								}
								m = utils.EncryptPassword(strVal)
							}
						} else {
							m = utils.EncryptPassword(strVal)
						}
					}
					val = reflect.ValueOf(m)
				}
			}
		}

		v, err := marshalValue(cloak, val, marshalResult)
		if err != nil {
			return nil, err
		}

		nestedVal, ok := v.(map[string]interface{})
		if isEmbeddedField && ok {
			for key, value := range nestedVal {
				dest[key] = value
			}
		} else {
			dest[jsonTag] = v
		}
	}

	return dest, nil
}

func marshalValue(cloak string, v reflect.Value, marshalResult tMarshallResult) (interface{}, error) {
	// return nil on nil pointer struct fields
	if !v.IsValid() || !v.CanInterface() {
		return nil, nil
	}

	val := v.Interface()

	// types which are e.g. structs, slices or maps and implement one of the following interfaces should not be
	// marshalled by sheriff because they'll be correctly marshalled by json.Marshal instead.
	// Otherwise (e.g. net.IP) a byte slice may be output as a list of uints instead of as an IP string.
	switch val.(type) {
	case json.Marshaler, encoding.TextMarshaler, fmt.Stringer:
		return val, nil
	}

	k := v.Kind()
	if k == reflect.Ptr {
		v = v.Elem()
		val = v.Interface()
		k = v.Kind()
	}

	if k == reflect.Interface || k == reflect.Struct {
		return marshal(cloak, val, marshalResult)
	}
	if k == reflect.Slice {
		if isEmptyValue(v) {
			return nil, nil
		}

		l := v.Len()
		dest := make([]interface{}, l)
		for i := 0; i < l; i++ {
			d, err := marshalValue(cloak, v.Index(i), marshalResult)
			if err != nil {
				return nil, err
			}
			dest[i] = d
		}
		return dest, nil
	}
	if k == reflect.Map {
		dest := make(map[string]interface{})

		if isEmptyValue(v) {
			if v.IsNil() {
				return nil, nil
			} else {
				return dest, nil
			}
		}

		mapKeys := v.MapKeys()
		if len(mapKeys) == 0 {
			return dest, nil
		}
		if mapKeys[0].Kind() != reflect.String {
			return nil, MarshalInvalidTypeError{t: mapKeys[0].Kind(), data: val}
		}
		for _, key := range mapKeys {
			d, err := marshalValue(cloak, v.MapIndex(key), marshalResult)
			if err != nil {
				return nil, err
			}
			dest[key.Interface().(string)] = d
		}
		return dest, nil
	}
	return val, nil
}
