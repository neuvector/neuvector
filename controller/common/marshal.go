package common

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/share/utils"
)

type Marshaller interface {
	Marshal(data interface{}) ([]byte, error)
}
type Unmarshaller interface {
	Unmarshal(raw []byte, data interface{}) error
	Uncloak(data interface{}) error
}

const (
	cloakTag     = "cloak"
	cloakMask    = "mask"
	emptyMask    = "empty"
	cloakEncrypt = "encrypt"
	cloakDecrypt = "decrypt"
)

const (
	saltSize = 16

	keyLength = 32
	keyIter   = 600000

	saltedHashPrefix = "s-"
)

type EmptyMarshaller struct{}
type MaskMarshaller struct{}
type EncryptMarshaller struct{}
type DecryptUnmarshaller struct{}

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

func IsSaltedPasswordHash(hash string) bool {
	if strings.HasPrefix(hash, saltedHashPrefix) {
		return len(strings.Split(hash, "-")) == 3
	}

	return false
}

func (m EmptyMarshaller) Marshal(data interface{}) ([]byte, error) {
	if u, err := marshal(emptyMask, data); err != nil {
		return nil, err
	} else {
		return json.Marshal(u)
	}
}

func (m MaskMarshaller) Marshal(data interface{}) ([]byte, error) {
	if u, err := marshal(cloakMask, data); err != nil {
		return nil, err
	} else {
		return json.Marshal(u)
	}
}

func (m EncryptMarshaller) Marshal(data interface{}) ([]byte, error) {
	if u, err := marshal(cloakEncrypt, data); err != nil {
		return nil, err
	} else {
		return json.Marshal(u)
	}
}

func (m DecryptUnmarshaller) Unmarshal(raw []byte, data interface{}) error {
	if err := json.Unmarshal(raw, data); err != nil {
		return err
	} else {
		return unmarshal(cloakDecrypt, data)
	}
}

func (m DecryptUnmarshaller) Uncloak(data interface{}) error {
	return unmarshal(cloakDecrypt, data)
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

func unmarshal(cloak string, data interface{}) error {
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
		return unmarshalValue(cloak, v)
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
						s := utils.DecryptPassword(val.Interface().(string))
						val.SetString(s)
					}
				}
			}
		}

		if val.CanAddr() {
			err := unmarshalValue(cloak, val.Addr())
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func unmarshalValue(cloak string, v reflect.Value) error {
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
			return unmarshal(cloak, v.Addr().Interface())
		} else {
			return nil
		}
	}

	if k == reflect.Slice {
		l := v.Len()
		for i := 0; i < l; i++ {
			err := unmarshalValue(cloak, v.Index(i))
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
			err := unmarshalValue(cloak, v.MapIndex(key))
			if err != nil {
				return err
			}
		}
		return nil
	}
	return nil
}

func marshal(cloak string, data interface{}) (interface{}, error) {
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
		return marshalValue(cloak, v)
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
					m := utils.EncryptPassword(val.Interface().(string))
					val = reflect.ValueOf(m)
				}
			}
		}

		v, err := marshalValue(cloak, val)
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

func marshalValue(cloak string, v reflect.Value) (interface{}, error) {
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
		return marshal(cloak, val)
	}
	if k == reflect.Slice {
		if isEmptyValue(v) {
			return nil, nil
		}

		l := v.Len()
		dest := make([]interface{}, l)
		for i := 0; i < l; i++ {
			d, err := marshalValue(cloak, v.Index(i))
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
			d, err := marshalValue(cloak, v.MapIndex(key))
			if err != nil {
				return nil, err
			}
			dest[key.Interface().(string)] = d
		}
		return dest, nil
	}
	return val, nil
}
