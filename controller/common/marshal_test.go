package common

import (
	"strings"
	"testing"

	"encoding/json"
	"net"
	"reflect"

	"github.com/neuvector/neuvector/controller/api"
)

type MaskEmbed struct {
	City    string `json:"city"`
	Company string `json:"company"`
}

type maskUser struct {
	Username string  `json:"username"`
	Alias    string  `json:"alias"`
	Password string  `json:"password,cloak"`
	Secret   *string `json:"secret,cloak"`
	MaskEmbed
}

type maskUserPair struct {
	User1 maskUser  `json:"user1"`
	User2 *maskUser `json:"user2"`
}

type maskUserList struct {
	Users []*maskUser `json:"users"`
}

type maskEmpty struct {
	Map  map[string]int `json:"map"`
	List []int          `json:"list"`
}

func TestMask(t *testing.T) {
	var m MaskMarshaller

	secret := "gary321"
	u1 := maskUser{Username: "gary", Alias: "gary's alias", Password: "gary123", Secret: &secret}
	u2 := maskUser{Username: "mary", Password: "mary123", Secret: &secret}
	u1.City = "San Jose"
	u2.City = "San Francisco"

	var user maskUser
	body, _ := m.Marshal(&u1)
	unmarshalJSON(t, body, &user)
	if user.Password != api.RESTMaskedValue || *user.Secret != api.RESTMaskedValue {
		t.Errorf("Incorrect mask marshal: %s", string(body[:]))
	}

	var pair maskUserPair
	p := maskUserPair{User1: u1, User2: &u2}
	body, _ = m.Marshal(&p)
	unmarshalJSON(t, body, &pair)
	if pair.User1.Password != api.RESTMaskedValue || *pair.User1.Secret != api.RESTMaskedValue ||
		pair.User2.Password != api.RESTMaskedValue || *pair.User2.Secret != api.RESTMaskedValue {
		t.Errorf("Incorrect mask marshal: %s", string(body[:]))
	}

	var list maskUserList
	l := maskUserList{Users: []*maskUser{&u1, &u2}}
	body, _ = m.Marshal(&l)
	unmarshalJSON(t, body, &list)
	if list.Users[0].Password != api.RESTMaskedValue || *list.Users[0].Secret != api.RESTMaskedValue ||
		list.Users[1].Password != api.RESTMaskedValue || *list.Users[1].Secret != api.RESTMaskedValue {
		t.Errorf("Incorrect mask marshal: %s", string(body[:]))
	}
}

func TestMaskEmpty(t *testing.T) {
	var m MaskMarshaller
	var d maskEmpty

	d1 := maskEmpty{Map: make(map[string]int), List: make([]int, 0)}
	body, _ := m.Marshal(&d1)
	unmarshalJSON(t, body, &d)
	if d.Map == nil || d.List == nil {
		t.Errorf("Incorrect mask marshal: %s", string(body[:]))
	}

	d1 = maskEmpty{}
	body, _ = m.Marshal(&d1)
	unmarshalJSON(t, body, &d)
	if d.Map != nil || d.List != nil {
		t.Errorf("Incorrect mask marshal: %s", string(body[:]))
	}
}

func TestEncrypt(t *testing.T) {
	var enc EncryptMarshaller
	var dec DecryptUnmarshaller

	secret := "gary321"
	u1 := maskUser{Username: "gary", Password: "gary123", Secret: &secret}
	u2 := maskUser{Username: "mary", Password: "mary123", Secret: &secret}

	var user maskUser
	body, _ := enc.Marshal(&u1)
	if err := dec.Unmarshal(body, &user); err != nil {
		t.Errorf("Unmarshal error: %v", err)
	}
	if !reflect.DeepEqual(user, u1) {
		t.Errorf("Incorrect mask marshal: marshal=%s", string(body[:]))
		body, _ = json.Marshal(&user)
		t.Errorf("Incorrect mask marshal: unmarshal=%s", string(body[:]))
	}

	var pair maskUserPair
	p := maskUserPair{User1: u1, User2: &u2}
	body, _ = enc.Marshal(&p)
	if err := dec.Unmarshal(body, &pair); err != nil {
		t.Errorf("Unmarshal error: %v", err)
	}
	if !reflect.DeepEqual(pair.User1, u1) || !reflect.DeepEqual(*pair.User2, u2) {
		t.Errorf("Incorrect mask marshal: marshal=%s", string(body[:]))
		body, _ = json.Marshal(&pair)
		t.Errorf("Incorrect mask marshal: unmarshal=%s", string(body[:]))
	}
}

func resetDekSeeds() {
	dekSeedMutex.Lock()
	defer dekSeedMutex.Unlock()

	currentDekSeed = nvDEK{}
	dekSeedsCache = make(map[string]string)
}

// just for unit test
func _deleteAesGcmKey(keyVersion string) {
	dekSeedMutex.Lock()
	defer dekSeedMutex.Unlock()

	delete(dekSeedsCache, keyVersion)
	if currentDekSeed.version == keyVersion {
		if len(dekSeedsCache) > 0 {
			for k, v := range dekSeedsCache {
				currentDekSeed = nvDEK{
					version: k,
					dekSeed: v,
				}
				break
			}
		} else {
			currentDekSeed = nvDEK{}
		}
	}
}

func TestAesGcmEncrypt(t *testing.T) {
	var enc EncryptMarshaller
	var dec DecryptUnmarshaller

	secret := "gary321"
	u1 := maskUser{Username: "gary", Password: "gary123", Secret: &secret}
	u2 := maskUser{Username: "mary", Password: "mary123", Secret: &secret}

	var user maskUser
	keyVersion := "1"
	if err := InitAesGcmKey(map[string][]byte{keyVersion: []byte("abcdefghijklmnopqrstuvwxyz123456")}, keyVersion); err != nil {
		t.Errorf("InitAesGcmKey failed: error=%v", err)
	}

	body, err := enc.Marshal(&u1) // enc marshal with DEK
	if u1.Secret == nil || err != nil {
		t.Errorf("enc.Marshal error: %v (u1.Secret=%v)", err, u1.Secret)
		return
	}

	// now sensitive fields in 'body' is encrypted with DEK.

	if err := json.Unmarshal(body, &user); err != nil { // sensitive fields(encrypted) are not decrypted after json unmarshal
		t.Errorf("json.Unmarshal error: %v", err)
	} else {
		if ss := strings.Split(*user.Secret, "-"); len(ss) != cipherBundleParts {
			t.Errorf("Unexpected json.Unmarshal result: %v (user.Secret=%v)", err, *user.Secret)
		}
	}

	if err := dec.Unmarshal(body, &user); err != nil { // dec unmarshal with DEK
		t.Errorf("dec.Unmarshal error: %v", err)
	} else if failed := dec.GetFailToDecryptFields(); failed != nil && failed.Cardinality() > 0 {
		t.Errorf("Failed to decrypt %v", failed)
	} else if !reflect.DeepEqual(user, u1) {
		t.Errorf("Incorrect mask marshal: marshal=%s, user=%v, u1=%v", string(body[:]), user, u1)
		body, _ := json.Marshal(&user)
		t.Errorf("Incorrect mask marshal: unmarshal=%s", string(body[:]))
	}

	var pair maskUserPair
	p := maskUserPair{User1: u1, User2: &u2}
	body, err = enc.Marshal(&p) // enc marshal with DEK
	if p.User1.Secret == nil || p.User2.Secret == nil || err != nil {
		t.Errorf("enc.Marshal error: %v (p.User1.Secret=%v, p.User2.Secret=%v)", err, p.User1.Secret, p.User2.Secret)
	} else {
		if err := json.Unmarshal(body, &pair); err != nil { // sensitive fields(encrypted) are not decrypted after json unmarshal
			t.Errorf("json.Unmarshal error: %v", err)
		} else {
			if ss := strings.Split(*pair.User1.Secret, "-"); len(ss) != cipherBundleParts {
				t.Errorf("Unexpected pair.User1 Marshal result: %v (pair.User1.Secret=%v)", err, *pair.User1.Secret)
			} else if ss := strings.Split(*pair.User2.Secret, "-"); len(ss) != cipherBundleParts {
				t.Errorf("Unexpected pair.User2 Marshal result: %v (pair.User2.Secret=%v)", err, *pair.User2.Secret)
			}
		}

		if err := dec.Unmarshal(body, &pair); err != nil { // dec unmarshal with DEK
			t.Errorf("dec.Unmarshal error: %v", err)
		} else if failed := dec.GetFailToDecryptFields(); failed != nil && failed.Cardinality() > 0 {
			t.Errorf("Failed to decrypt %v", failed)
		} else if !reflect.DeepEqual(pair.User1, u1) || !reflect.DeepEqual(*pair.User2, u2) {
			t.Errorf("Incorrect mask marshal: marshal=%s", string(body[:]))
			body, _ := json.Marshal(&pair)
			t.Errorf("Incorrect mask marshal: unmarshal=%s", string(body[:]))
		}
	}

	resetDekSeeds()
}

func TestAesGcmDecryptWithRotation(t *testing.T) {
	var enc EncryptMarshaller
	var dec DecryptUnmarshaller

	secret := "gary321"
	u1 := maskUser{Username: "gary", Password: "gary123", Secret: &secret}

	var user maskUser
	keyVersion1 := "1"
	if err := InitAesGcmKey(map[string][]byte{keyVersion1: []byte("11cdefghijklmnopqrstuvwxyz123456")}, keyVersion1); err != nil {
		t.Errorf("InitAesGcmKey failed: error=%v", err)
	}
	currDekSeed1 := getCurrentDekSeed()
	if currDekSeed1.version != keyVersion1 || !currDekSeed1.isAvailable() {
		t.Errorf("currDekSeed1 error: %v", currDekSeed1)
	}

	body, err := enc.Marshal(&u1) // enc marshal with DEK (current DEK is dekSeed-v1)
	if u1.Secret == nil || err != nil {
		t.Errorf("enc.Marshal error: %v (u1.Secret=%v)", err, u1.Secret)
		return
	}

	// now sensitive fields in 'body' is encrypted with dekSeed-v1.

	if err := json.Unmarshal(body, &user); err != nil { // sensitive fields(encrypted) are not decrypted after json unmarshal
		t.Errorf("json.Unmarshal error: %v", err)
	} else {
		if ss := strings.Split(*user.Secret, "-"); len(ss) != cipherBundleParts {
			t.Errorf("Unexpected json.Unmarshal result: %v (user.Secret=%v)", err, *user.Secret)
		}
	}

	if err := dec.Unmarshal(body, &user); err != nil { // dec unmarshal (current DEK is dekSeed-v1)
		t.Errorf("dec.Unmarshal error: %v", err)
	} else if failed := dec.GetFailToDecryptFields(); failed != nil && failed.Cardinality() > 0 {
		t.Errorf("Failed to decrypt %v", failed)
	} else if !reflect.DeepEqual(user, u1) {
		t.Errorf("Incorrect mask marshal: marshal=%s, user=%v, u1=%v", string(body[:]), user, u1)
		body, _ := json.Marshal(&user)
		t.Errorf("Incorrect mask marshal: unmarshal=%s", string(body[:]))
	}

	// now currentDekSeed is set to version 2
	keyVersion2 := "2"
	if err := AddAesGcmKey(keyVersion2, []byte("22cdefghijklmnopqrstuvwxyz123456")); err != nil {
		t.Errorf("AddAesGcmKey failed: error=%v", err)
	}
	currDekSeed2 := getCurrentDekSeed()
	if currDekSeed2 == currDekSeed1 || currDekSeed2.version != keyVersion2 || !currDekSeed2.isAvailable() {
		t.Errorf("currDekSeed2 error: %v", currDekSeed2)
	}

	// try dec.Unmarshal again to see whether the sensitive data encrypted with dekSeed-v1 can be decrypted when the currentDekSeed is version 2.
	user = maskUser{}
	if err := dec.Unmarshal(body, &user); err != nil { // dec unmarshal (current DEK is dekSeed-v2 but dekSeed-v1 is used for this decryption)
		t.Errorf("dec.Unmarshal error: %v", err)
	} else if failed := dec.GetFailToDecryptFields(); failed != nil && failed.Cardinality() > 0 {
		t.Errorf("Failed to decrypt %v", failed)
	} else if !reflect.DeepEqual(user, u1) {
		t.Errorf("Incorrect mask marshal: marshal=%s, user=%v, u1=%v", string(body[:]), user, u1)
		body, _ := json.Marshal(&user)
		t.Errorf("Incorrect mask marshal: unmarshal=%s", string(body[:]))
	}

	// now intentionally delete dekSeed-v1 from cache (ideally should not happen in real world)
	_deleteAesGcmKey(keyVersion1)

	// try dec.Unmarshal again. currentDekSeed is version 2 & there is no dekSeed-v1 in the cache.
	// it's expected that the sensitive data encrypted by dekSeed-v1 can not be decrypted anymore.
	user = maskUser{}
	if err := dec.Unmarshal(body, &user); err != nil { // dec unmarshal (current DEK is dekSeed-v2 and there is no dekSeed-v1 in the cache)
		t.Errorf("dec.Unmarshal error: %v", err)
	} else if failed := dec.GetFailToDecryptFields(); failed == nil || failed.Cardinality() == 0 {
		t.Errorf("Expected to fail to decrypt sensitive fields in the object")
	} else if failed.Cardinality() != 2 {
		t.Errorf("Expected to fail to decrypt 2, not %d, sensitive fields in the object", failed.Cardinality())
	} else if !failed.Contains("password") || !failed.Contains("secret") {
		t.Errorf("Expected to fail to decrypt sensitive fields, %v, in the object", failed.ToStringSlice())
	}

	// Now try enc.Marshal again. Because current DEK is dekSeed-v2, it's expected the marshaled data is different
	body2, err2 := enc.Marshal(&u1) // enc marshal with DEK (current DEK is dekSeed-v2)
	if u1.Secret == nil || err2 != nil {
		t.Errorf("enc.Marshal error: %v (u1.Secret=%v)", err, u1.Secret)
	} else if string(body) == string(body2) {
		t.Errorf("Expected to have different marshaled data because sensitive fields in the objects are encrypted with different dekSeed")
	}

	resetDekSeeds()
}

func TestAesGcmDecryptNegative(t *testing.T) {
	var enc EncryptMarshaller
	var dec DecryptUnmarshaller

	secret := "gary321"
	u1 := maskUser{Username: "gary", Password: "gary123", Secret: &secret}

	var user maskUser
	keyVersion := "1"
	if err := InitAesGcmKey(map[string][]byte{keyVersion: []byte("abcdefghijklmnopqrstuvwxyz123456")}, keyVersion); err != nil {
		t.Errorf("[1] InitAesGcmKey failed: error=%v", err)
	}

	body, err := enc.Marshal(&u1) // enc marshal with DEK
	if u1.Secret == nil || err != nil {
		t.Errorf("enc.Marshal error: %v (u1.Secret=%v)", err, u1.Secret)
		return
	}

	// now sensitive fields in 'body' is encrypted with DEK.

	// change dekSeed to different value
	if err := InitAesGcmKey(map[string][]byte{keyVersion: []byte("abcdefghijklmnopqrstuvwxyz123457")}, keyVersion); err != nil {
		t.Errorf("[2] InitAesGcmKey failed: error=%v", err)
	}

	// try to decrypt with different dekSeed
	if err := dec.Unmarshal(body, &user); err != nil { // dec unmarshal with DEK
		t.Errorf("dec.Unmarshal error: %v", err)
	} else if failed := dec.GetFailToDecryptFields(); failed.Cardinality() == 0 {
		t.Errorf("Unexpected that all sensitive fields can be decrypt")
	} else if reflect.DeepEqual(user, u1) {
		t.Errorf("Incorrect mask marshal: marshal=%s", string(body[:]))
		body, _ := json.Marshal(&user)
		t.Errorf("Incorrect mask marshal: unmarshal=%s", string(body[:]))
	}

	resetDekSeeds()
}

func TestAesGcmMigrateDecryptUnmarshaller(t *testing.T) {
	var enc EncryptMarshaller
	var dec DecryptUnmarshaller

	secret := "gary321"
	u1 := maskUser{Username: "gary", Password: "gary123", Secret: &secret}

	resetDekSeeds()

	var user maskUser
	body, err := enc.Marshal(&u1) // enc marshal with fixed default key
	if u1.Secret == nil || err != nil {
		t.Errorf("enc.Marshal error: %v (u1.Secret=%v)", err, u1.Secret)
		return
	}

	// now sensitive fields in 'body' is encrypted with fixed default key.

	if err := json.Unmarshal(body, &user); err != nil { // sensitive fields(encrypted) are not decrypted after json unmarshal
		t.Errorf("json.Unmarshal error: %v", err)
	} else if ss := strings.Split(*user.Secret, "-"); len(ss) != 1 {
		t.Errorf("Unexpected json.Marshal result: %v (user.Secret=%v)", err, *user.Secret)
	}

	if err := dec.Unmarshal(body, &user); err != nil { // dec unmarshal with fixed default key
		t.Errorf("dec.Unmarshal error: %v", err)
	} else if !reflect.DeepEqual(user, u1) {
		t.Errorf("Incorrect mask marshal: marshal=%s", string(body[:]))
		body, _ := json.Marshal(&user)
		t.Errorf("Incorrect mask marshal: unmarshal=%s", string(body[:]))
	}

	keyVersion := "1"
	if err := InitAesGcmKey(map[string][]byte{keyVersion: []byte("abcdefghijklmnopqrstuvwxyz123456")}, keyVersion); err != nil {
		t.Errorf("InitAesGcmKey failed: error=%v", err)
	}

	// now DEK & fixed default key are available

	var user1 maskUser
	var dec2 MigrateDecryptUnmarshaller
	if err := dec2.Unmarshal(body, &user1); err != nil { // dec unmarshal with fixed default key & set dec2.ReEncryptRequired to true
		t.Errorf("Unmarshal error: %v", err)
	} else if !dec2.ReEncryptRequired {
		t.Errorf("Expect dec2.ReEncryptRequired=true but not see that")
	} else {
		if !reflect.DeepEqual(user1, u1) {
			t.Errorf("Incorrect mask marshal: marshal=%s", string(body[:]))
			body, _ := json.Marshal(&user)
			t.Errorf("Incorrect mask marshal: unmarshal=%s", string(body[:]))
		}
	}

	var user2 maskUser
	if err := dec.Unmarshal(body, &user2); err != nil { // dec unmarshal with fixed default key
		t.Errorf("dec.Unmarshal error: %v", err)
	} else {
		if !reflect.DeepEqual(user1, user2) {
			t.Errorf("Incorrect mask marshal: marshal=%s", string(body[:]))
			body, _ := json.Marshal(&user2)
			t.Errorf("Incorrect mask marshal: unmarshal=%s", string(body[:]))
		}
	}

	var user3 maskUser
	if err := json.Unmarshal(body, &user3); err != nil { // sensitive fields(encrypted) are not decrypted after json unmarshal
		t.Errorf("json.Unmarshal error: %v", err)
	} else {
		var dec3 MigrateDecryptUnmarshaller
		if err := dec3.Uncloak(&user3); err != nil { // uncloak sensitive fields with fixed default key & set dec3.ReEncryptRequired to true
			t.Errorf("dec3.Uncloak error: %v", err)
		} else if !dec3.ReEncryptRequired {
			t.Errorf("Expect dec3.ReEncryptRequired=true but not see that")
		} else {
			if !reflect.DeepEqual(user3, u1) {
				t.Errorf("Incorrect mask marshal: marshal=%s", string(body[:]))
				body, _ := json.Marshal(&user3)
				t.Errorf("Incorrect mask marshal: unmarshal=%s", string(body[:]))
			}
		}
	}

	resetDekSeeds()
}

type aType struct {
	IP    net.IP   `json:"ip"`
	Array []byte   `json:"array"`
	IPs   []net.IP `json:"ips"`
}

func TestSpecialType(t *testing.T) {
	var enc EncryptMarshaller
	var dec DecryptUnmarshaller
	var b aType

	a := aType{
		IP: net.IPv4(1, 2, 3, 4), Array: []byte{4, 5, 6, 7},
		IPs: []net.IP{net.IPv4(1, 2, 3, 4), net.IPv4(9, 8, 7, 6)},
	}
	body, _ := enc.Marshal(&a)
	if err := dec.Unmarshal(body, &b); err != nil {
		t.Errorf("Unmarshal error: %v", err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Errorf("Incorrect mask marshal: marshal=%s", string(body[:]))
	}
}

func TestAuthServer(t *testing.T) {
	body := "{\"config\":{\"ldap\":{\"base_dn\":\"abc\",\"bind_dn\":\"abc\",\"bind_password\":\"very sensitive\",\"directory\":\"OpenLDAP\",\"enable\":true,\"hostname\":\"1.2.3.4\",\"role_groups\":{\"admin\":[],\"reader\":[]}},\"name\":\"ldap1\"}}"

	var rconf api.RESTServerConfigData
	unmarshalJSON(t, []byte(body), &rconf)

	var m MaskMarshaller
	masked, _ := m.Marshal(&rconf)

	var maskedConf api.RESTServerConfigData
	unmarshalJSON(t, masked, &maskedConf)

	if *maskedConf.Config.LDAP.BindPasswd != api.RESTMaskedValue {
		t.Errorf("Incorrect mask marshal: marshal=%s", string(masked[:]))
	}
}

func unmarshalJSON(t *testing.T, data []byte, v interface{}) {
	if err := json.Unmarshal(data, v); err != nil {
		t.Errorf("Unmarshal error: %v", err)
	}
}
