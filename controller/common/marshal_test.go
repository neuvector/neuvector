package common

import (
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
	_ = json.Unmarshal(body, &user)
	if user.Password != api.RESTMaskedValue || *user.Secret != api.RESTMaskedValue {
		t.Errorf("Incorrect mask marshal: %s", string(body[:]))
	}

	var pair maskUserPair
	p := maskUserPair{User1: u1, User2: &u2}
	body, _ = m.Marshal(&p)
	_ = json.Unmarshal(body, &pair)
	if pair.User1.Password != api.RESTMaskedValue || *pair.User1.Secret != api.RESTMaskedValue ||
		pair.User2.Password != api.RESTMaskedValue || *pair.User2.Secret != api.RESTMaskedValue {
		t.Errorf("Incorrect mask marshal: %s", string(body[:]))
	}

	var list maskUserList
	l := maskUserList{Users: []*maskUser{&u1, &u2}}
	body, _ = m.Marshal(&l)
	_ = json.Unmarshal(body, &list)
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
	_ = json.Unmarshal(body, &d)
	if d.Map == nil || d.List == nil {
		t.Errorf("Incorrect mask marshal: %s", string(body[:]))
	}

	d1 = maskEmpty{}
	body, _ = m.Marshal(&d1)
	_ = json.Unmarshal(body, &d)
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
	_ = dec.Unmarshal(body, &user)
	if !reflect.DeepEqual(user, u1) {
		t.Errorf("Incorrect mask marshal: marshal=%s", string(body[:]))
		body, _ = json.Marshal(&user)
		t.Errorf("Incorrect mask marshal: unmarshal=%s", string(body[:]))
	}

	var pair maskUserPair
	p := maskUserPair{User1: u1, User2: &u2}
	body, _ = enc.Marshal(&p)
	_ = dec.Unmarshal(body, &pair)
	if !reflect.DeepEqual(pair.User1, u1) || !reflect.DeepEqual(*pair.User2, u2) {
		t.Errorf("Incorrect mask marshal: marshal=%s", string(body[:]))
		body, _ = json.Marshal(&pair)
		t.Errorf("Incorrect mask marshal: unmarshal=%s", string(body[:]))
	}
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
	_ = dec.Unmarshal(body, &b)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("Incorrect mask marshal: marshal=%s", string(body[:]))
	}
}

func TestAuthServer(t *testing.T) {
	body := "{\"config\":{\"ldap\":{\"base_dn\":\"abc\",\"bind_dn\":\"abc\",\"bind_password\":\"very sensitive\",\"directory\":\"OpenLDAP\",\"enable\":true,\"hostname\":\"1.2.3.4\",\"role_groups\":{\"admin\":[],\"reader\":[]}},\"name\":\"ldap1\"}}"

	var rconf api.RESTServerConfigData
	_ = json.Unmarshal([]byte(body), &rconf)

	var m MaskMarshaller
	masked, _ := m.Marshal(&rconf)

	var maskedConf api.RESTServerConfigData
	_ = json.Unmarshal(masked, &maskedConf)

	if *maskedConf.Config.LDAP.BindPasswd != api.RESTMaskedValue {
		t.Errorf("Incorrect mask marshal: marshal=%s", string(masked[:]))
	}
}
