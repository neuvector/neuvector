package utils

import (
	"testing"

	"net"

	"github.com/neuvector/neuvector/share"
)

func TestNormalizeForURL(t *testing.T) {
	repls := map[string]string{
		"nginx":                     "nginx",
		"nginx:5":                   "nginx:5",
		"neuvector/nginx:5":         "neuvector:nginx:5",
		"service nginx":             "service:nginx",
		"service nginx?":            "service:nginx:",
		"service nginx&redis":       "service:nginx:redis",
		"service nginx%redis":       "service:nginx:redis",
		"service\tnginx%redis":      "servicenginx:redis",
		"service\nnginx%redis":      "servicenginx:redis",
		"servi\x08ce nginx&redis":   "service:nginx:redis",
		"servi\xffce/nginx&redis:5": "service:nginx:redis:5",
		"serv\x69ce/nginx&redis:5":  "service:nginx:redis:5",
		"\xa0":                      "",
	}

	for k, v := range repls {
		out := NormalizeForURL(k)
		if v != out {
			t.Errorf("Error: %v\n", k)
			t.Errorf("  Expect: %v\n", v)
			t.Errorf("  Actual: %v\n", out)
		}
	}
}

func TestIPEnclosure(t *testing.T) {
	cases := [][]string{
		{"192.168.1.0/24", "192.168.1.1", "192.168.1.20", "192.168.1.255"},
		{"192.168.0.0/22", "192.168.1.1", "192.168.2.1"},
		{"192.168.1.0/31", "192.168.1.0", "192.168.1.1"},
		{"192.168.1.0/30", "192.168.1.1", "192.168.1.2"},
		{"192.168.1.2/31", "192.168.1.2", "192.168.1.3"},
		{"192.0.0.0/2", "192.168.1.1", "255.255.255.255"},
		{"192.168.1.1/32", "192.168.1.1", "192.168.1.1"},
		{"10.1.1.2/31", "10.1.1.2", "10.1.1.3"},
		{"0.0.0.0/4", "10.1.1.2", "0.0.0.0"},
		{"0.0.0.0/0", "192.1.1.2", "0.0.0.0"},
	}
	for _, v := range cases {
		ips := make([]net.IP, 0)
		for _, ip := range v[1:] {
			ips = append(ips, net.ParseIP(ip))
		}
		subnet := GetIPEnclosure(ips)
		if subnet.String() != v[0] {
			t.Errorf("Error: %v\n", v[1:])
			t.Errorf("  Expect: %v\n", v[0])
			t.Errorf("  Actual: %v\n", subnet.String())
		}
	}
}

func TestSubnetContains(t *testing.T) {
	type testCase struct {
		n1, n2  string
		contain bool
		compare int
	}
	cases := []testCase{
		{"10.1.0.0/16", "10.1.0.0/24", true, 1},
		{"10.1.1.0/24", "10.1.0.0/24", false, 0},
		{"10.1.1.192/28", "10.1.1.0/24", true, -1},
		{"10.1.1.0/24", "10.1.1.0/24", true, 0},
		{"10.1.2.3/32", "10.1.2.0/25", true, -1},
		{"0.0.0.0/0", "10.1.1.0/24", true, 1},
	}

	for _, c := range cases {
		_, n1, _ := net.ParseCIDR(c.n1)
		_, n2, _ := net.ParseCIDR(c.n2)
		contain, compare := SubnetContains(n1, n2)
		if contain != c.contain || compare != c.compare {
			t.Errorf("Error: n1=%v n2=%v\n", n1.String(), n2.String())
			t.Errorf("  Expect: %v %v\n", c.contain, c.compare)
			t.Errorf("  Actual: %v %v\n", contain, compare)
		}
	}
}

func TestSubnetSet(t *testing.T) {
	subnets := NewSet()
	ipnet1 := net.IPNet{IP: net.ParseIP("1.2.3.4"), Mask: net.CIDRMask(16, 32)}
	ipnet2 := net.IPNet{IP: net.ParseIP("1.2.4.5"), Mask: net.CIDRMask(16, 32)}
	str1 := IPNet2Subnet(&ipnet1).String()
	str2 := IPNet2Subnet(&ipnet2).String()
	subnets.Add(str1)
	subnets.Add(str2)

	if subnets.Cardinality() != 1 {
		t.Errorf("Wrong subnet set size: %v\n", subnets.Cardinality())
	}

	ip := net.ParseIP("1.2.5.6")
	for str := range subnets.Iter() {
		if _, subnet, err := net.ParseCIDR(str.(string)); err != nil {
			t.Errorf("Subnet set error: %v\n", err.Error())
		} else if !subnet.Contains(ip) {
			t.Errorf("Subnet not contain IP: %v %v\n", subnets, ip.String())
		}
	}
}

func TestSubnetLoose(t *testing.T) {
	type testCase struct {
		input  string
		scope  string
		output string
	}
	cases := []testCase{
		{"1.2.3.4/16", share.CLUSIPAddrScopeNAT, "1.2.0.0/16"},
		{"1.2.3.4/24", share.CLUSIPAddrScopeNAT, "1.2.3.0/24"},
		{"1.2.3.4/16", share.CLUSIPAddrScopeGlobal, "1.2.0.0/16"},
		{"1.2.3.4/24", share.CLUSIPAddrScopeGlobal, "1.2.3.0/24"},
		{"1.2.3.4/32", share.CLUSIPAddrScopeGlobal, "1.2.3.0/24"},
	}
	for _, c := range cases {
		_, ipnet, _ := net.ParseCIDR(c.input)
		parsed := IPNet2SubnetLoose(ipnet, c.scope)
		if parsed.String() != c.output {
			t.Errorf("Error: input=%s scope=%s", c.input, c.scope)
			t.Errorf("  Expect: %s\n", c.output)
			t.Errorf("  Actual: %s\n", parsed.String())
		}
	}
}

func TestPlatformEnv(t *testing.T) {
	{
		envs := []string{"NV_PLATFORM_INFO=platform=aliyun;if-eth0=host;if-eth0=global;if-eth1=global"}
		p := NewEnvironParser(envs)

		plt, _ := p.GetPlatformName()
		if plt != "aliyun" {
			t.Errorf("Error: platform=%v env=%+v\n", plt, p.GetPlatformEnv())
		}

		cfgs := p.GetPlatformIntf("eth0")
		if len(cfgs) != 2 || cfgs[0] != "host" || cfgs[1] != "global" {
			t.Errorf("Error: cfgs=%v env=%+v\n", cfgs, p.GetPlatformEnv())
		}
	}

	// test platform and flavor
	{
		envs := []string{"NV_PLATFORM_INFO=platform=kubernetes:gke"}
		p := NewEnvironParser(envs)

		plt, flavor := p.GetPlatformName()
		if plt != "kubernetes" || flavor != "gke" {
			t.Errorf("Error: platform=%v flavor=%v env=%+v\n", plt, flavor, p.GetPlatformEnv())
		}
	}

	{
		envs := []string{"NV_PLATFORM_INFO=platform=kubernetes:"}
		p := NewEnvironParser(envs)

		plt, flavor := p.GetPlatformName()
		if plt != "kubernetes" || flavor != "" {
			t.Errorf("Error: platform=%v flavor=%v env=%+v\n", plt, flavor, p.GetPlatformEnv())
		}
	}

	{
		envs := []string{"NV_PLATFORM_INFO=platform=kubernetes"}
		p := NewEnvironParser(envs)

		plt, flavor := p.GetPlatformName()
		if plt != "kubernetes" || flavor != "" {
			t.Errorf("Error: platform=%v flavor=%v env=%+v\n", plt, flavor, p.GetPlatformEnv())
		}
	}
}

func TestBase64Encrypt(t *testing.T) {
	token := "123456"
	encrypt := EncryptUserToken(token, nil)
	decrypt := DecryptUserToken(encrypt, nil)
	if decrypt != token {
		t.Errorf("Token encrypt error: token=%v decrypt=%v\n", token, decrypt)
	}
}

func TestPasswordEncrypt(t *testing.T) {
	password := "123456"
	encrypt := EncryptPassword(password)
	decrypt := DecryptPassword(encrypt)
	if decrypt != password {
		t.Errorf("Password encrypt error: password=%v decrypt=%v\n", password, decrypt)
	}

	if EncryptPassword("") != "" {
		t.Errorf("Empty password should be encrypted as emtpy string\n")
	}

	e1 := EncryptPassword(password)
	e2 := EncryptPassword(password)
	if e1 == e2 {
		t.Errorf("Encrypt same string twice gives same output\n")
	}

	decrypt = DecryptPassword("1234567890")
	if decrypt != "" {
		t.Errorf("Decrypt invalid string should give empty output\n")
	}
}

func TestCompareSliceWithoutOrder(t *testing.T) {
	a1 := []string{"cpath"}
	a2 := []string{"all"}
	if CompareSliceWithoutOrder(a1, a2) {
		t.Errorf("(%v) and (%v) should not be equal\n", a1, a2)
	}

	a1 = []string{""}
	a2 = []string{"all"}
	if CompareSliceWithoutOrder(a1, a2) {
		t.Errorf("(%v) and (%v) should not be equal\n", a1, a2)
	}

	a1 = []string{"conn", "cpath"}
	a2 = []string{"conn", "cpath"}
	if !CompareSliceWithoutOrder(a1, a2) {
		t.Errorf("(%v) and (%v) should be equal\n", a1, a2)
	}

	a1 = []string{"cpath", "conn"}
	a2 = []string{"conn", "cpath"}
	if !CompareSliceWithoutOrder(a1, a2) {
		t.Errorf("(%v) and (%v) should be equal\n", a1, a2)
	}

}

func TestBytesDisplay(t *testing.T) {
	var num int64 = 356
	if str := DisplayBytes(num); str != "356 Bytes" {
		t.Errorf("(%v) and (%v) is not equal\n", num, str)
	}

	num = 44356
	if str := DisplayBytes(num); str != "43 KB" {
		t.Errorf("(%v) and (%v) is not equal\n", num, str)
	}

	num = 44356000
	if str := DisplayBytes(num); str != "42 MB" {
		t.Errorf("(%v) and (%v) is not equal\n", num, str)
	}

	num = 44356000000
	if str := DisplayBytes(num); str != "41 GB" {
		t.Errorf("(%v) and (%v) is not equal\n", num, str)
	}

	num = 44356000000000
	if str := DisplayBytes(num); str != "40 TB" {
		t.Errorf("(%v) and (%v) is not equal\n", num, str)
	}

	num = 4435600000000000
	if str := DisplayBytes(num); str != "4034 TB" {
		t.Errorf("(%v) and (%v) is not equal\n", num, str)
	}
}
