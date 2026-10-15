package cluster

import (
	"math"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGrpcMaxMsgSizeFromEnv(t *testing.T) {
	cases := []struct {
		name  string
		set   bool
		value string
		want  int
	}{
		{name: "unset uses default", set: false, want: defaultGRPCMaxMsgSize},
		{name: "empty uses default", set: true, value: "", want: defaultGRPCMaxMsgSize},
		{name: "invalid uses default", set: true, value: "abc", want: defaultGRPCMaxMsgSize},
		{name: "zero clamped to default", set: true, value: "0", want: defaultGRPCMaxMsgSize},
		{name: "negative clamped to default", set: true, value: "-5", want: defaultGRPCMaxMsgSize},
		{name: "below default clamped up", set: true, value: "16", want: defaultGRPCMaxMsgSize},
		{name: "former cap below default clamped up", set: true, value: "32", want: defaultGRPCMaxMsgSize},
		{name: "equal to default", set: true, value: "64", want: defaultGRPCMaxMsgSize},
		{name: "valid override", set: true, value: "128", want: 128 * 1024 * 1024},
		{name: "ceiling boundary last multiply", set: true, value: "2047", want: 2047 * 1024 * 1024},
		{name: "ceiling boundary first clamp", set: true, value: "2048", want: math.MaxInt32},
		{name: "huge clamped to ceiling", set: true, value: strconv.Itoa(math.MaxInt32), want: math.MaxInt32},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.set {
				t.Setenv(EnvGRPCMaxMsgSizeMB, c.value)
			} else {
				// t.Setenv registers restoration of the prior value on cleanup;
				// unset it afterwards so this subtest sees a truly absent var.
				t.Setenv(EnvGRPCMaxMsgSizeMB, "")
				err := os.Unsetenv(EnvGRPCMaxMsgSizeMB)
				assert.NoError(t, err)
			}
			assert.Equal(t, c.want, grpcMaxMsgSizeFromEnv())
		})
	}
}
