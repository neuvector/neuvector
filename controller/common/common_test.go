package common

import (
	"os"
	"testing"

	"github.com/neuvector/neuvector/share/utils"
	"github.com/stretchr/testify/assert"
)

func TestDefaultPasswordHelper(t *testing.T) {
	os.Setenv("BOOTSTRAP_PASSWORD", "password")
	assert.True(t, IsBootstrapAdminPass("password"))
	assert.True(t, IsBootstrapAdminPass("admin"))
	assert.False(t, IsBootstrapAdminPass("12345"))
	assert.True(t, IsBootstrapAdminPassHash(utils.HashPassword("password")))
	assert.True(t, IsBootstrapAdminPassHash(utils.HashPassword("admin")))
	assert.False(t, IsBootstrapAdminPassHash(utils.HashPassword("12345")))

	os.Unsetenv("BOOTSTRAP_PASSWORD")
	assert.False(t, IsBootstrapAdminPass("password"))
	assert.True(t, IsBootstrapAdminPass("admin"))
	assert.False(t, IsBootstrapAdminPass("12345"))
	assert.False(t, IsBootstrapAdminPassHash(utils.HashPassword("password")))
	assert.True(t, IsBootstrapAdminPassHash(utils.HashPassword("admin")))
	assert.False(t, IsBootstrapAdminPassHash(utils.HashPassword("12345")))

	os.Setenv("BOOTSTRAP_PASSWORD", "")
	assert.False(t, IsBootstrapAdminPass("password"))
	assert.True(t, IsBootstrapAdminPass("admin"))
	assert.False(t, IsBootstrapAdminPass("12345"))
	assert.False(t, IsBootstrapAdminPassHash(utils.HashPassword("password")))
	assert.True(t, IsBootstrapAdminPassHash(utils.HashPassword("admin")))
	assert.False(t, IsBootstrapAdminPassHash(utils.HashPassword("12345")))
}
