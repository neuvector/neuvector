// [20220809] this is a simplified version of controller/resource/types.go
package resource

import (
	"errors"
)

var ErrMethodNotSupported = errors.New("Method not supported")
var ErrResourceNotSupported = errors.New("Method on resource not supported")

const (
	RscTypeImage = "image"
)
