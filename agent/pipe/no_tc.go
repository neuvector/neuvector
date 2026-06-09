package pipe

import (
	"net"
)

type notcPipeDriver struct {
}

var notcPipe notcPipeDriver = notcPipeDriver{}

func (d *notcPipeDriver) AttachPortPair(pair *InterceptPair) (net.HardwareAddr, net.HardwareAddr) {
	// 4e:65:75:56 - NeuV
	ucmac := net.HardwareAddr{0x4e, 0x65, 0x75, 0x56, 0x00, 0x00}
	bcmac := net.HardwareAddr{0xff, 0xff, 0xff, 0x00, 0x00, 0x00}
	return ucmac, bcmac
}

func (d *notcPipeDriver) DetachPortPair(pair *InterceptPair) {
}

func (d *notcPipeDriver) ResetPortPair(pid int, pair *InterceptPair) {

}

func (d *notcPipeDriver) TapPortPair(pid int, pair *InterceptPair) {

}

func (d *notcPipeDriver) FwdPortPair(pid int, pair *InterceptPair) {

}

func (d *notcPipeDriver) GetPortPairRules(pair *InterceptPair) (string, string, string) {
	return "NO_TC", "NO_TC", "NO_TC"
}

func (d *notcPipeDriver) Connect(jumboframe bool) {

}

func (d *notcPipeDriver) Cleanup() {

}
