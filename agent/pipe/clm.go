package pipe

import (
	"net"
)

type clmPipeDriver struct {
}

var clmPipe clmPipeDriver = clmPipeDriver{}

func (d *clmPipeDriver) AttachPortPair(pair *InterceptPair) (net.HardwareAddr, net.HardwareAddr) {
	// 4e:65:75:56 - NeuV
	ucmac := net.HardwareAddr{0x4e, 0x65, 0x75, 0x56, 0x00, 0x00}
	bcmac := net.HardwareAddr{0xff, 0xff, 0xff, 0x00, 0x00, 0x00}
	return ucmac, bcmac
}

func (d *clmPipeDriver) DetachPortPair(pair *InterceptPair) {
}

func (d *clmPipeDriver) ResetPortPair(pid int, pair *InterceptPair) {

}

func (d *clmPipeDriver) TapPortPair(pid int, pair *InterceptPair) {

}

func (d *clmPipeDriver) FwdPortPair(pid int, pair *InterceptPair) {

}

func (d *clmPipeDriver) GetPortPairRules(pair *InterceptPair) (string, string, string) {
	return "", "", ""
}

func (d *clmPipeDriver) Connect(jumboframe bool) {

}

func (d *clmPipeDriver) Cleanup() {

}
