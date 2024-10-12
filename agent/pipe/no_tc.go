package pipe

import (
	"net"
)

type notcPipeDriver struct {
}

var notcPipe notcPipeDriver = notcPipeDriver{}

func (d *notcPipeDriver) AttachPortPair(pair *InterceptPair) (net.HardwareAddr, net.HardwareAddr) {
	// 4e:65:75:56 - NeuV
	ucmac, _ := net.ParseMAC("4e:65:75:56:00:00")
	bcmac, _ := net.ParseMAC("ff:ff:ff:00:00:00")
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
