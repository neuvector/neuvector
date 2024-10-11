package pipe

import (
	"net"
)

type clmPipeDriver struct {
}

var clmPipe clmPipeDriver = clmPipeDriver{}

func (d *clmPipeDriver) AttachPortPair(pair *InterceptPair) (net.HardwareAddr, net.HardwareAddr) {
	// 4e:65:75:56 - NeuV
	ucmac, _ := net.ParseMAC("4e:65:75:56:00:00")
	bcmac, _ := net.ParseMAC("ff:ff:ff:00:00:00")
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
