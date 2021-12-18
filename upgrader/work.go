package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

func getAddrList(address string) ([]string, error) {
	addrs, _ := utils.ResolveAddrList(address, false)
	var retry uint = 0
	for len(addrs) == 0 {
		if retry < 5 {
			time.Sleep(time.Second * (1 << retry))
		} else if retry < 10 {
			time.Sleep(time.Second * 30)
		} else {
			return nil, errors.New("Failed to resolve address")
		}
		retry++
		log.WithFields(log.Fields{"addr": address, "retry": retry}).Info("resolve")
		addrs, _ = utils.ResolveAddrList(address, false)
	}
	log.WithFields(log.Fields{"addr": address, "ip": addrs}).Info("")
	return addrs, nil
}

func createControllerUpgradeServiceWrapper(conn *grpc.ClientConn) cluster.Service {
	return share.NewControllerUpgradeServiceClient(conn)
}

func createControllerClient(id string, ip string, port uint16) {
	endpoint := fmt.Sprintf("%s:%v", ip, port)
	cluster.CreateGRPCClient(id, endpoint, false, createControllerUpgradeServiceWrapper)
}

func deleteControllerClient(id string) {
	cluster.DeleteGRPCClient(id)
}

func getControllerClient(id string) (share.ControllerUpgradeServiceClient, error) {
	c, err := cluster.GetGRPCClient(id, cluster.IsControllerGRPCCommpressed, nil)
	if err == nil {
		return c.(share.ControllerUpgradeServiceClient), nil
	} else {
		log.WithFields(log.Fields{"error": err}).Error("Failed to connect to grpc server")
		return nil, err
	}
}

const defaultReqTimeout = time.Second * 30
const packetSize int = 2 * 1024 * 1024

func upgrade(ctrlAddress string, port uint16, done chan bool, dbFile string) {
	log.WithFields(log.Fields{"ctrl": ctrlAddress, "port": port}).Info("")
	if port == 0 {
		port = cluster.DefaultControllerGRPCPort
	}

	// Intentionally introduce some delay so scanner IP can be populated to all enforcers
	log.Info("Wait 15s ...")
	time.Sleep(time.Second * 15)

	addr, err := getAddrList(ctrlAddress)
	if err != nil {
		log.WithFields(log.Fields{"addr": ctrlAddress, "error": err}).Error()
		return
	}

	for _, ip := range addr {
		createControllerClient(ip, ip, port)

		client, err := getControllerClient(ip)
		if err != nil {
			log.WithFields(log.Fields{"ip": ip, "error": err}).Error("Failed to connect")
			continue
		}

		ctx, cancel := context.WithTimeout(context.Background(), defaultReqTimeout)
		defer cancel()

		// Post 4.0 controller has no internal DB, no upgrade
		cap, err := client.SupportUpgradeDB(ctx, &share.RPCVoid{})
		if err == nil && cap != nil && !cap.Value {
			log.WithFields(log.Fields{"ip": ip}).Info("Database upgrade is not supported")
			continue
		}

		// Decide compact or regular database
		var uploadFile string
		if dbFile != "" {
			uploadFile = dbFile
		} else {
			cap, err := client.SupportRegularDB(ctx, &share.RPCVoid{})
			if err != nil || cap == nil || !cap.Value {
				uploadFile = fmt.Sprintf("%s%s", share.CVEDatabaseFolder, share.CompactCVEDBName)
			} else {
				uploadFile = fmt.Sprintf("%s%s", share.CVEDatabaseFolder, share.RegularCVEDBName)
			}
		}

		stream, err := client.UpgradeScannerDB(ctx)
		if err != nil {
			log.WithFields(log.Fields{"ip": ip, "error": err}).Error("Failed to get stream")
			continue
		}

		var fp *os.File
		if fp, err = os.Open(uploadFile); err != nil {
			log.WithFields(log.Fields{"database": uploadFile, "error": err}).Error("Fail to open file!")
			break
		}

		buf := make([]byte, packetSize)
		for {
			var n int
			n, err = fp.Read(buf)
			if n > 0 {
				packet := &share.CLUSFilePacket{
					Name: "cvedb",
					Len:  uint32(n),
					Data: buf[:n],
				}
				err = stream.Send(packet)
				if err == io.EOF {
					log.WithFields(log.Fields{"ip": ip}).Info("Database update API is not supported")
					break
				} else if err != nil {
					log.WithFields(log.Fields{"ip": ip, "error": err}).Error("Failed to send")
					break
				}
			} else if err == io.EOF {
				if _, err = stream.CloseAndRecv(); err != nil {
					log.WithFields(log.Fields{"ip": ip, "error": err}).Error("Failed to close")
				}
				break
			} else {
				log.WithFields(log.Fields{"database": uploadFile, "error": err}).Error("Fail to read file!")
				break
			}
		}
		fp.Close()
		if err == nil {
			log.WithFields(log.Fields{"ip": ip, "database": uploadFile}).Info("Upgrade succeeded!")
		}
	}

	for _, ip := range addr {
		deleteControllerClient(ip)
	}
}
