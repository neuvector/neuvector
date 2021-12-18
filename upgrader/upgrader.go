package main

import (
	"flag"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/utils"
)

const Version = "0.1"

func main() {
	var ctrlAddr string

	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&utils.LogFormatter{Module: "UPG"})

	log.WithFields(log.Fields{"version": Version}).Info("START")

	debug := flag.Bool("d", false, "Enable debug")
	ctrl := flag.String("c", "", "Controller address")
	grpcPort := flag.Uint("p", 0, "Controller GRPC port")
	dbFile := flag.String("f", "", "The updated db file")
	flag.Parse()

	if *debug || os.Getenv("CTRL_PATH_DEBUG") != "" {
		log.SetLevel(log.DebugLevel)
	}

	if *ctrl != "" {
		ctrlAddr = *ctrl
	} else {
		ctrlAddr = os.Getenv("CLUSTER_JOIN_ADDR")
		if ctrlAddr == "" {
			ctrlAddr = "127.0.0.1"
		}
	}

	if *grpcPort == 0 {
		port := os.Getenv("CTRL_GRPC_PORT")
		if port != "" {
			if p, err := strconv.ParseUint(port, 10, 32); err == nil {
				*grpcPort = uint(p)
			}
		}
	}

	done := make(chan bool, 1)
	c_sig := make(chan os.Signal, 1)
	signal.Notify(c_sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		upgrade(ctrlAddr, uint16(*grpcPort), done, *dbFile)
		done <- true
	}()

	go func() {
		<-c_sig
		done <- true
	}()

	var rc int
	select {
	case <-done:
		rc = 0
	}

	log.Info("Exiting ...")
	os.Exit(rc)
}
