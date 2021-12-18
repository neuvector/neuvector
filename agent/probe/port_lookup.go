package probe

// #include "../../defs.h"
import "C"

import (
	"strings"
	"time"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/osutil"
	"github.com/neuvector/neuvector/share/utils"
)

const (
	langBin = 1 << iota
	langJava
	langErlang
)

type appType struct {
	id    uint32
	isApp bool
}
type javaAppType struct {
	name  string
	id    uint32
	isApp bool
}

var binAppMap map[string]appType = map[string]appType{
	"mysqld":            {C.DPI_APP_MYSQL, true},
	"redis-server":      {C.DPI_APP_REDIS, true},
	"mongod":            {C.DPI_APP_MONGODB, true},
	"postgres":          {C.DPI_APP_POSTGRESQL, true},
	"radiusd":           {C.DPI_APP_RADIUS, true},
	"consul":            {C.DPI_APP_CONSUL, true},
	"etcd":              {C.DPI_APP_ETCD, true},
	"node":              {C.DPI_APP_NODEJS, false},
	"nginx":             {C.DPI_APP_NGINX, false},
	"apache2":           {C.DPI_APP_APACHE, false},
	"saslauthd-port":    {C.DPI_APP_COUCHBASE, true},
	"memcached":         {C.DPI_APP_COUCHBASE, true},
	"godu":              {C.DPI_APP_COUCHBASE, true},
	"goxdcr":            {C.DPI_APP_COUCHBASE, true},
	"goport":            {C.DPI_APP_COUCHBASE, true},
	"indexer":           {C.DPI_APP_COUCHBASE, true},
	"moxi":              {C.DPI_APP_COUCHBASE, true},
	"cbq-engine":        {C.DPI_APP_COUCHBASE, true},
	"projector":         {C.DPI_APP_COUCHBASE, true},
	"couchdb":           {C.DPI_APP_COUCHDB, true},
	"couchjs":           {C.DPI_APP_COUCHDB, true},
	"tini":              {C.DPI_APP_COUCHDB, true},
	"gosu":              {C.DPI_APP_COUCHDB, true},
	"rabbitmq-server":   {C.DPI_APP_RABBITMQ, true},
	"rabbitmqctl":       {C.DPI_APP_RABBITMQ, true},
	"rabbitmq-plugins":  {C.DPI_APP_RABBITMQ, true},
	"rabbitmq-env":      {C.DPI_APP_RABBITMQ, true},
	"rabbitmq-defaults": {C.DPI_APP_RABBITMQ, true},
}

var javaAppMap []javaAppType = []javaAppType{
	{"spark", C.DPI_APP_SPARK, true},
	{"cassandra", C.DPI_APP_CASSANDRA, true},
	{"voltdb", C.DPI_APP_VOLTDB, true},
	{"kafka", C.DPI_APP_KAFKA, true},
	{"activemq", C.DPI_APP_ACTIVEMQ, true},
	{"Elasticsearch", C.DPI_APP_ELASTICSEARCH, false},
	{"zookeeper", C.DPI_APP_ZOOKEEPER, true},
}

var erlangAppMap map[string]appType = map[string]appType{
	"couchbase": {C.DPI_APP_COUCHBASE, true},
	"couchdb":   {C.DPI_APP_COUCHDB, true},
	"rabbitmq":  {C.DPI_APP_RABBITMQ, true},
}

type procApp struct {
	Pids            utils.Set
	App             share.CLUSApp
	AddConfirmed    bool
	DelConfirmed    bool
	SessionInitTime time.Time
}

func getJavaClass(cmdline []string) []string {
	var classes []string // all possible matches from the command line
	bSkipNextToken := false
	length := len(cmdline)
	for i := 1; i < length; i++ {
		//get the java main class, java [ options ] class [ arguments ]
		//or java [ options ] -jar file.jar [ arguments ]
		//exclude -cp class_path
		// log.WithFields(log.Fields{"cmdline": cmdline[i], "i": i}).Debug()
		if bSkipNextToken {
			bSkipNextToken = false
			continue
		}

		if strings.HasPrefix(cmdline[i], "--") { // escape parameter, it follows with a space, then a parameter
			bSkipNextToken = true
			continue
		}

		if strings.HasPrefix(cmdline[i], "%") { // like %p, part of previous parameter, ignored
			continue
		}

		if !strings.HasPrefix(cmdline[i], "-") {
			classes = append(classes, cmdline[i])
		} else if (cmdline[i] == "-jar" || cmdline[i] == "-cp" || cmdline[i] == "-classpath") && ((i + 1) < length) {
			classes = append(classes, cmdline[i+1])
			bSkipNextToken = true
		}
	}

	return classes
}

func lookupAppMap(cmdName string, cmdline []string) (uint32, bool) {
	if len(cmdline) == 0 {
		return 0, false
	}

	if cmdName == "java" {
		if javaClasses := getJavaClass(cmdline); len(javaClasses) > 0 {
			for _, class := range javaClasses {
				// log.WithFields(log.Fields{"javaClass": class}).Debug()
				for _, app := range javaAppMap {
					if strings.Contains(class, app.name) {
						return app.id, app.isApp
					}
				}
			}
		}
		return 0, false
	} else if cmdName == "beam.smp" || cmdName == "beam" {
		//erlang daemon
		for _, c := range cmdline {
			for name, app := range erlangAppMap {
				if len(c) > 1 && c[0] != '-' && strings.Contains(c, name) {
					return app.id, app.isApp
				}
			}
		}
		return 0, false
	} else if cmdName == "epmd" {
		return C.DPI_APP_ERLANG_EPMD, false
	}

	//lookup the binary app map
	if app, found := binAppMap[cmdName]; found {
		return app.id, app.isApp
	}
	return 0, false
}

func getAppMap(portsMap map[osutil.SocketInfo]*procApp) {
	var conServer uint32
	var erlangPort osutil.SocketInfo
	for port, papp := range portsMap {
		if papp.Pids.Cardinality() == 0 {
			continue
		}

		pid := papp.Pids.Any().(int)
		ppid, _, _, _, cmdName := osutil.GetProcessPIDs(pid)
		if ppid == -1 {
			continue
		}

		cmds, err := global.SYS.ReadCmdLine(pid)
		if err != nil {
			continue
		}

		// log.WithFields(log.Fields{"pids": papp.Pids, "name": cmdName}).Debug()
		if server, isApp := lookupAppMap(cmdName, cmds); server != 0 {
			papp.App.CLUSProtoPort = share.CLUSProtoPort{IPProto: port.IPProto, Port: port.Port}
			papp.App.Server = server
			if isApp {
				papp.App.Application = server
			}
			if server == C.DPI_APP_ERLANG_EPMD {
				erlangPort = port
			}
			if server != C.DPI_APP_ERLANG_EPMD {
				conServer = server
			}
		} else {
			papp.App.CLUSProtoPort = share.CLUSProtoPort{IPProto: port.IPProto, Port: port.Port}
		}
	}

	//the erlang port mapper is an independent program, like dns, it is used in couchbase/rabbitmq/couchdb, etc.
	//we can not identify which application it belong to only in cmdline lookup,
	//so we need to find out the application after the whole container identified
	if erlangPort.Port != 0 {
		if conServer != 0 {
			// update epmd server since they have diffferent inodes but shared the same tcp/port
			for port, papp := range portsMap {
				if port.Port == erlangPort.Port && port.IPProto == erlangPort.IPProto {
					papp.App.Server = conServer
					papp.App.Application = conServer
				}
			}
		} else {
			for _, a := range portsMap {
				if a.App.Server != 0 && a.App.Server != C.DPI_APP_ERLANG_EPMD {
					portsMap[erlangPort].App.Server = a.App.Server
					portsMap[erlangPort].App.Application = a.App.Server
					break
				}
			}
		}
	}
}
