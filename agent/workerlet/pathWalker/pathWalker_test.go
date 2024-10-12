package main

/*
//// Use tests locally by replacing the first character of function name, "t", with "T"

// // need to "sudo -i" is required to run these testssudo -i
const workPath = "/tmp/walk/test"
const rootPid = 61762 //  INPUT the root PID and container ID for a running container
const cid = "2d57dbe19bebd146928242e479f2e5a6c8cca99fd2d15545448d1c41e1868669"

// -- Logger
// LogFormatter emulates the form of the traditional built-in logger.
type logFormatter struct {
	Module string
}

func (f *logFormatter) Format(entry *log.Entry) ([]byte, error) {
	b := &bytes.Buffer{}
	fmt.Fprintf(b, "%-10s|%s|", entry.Time.Format("04:05.999"), strings.ToUpper(entry.Level.String())[0:4])
	if len(entry.Message) > 0 {
		fmt.Fprintf(b, "%s", entry.Message)
	}

	fmt.Fprintf(b, " - ")
	for key, value := range entry.Data {
		b.WriteString(key)
		b.WriteByte('=')
		fmt.Fprintf(b, "%+v ", value)
	}
	b.WriteByte('\n')
	return b.Bytes(), nil
}

func initEnv() *taskMain {
	os.RemoveAll(workPath)
	if dbgError := os.MkdirAll(workPath, 0755); dbgError != nil {
	log.WithFields(log.Fields{"dbgError": dbgError}).Debug()
}

	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel) // change it later: log.InfoLevel
	log.SetFormatter(&logFormatter{Module: "WLK"})

	// acquire tool
	sys := system.NewSystemTools()
	done := make(chan error, 1)
	return InitTaskMain(workPath, done, sys)
}

func testWalkPathExecOnly(t *testing.T) {
	fmt.Printf("TestWalkPathExecOnly: Start ...\n")
	tm := initEnv()
	req := workerlet.WalkPathRequest{
		Pid:      rootPid,
		Path:     "",
		ExecOnly: true,
	}

	go tm.WalkPathTask(req)
	err := <-tm.done
	if err != nil {
		t.Errorf("")
	}
	fmt.Printf("TestWalkPathExecOnly: Done\n\n")
}

func testWalkPath_bin(t *testing.T) {
	fmt.Printf("TestWalkPath_bin: Start ...\n")
	tm := initEnv()
	req := workerlet.WalkPathRequest{
		Pid:      rootPid,
		Path:     "bin",
		ExecOnly: false,
	}

	go tm.WalkPathTask(req)
	err := <-tm.done
	if err != nil {
		t.Errorf("")
	}
	fmt.Printf("TestWalkPath_bin: Done\n\n")
}

func testWalkPakcages(t *testing.T) {
	fmt.Printf("TestWalkPakcages: Start ...\n")
	tm := initEnv()
	req := workerlet.WalkGetPackageRequest{
		Pid:     rootPid,
		Id:      cid,
		ObjType: share.ScanObjectType_CONTAINER,
	}

	go tm.WalkPackageTask(req)
	err := <-tm.done
	if err != nil {
		t.Errorf("")
	}
	fmt.Printf("testWalkPakcages: Done\n\n")
}

func testWalkSecrets(t *testing.T) {
	fmt.Printf("TestWalkSecrets: Start ...\n")
	tm := initEnv()
	req := workerlet.WalkSecretRequest{
		Pid:         rootPid,
		MaxFileSize: 0,
		MiniWeight:  0.1,
		TimeoutSec:  3 * 60,
	}

	go tm.ScanSecretTask(req)
	err := <-tm.done
	if err != nil {
		t.Errorf("")
	}
	fmt.Printf("TestWalkSecrets: Done\n\n")
}
*/
