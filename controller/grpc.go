package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codeskyblue/go-sh"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/neuvector/neuvector/controller/access"
	"github.com/neuvector/neuvector/controller/api"
	"github.com/neuvector/neuvector/controller/cache"
	"github.com/neuvector/neuvector/controller/kv"
	"github.com/neuvector/neuvector/controller/rest"
	"github.com/neuvector/neuvector/controller/rpc"
	"github.com/neuvector/neuvector/controller/scan"
	nvdb "github.com/neuvector/neuvector/db"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/httpclient"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/system"
	"github.com/neuvector/neuvector/share/utils"
)

// const scanImageDataTimeout = time.Second * 45
const repoScanTimeout = time.Minute * 20
const (
	defaultCVEDBPageSize = 5000 // CVE entries per page request to the scanner
	dbSlotsBase          = 256
	dbSlotsMax           = 512
)

var cvedbSlotSizeMax = 400 * 1024 // pre-compression JSON byte threshold per Consul slot

type ScanService struct {
}

// incrementalDBWriter writes CVE entries to Consul KV slots as they arrive, flushing when
// the accumulated pre-compression JSON size would exceed cvedbSlotSizeMax.
type incrementalDBWriter struct {
	store       string
	baseSize    int // JSON size of an empty CLUSScannerDB (version + createTime overhead)
	currentSize int // accumulated JSON size of buffered entries in the current slot
	db          share.CLUSScannerDB
	handled     map[string]bool
	batch       int
	Total       int                     // total unique CVE entries written (including colon-prefix expansions)
	writeFunc   func(int, []byte) error // abstracted slot write; injected for testability
}

func newIncrementalDBWriter(version, createTime, store string, writeFunc func(int, []byte) error) *incrementalDBWriter {
	db := share.CLUSScannerDB{
		CVEDBVersion:    version,
		CVEDBCreateTime: createTime,
		CVEDB:           make(map[string]*share.ScanVulnerability),
	}
	base, _ := json.Marshal(db)
	return &incrementalDBWriter{
		store:       store,
		baseSize:    len(base),
		currentSize: len(base),
		writeFunc:   writeFunc,
		db:          db,
		handled:     make(map[string]bool),
	}
}

// expandCVEEntry inserts cve into dest under key name.  When name contains a colon (e.g.
// "ubuntu:CVE-2021-1234") a second entry is inserted under the bare suffix ("CVE-2021-1234")
// with only the NVD-level metadata copied, so that OS-neutral lookups still work.
// This is the single authoritative implementation of the expansion logic; both preprocessDB
// and incrementalDBWriter.Add delegate here.
func expandCVEEntry(dest map[string]*share.ScanVulnerability, name string, cve *share.ScanVulnerability) {
	if _, after, found := strings.Cut(name, ":"); found {
		dest[after] = &share.ScanVulnerability{
			Name:             after,
			Description:      cve.Description,
			Link:             cve.Link,
			Score:            cve.Score,
			Vectors:          cve.Vectors,
			ScoreV3:          cve.ScoreV3,
			VectorsV3:        cve.VectorsV3,
			PublishedDate:    cve.PublishedDate,
			LastModifiedDate: cve.LastModifiedDate,
		}
	}
	dest[name] = cve
}

// Add processes one CVE entry, expanding colon-prefixed names into two entries (with and without
// the prefix) via expandCVEEntry, then streams them to the incremental writer.
func (w *incrementalDBWriter) Add(name string, cve *share.ScanVulnerability) error {
	expanded := make(map[string]*share.ScanVulnerability, 2)
	expandCVEEntry(expanded, name, cve)
	for k, v := range expanded {
		if err := w.addOne(k, v); err != nil {
			return err
		}
	}
	return nil
}

// cveEntryJSONSize returns the byte length of one map entry "name":<json_value>, in the CVEDB JSON object.
func cveEntryJSONSize(name string, cve *share.ScanVulnerability) (int, error) {
	b, err := json.Marshal(cve)
	if err != nil {
		return 0, err
	}
	// "name":<value>, — 2 quotes around name + 1 colon + value + 1 comma
	return len(name) + 4 + len(b), nil
}

// exceedsSlotSize reports whether adding delta bytes to the current slot would exceed the threshold.
// An empty slot is never considered over the limit to prevent infinite flush loops on oversized entries.
func (w *incrementalDBWriter) exceedsSlotSize(delta int) bool {
	return len(w.db.CVEDB) > 0 && w.currentSize+delta > cvedbSlotSizeMax
}

func (w *incrementalDBWriter) addOne(name string, cve *share.ScanVulnerability) error {
	if w.handled[name] {
		return nil
	}
	delta, err := cveEntryJSONSize(name, cve)
	if err != nil {
		return fmt.Errorf("failed to estimate size for %s: %w", name, err)
	}
	if w.exceedsSlotSize(delta) {
		if err := w.flush(); err != nil {
			return err
		}
	}
	w.handled[name] = true
	w.db.CVEDB[name] = cve
	w.currentSize += delta
	w.Total++
	return nil
}

func (w *incrementalDBWriter) flush() error {
	value, err := json.Marshal(w.db)
	if err != nil {
		return fmt.Errorf("failed to marshal db slot %d: %w", w.batch, err)
	}
	zb := utils.GzipBytes(value)
	log.WithFields(log.Fields{"slot": w.batch, "before": len(value), "after": len(zb), "cveNum": len(w.db.CVEDB)}).Debug()
	if len(zb) >= cluster.KVValueSizeMax {
		return errors.New("database slot is too large")
	}
	if err := w.writeFunc(w.batch, zb); err != nil {
		return fmt.Errorf("failed to write slot %d (size %d): %w", w.batch, len(zb), err)
	}
	w.db.CVEDB = make(map[string]*share.ScanVulnerability)
	w.currentSize = w.baseSize
	w.batch++
	return nil
}

// Flush writes any remaining buffered entries to Consul. Must be called after all Add calls.
func (w *incrementalDBWriter) Flush() error {
	if len(w.db.CVEDB) > 0 {
		return w.flush()
	}
	return nil
}

// deleteStoreKeys removes all Consul KV keys under the given store prefix.
// It is the shared implementation for both incrementalDBWriter.Cleanup and
// ScanService.registerFailureCleanup.
func deleteStoreKeys(store string) {
	keys, err := cluster.GetStoreKeys(store)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("Failed to get store keys for cleanup")
		return
	}
	for _, key := range keys {
		if err := cluster.Delete(key); err != nil {
			log.WithFields(log.Fields{"error": err}).Warn("failed to cleanup")
		}
	}
}

// Cleanup removes all Consul slots written so far. Called on error to roll back partial writes.
func (w *incrementalDBWriter) Cleanup() {
	deleteStoreKeys(w.store)
}

// getCVEDBPageSize returns the effective number of CVE entries per page request to the scanner,
// reading the CVEDB_PAGE_SIZE environment variable if set and valid.
func getCVEDBPageSize() uint32 {
	if s := os.Getenv("CVEDB_PAGE_SIZE"); s != "" {
		if v, err := strconv.ParseUint(s, 10, 32); err != nil || v == 0 {
			log.WithError(err).WithField("env", s).Warn("invalid CVEDB_PAGE_SIZE, using default")
		} else {
			log.WithField("env", s).Info("CVEDB_PAGE_SIZE is overridden")
			return uint32(v)
		}
	}
	return defaultCVEDBPageSize
}

// Previously, to minimize data size, only the basic info is returned by scanner and saved in the kv store.
// This is problematic, because if a cve of an OS is gone, previously scanned result will be missing metadata.
// So, we build a meta data map with the CVE name as key. These data are from NVD anyway.
func (ss *ScanService) preprocessDB(data *share.ScannerRegisterData) map[string]*share.ScanVulnerability {
	cvedb := make(map[string]*share.ScanVulnerability, len(data.CVEDB)*2)
	for name, cve := range data.CVEDB {
		expandCVEEntry(cvedb, name, cve)
	}
	return cvedb
}

func (ss *ScanService) prepareDBSlots(data *share.ScannerRegisterData, cvedb map[string]*share.ScanVulnerability) ([][]byte, error) {
	// Splits the compressed CVE database into multiple slots to fit within the key-value store's size limitations (512KB).
	// Using 128 slots as the base was found to be insufficient, so 256 is now used as the starting base (dbSlotsBase).
	// The function attempts to double the number of slots with each iteration (up to dbSlotsMax) to ensure that
	// the size of each slot stays within the permissible limit.
	for slots := dbSlotsBase; slots <= dbSlotsMax; slots *= 2 {
		log.WithFields(log.Fields{"slots": slots}).Debug()

		enlarge := false
		dbs := make([]*share.CLUSScannerDB, slots)
		zbs := make([][]byte, slots)
		for i := range dbs {
			dbs[i] = &share.CLUSScannerDB{
				CVEDBVersion:    data.CVEDBVersion,
				CVEDBCreateTime: data.CVEDBCreateTime,
				CVEDB:           make(map[string]*share.ScanVulnerability),
			}
		}

		// hash db to slots
		for name, cve := range cvedb {
			cve.Name = name // fix the record
			i := utils.HashStringToInt32(cve.Name, slots)
			dbs[i].CVEDB[cve.Name] = cve
		}

		for i, db := range dbs {
			value, err := json.Marshal(db)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal db slot %d: %w", i, err)
			}
			zb := utils.GzipBytes(value)
			log.WithFields(log.Fields{"slot": i, "size": len(zb)}).Debug()
			if len(zb) >= cluster.KVValueSizeMax {
				enlarge = true
				break
			}
			zbs[i] = zb
		}

		if !enlarge {
			return zbs, nil
		}
	}

	return nil, errors.New("Database is too large")
}

func (ss *ScanService) registerFailureCleanup(newDBStore string) {
	deleteStoreKeys(newDBStore)
}

// finalizeDBCommit writes the CVE database version marker and scanner record to the cluster KV
// store. It assumes that all Consul DB slots have already been written to newStore by the caller
// (e.g. incrementalDBWriter). Old DB stores are removed after the commit.
func (ss *ScanService) finalizeDBCommit(data *share.ScannerRegisterData, newStore string, totalEntries int) error {
	newScanner := share.CLUSScanner{
		ID:                           data.ID,
		CVEDBVersion:                 data.CVEDBVersion,
		CVEDBCreateTime:              data.CVEDBCreateTime,
		JoinedAt:                     time.Now().UTC(),
		RPCServer:                    data.RPCServer,
		RPCServerPort:                uint16(data.RPCServerPort),
		BuiltIn:                      data.RPCServer == "127.0.0.1",
		CVEDBEntries:                 totalEntries,
		MaxConcurrentScansPerScanner: rpc.ScannerAcquisitionMgr.GetMaxConcurrentScansPerScanner(),
		ScanCredit:                   rpc.ScannerAcquisitionMgr.GetMaxConcurrentScansPerScanner(),
	}
	if newScanner.BuiltIn {
		newScanner.ID = Ctrler.ID
	}

	clusHelper := kv.GetClusterHelper()
	lock, err := clusHelper.AcquireLock(share.CLUSLockScannerKey, time.Second*20)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
		return err
	}
	defer clusHelper.ReleaseLock(lock)

	// Snapshot existing store directories before committing; these are the old version stores to
	// clean up after the transaction. Fetched now so the new store is excluded automatically
	// (it was already written before this call).
	oldStores, err := cluster.GetStoreKeys(share.CLUSScannerDBStore)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("Failed to get old scanner DB stores")
	}

	txn := cluster.Transact()
	defer txn.Close()

	dbVerScanner := share.CLUSScanner{
		ID:              share.CLUSScannerDBVersionID,
		CVEDBVersion:    data.CVEDBVersion,
		CVEDBCreateTime: data.CVEDBCreateTime,
		CVEDBEntries:    totalEntries,
	}
	if err := clusHelper.PutScannerTxn(txn, &dbVerScanner); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("PutScannerTxn")
		return err
	}
	if err := clusHelper.PutScannerTxn(txn, &newScanner); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("PutScannerTxn")
		return err
	}
	if ok, err := txn.Apply(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to write scanner to the cluster")
		return err
	} else if !ok {
		return errors.New("Atomic write failed")
	}

	log.WithFields(log.Fields{"cvedb": newStore, "entries": totalEntries}).Info("CVE database written")

	if len(oldStores) > 0 {
		txn.Reset()
		for _, store := range oldStores {
			if !strings.HasPrefix(store, newStore) {
				txn.DeleteTree(store)
			}
		}
		if _, err := txn.Apply(); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("txn.Apply")
		}
	}

	if err := clusHelper.CreateScannerStats(newScanner.ID); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("CreateScannerStats")
	}
	return nil
}

func (ss *ScanService) ScannerRegisterStream(stream share.ControllerScanService_ScannerRegisterStreamServer) error {
	clusHelper := kv.GetClusterHelper()
	lock, err := acquireCVEDBUploadLock(clusHelper)
	if err != nil {
		return err
	}
	defer clusHelper.ReleaseLock(lock)

	var data *share.ScannerRegisterData

	for {
		r, err := stream.Recv()
		if err == io.EOF {
			log.Info("Stream receive done")
			break
		} else if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Receive error")
			return err
		}
		if data == nil {
			data = r
			// When sender sends an empty map, the receiver gets nil
			if data.CVEDB == nil {
				data.CVEDB = make(map[string]*share.ScanVulnerability)
			}
		} else {
			log.WithFields(log.Fields{"entries": len(r.CVEDB)}).Info("Stream receive")
			maps.Copy(data.CVEDB, r.CVEDB)
		}
	}

	if data == nil {
		return status.Error(codes.Aborted, "empty scanner registration stream")
	}

	if err := ss.scannerRegister(data); err != nil {
		return err
	}
	return stream.SendAndClose(&share.RPCVoid{})
}

const (
	cvedbUploadLockWait   = 3 * time.Minute
	cvedbUploadSessionTTL = "300s"
)

func acquireCVEDBUploadLock(clusHelper kv.ClusterHelper) (cluster.LockInterface, error) {
	lock, err := clusHelper.AcquireLock(share.CLUSLockScannerDBUploadKey, cvedbUploadLockWait, cluster.LockOptions{SessionTTL: cvedbUploadSessionTTL})
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to acquire CVEDB upload lock")
	}
	return lock, err
}


// ScannerRegisterV3 implements bidirectional streaming scanner registration.
// The scanner sends version info first; the controller checks if its CVE database is
// already current. If so, it registers the scanner immediately without requiring a
// database upload. If not, it requests the database from the scanner.
// A cluster-wide lock serializes all uploads so only one CVEDB transfer occurs at a time.
func (ss *ScanService) ScannerRegisterV3(stream share.ControllerScanService_ScannerRegisterV3Server) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}

	clusHelper := kv.GetClusterHelper()

	lock, err := acquireCVEDBUploadLock(clusHelper)
	if err != nil {
		return err
	}
	defer clusHelper.ReleaseLock(lock)

	// Check under lock whether the controller's CVE database is already current.
	s, err := clusHelper.GetScanner(share.CLUSScannerDBVersionID, access.NewReaderAccessControl())
	upToDate := false
	if err == nil && s != nil {
		upToDate = s.CVEDBVersion == req.CVEDBVersion
	}

	if upToDate {
		log.WithFields(log.Fields{"scanner": req.ID, "version": req.CVEDBVersion}).Info("CVEDB up-to-date, registering scanner without upload")
		totalEntries := int(s.CVEDBEntries)
		if totalEntries == 0 {
			// CVEDBEntries was not written by older code; fetch the real count from SQLite
			// to avoid storing 0 and causing every future registration to trigger a re-upload.
			if count, err := nvdb.GetCVECount(); err != nil {
				log.WithFields(log.Fields{"error": err}).Warn("Failed to get CVE count from SQLite, using 0")
			} else {
				totalEntries = count
			}
		}
		data := &share.ScannerRegisterData{
			CVEDBVersion:    req.CVEDBVersion,
			CVEDBCreateTime: req.CVEDBCreateTime,
			RPCServer:       req.RPCServer,
			RPCServerPort:   req.RPCServerPort,
			ID:              req.ID,
		}
		newStore := fmt.Sprintf("%s%s/", share.CLUSScannerDBStore, req.CVEDBVersion)
		if err := ss.finalizeDBCommit(data, newStore, totalEntries); err != nil {
			return stream.Send(&share.ScannerRegisterV3Response{
				Action:  share.ScannerRegisterV3Response_ERROR,
				Message: err.Error(),
			})
		}
		return stream.Send(&share.ScannerRegisterV3Response{
			Action: share.ScannerRegisterV3Response_REGISTERED,
		})
	}

	pageSize := getCVEDBPageSize()

	newStore := fmt.Sprintf("%s%s/", share.CLUSScannerDBStore, req.CVEDBVersion)
	writeFunc := func(i int, zb []byte) error {
		return cluster.PutBinary(fmt.Sprintf("%s%d", newStore, i), zb)
	}
	writer := newIncrementalDBWriter(req.CVEDBVersion, req.CVEDBCreateTime, newStore, writeFunc)
	needCleanup := true
	defer func() {
		if needCleanup {
			writer.Cleanup()
		}
	}()

	log.WithFields(log.Fields{"scanner": req.ID, "version": req.CVEDBVersion, "pageSize": pageSize}).Info("Requesting CVEDB from scanner")

	sendError := func(err error) error {
		log.WithError(err).Error("failed to handle scanner registration request")
		return stream.Send(&share.ScannerRegisterV3Response{
			Action:  share.ScannerRegisterV3Response_ERROR,
			Message: err.Error(),
		})
	}

	// Request the first page.
	if err := stream.Send(&share.ScannerRegisterV3Response{
		Action:        share.ScannerRegisterV3Response_SEND_CVEDB,
		CVEDBPageSize: pageSize,
	}); err != nil {
		return err
	}

	// Receive all CVE batches pushed by the scanner until CVEDBLast=true.
	for {
		r, err := stream.Recv()
		if err != nil {
			return err
		}
		log.WithFields(log.Fields{"total": len(r.CVEDB)}).Info("received cvedb batch")

		for k, v := range r.CVEDB {
			if err := writer.Add(k, v); err != nil {
				return sendError(err)
			}
		}
		if r.CVEDBLast {
			break
		}
	}

	if err := writer.Flush(); err != nil {
		return sendError(err)
	}

	log.WithFields(log.Fields{"scanner": req.ID, "version": req.CVEDBVersion, "entries": writer.Total}).Info("CVEDB received, registering scanner")

	data := &share.ScannerRegisterData{
		CVEDBVersion:    req.CVEDBVersion,
		CVEDBCreateTime: req.CVEDBCreateTime,
		RPCServer:       req.RPCServer,
		RPCServerPort:   req.RPCServerPort,
		ID:              req.ID,
	}
	if err := ss.finalizeDBCommit(data, newStore, writer.Total); err != nil {
		return sendError(err)
	}
	needCleanup = false
	return stream.Send(&share.ScannerRegisterV3Response{
		Action: share.ScannerRegisterV3Response_REGISTERED,
	})
}

// HealthCheck checks if the scanner is in the list of controller Consul key-value pairs and if the controller is alive
// This function follows the logic from how scannerRegister function puts the scanner into the KV store to retrieve it.
func (ss *ScanService) HealthCheck(ctx context.Context, data *share.ScannerRegisterData) (*share.ScannerAvailable, error) {
	visible := false
	scannerID := data.ID
	if data.RPCServer == "127.0.0.1" {
		// If scanner running in container, the ID should already by controller's ID.
		// This is to cover the case while scanner is not running in container.
		scannerID = Ctrler.ID
	}

	clusHelper := kv.GetClusterHelper()
	s, err := clusHelper.GetScanner(scannerID, access.NewReaderAccessControl())
	if err != nil && !errors.Is(err, cluster.ErrKeyNotFound) {
		log.WithFields(log.Fields{"error": err, "scanner": scannerID}).Warn("Failed to get scanner during health check")
		return nil, fmt.Errorf("failed to get scanner %s: %w", scannerID, err)
	}
	if s != nil {
		visible = true
	}

	return &share.ScannerAvailable{Visible: visible}, nil
}

func (ss *ScanService) scannerRegister(data *share.ScannerRegisterData) error {
	log.WithFields(log.Fields{
		"id": data.ID, "version": data.CVEDBVersion, "create": data.CVEDBCreateTime, "server": data.RPCServer, "entries": len(data.CVEDB),
	}).Info()

	writeDB := false
	newVer, err := utils.NewVersion(data.CVEDBVersion)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "version": data.CVEDBVersion}).Warn("Failed to parse scanner CVE DB version")
	}

	newScanner := share.CLUSScanner{
		ID:                           data.ID,
		CVEDBVersion:                 data.CVEDBVersion,
		CVEDBCreateTime:              data.CVEDBCreateTime,
		JoinedAt:                     time.Now().UTC(),
		RPCServer:                    data.RPCServer,
		RPCServerPort:                uint16(data.RPCServerPort),
		BuiltIn:                      data.RPCServer == "127.0.0.1",
		CVEDBEntries:                 len(data.CVEDB),
		MaxConcurrentScansPerScanner: rpc.ScannerAcquisitionMgr.GetMaxConcurrentScansPerScanner(),
		ScanCredit:                   rpc.ScannerAcquisitionMgr.GetMaxConcurrentScansPerScanner(),
	}
	if newScanner.BuiltIn {
		// If scanner running in container, the ID should already by controller's ID.
		// This is to cover the case while scanner is not running in container.
		newScanner.ID = Ctrler.ID
	}

	clusHelper := kv.GetClusterHelper()
	lock, err := clusHelper.AcquireLock(share.CLUSLockScannerKey, time.Second*20)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to acquire cluster lock")
		return err
	}
	defer clusHelper.ReleaseLock(lock)

	hasCveDB := len(data.CVEDB) > 0
	if !hasCveDB {
		log.WithFields(log.Fields{"scanner": data.ID, "version": data.CVEDBVersion}).Warn("Skip empty scanner DB update")
		return errors.New("scanner cvedb is empty")
	}

	// Check if the database is newer.
	s, err := clusHelper.GetScanner(share.CLUSScannerDBVersionID, access.NewReaderAccessControl())
	if err != nil && !errors.Is(err, cluster.ErrKeyNotFound) {
		log.WithFields(log.Fields{"error": err, "version": data.CVEDBVersion}).Warn("Failed to get scanner DB version record")
		return fmt.Errorf("failed to get scanner DB version record: %w", err)
	}
	if s == nil {
		writeDB = true
	} else {
		var ver utils.Version
		ver, err = utils.NewVersion(s.CVEDBVersion)
		if err != nil {
			log.WithFields(log.Fields{"error": err, "version": s.CVEDBVersion}).Warn("Failed to parse existing scanner CVE DB version")
		}
		if newVer.Compare(ver) > 0 || len(data.CVEDB) > s.CVEDBEntries {
			writeDB = true
		}
	}

	// Write the scanner and db atomically.
	// Consul value size limit is 512K. The limit also applies to the total value size in a transaction.
	// => so we cannot really use transaction to write database.

	oldStores, err := cluster.GetStoreKeys(share.CLUSScannerDBStore)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("Failed to get old scanner DB stores")
	}
	newStore := fmt.Sprintf("%s%s/", share.CLUSScannerDBStore, data.CVEDBVersion)

	txn := cluster.Transact()
	defer txn.Close()

	// Logic is like is, if we figure the db should be updated, we write the scanner record with new db prefix.
	// When the cache handler get notified of the new scanner, if db store is set, it will re-read the db keys.
	if writeDB {
		// Initiate slots
		cvedb := ss.preprocessDB(data)
		zbs, err := ss.prepareDBSlots(data, cvedb)
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error()
			return err
		}

		for i, zb := range zbs {
			key := fmt.Sprintf("%s%d", newStore, i)
			if err = cluster.PutBinary(key, zb); err != nil {
				log.WithFields(log.Fields{"error": err, "slot": i, "size": len(zb)}).Error()
				ss.registerFailureCleanup(newStore)
				return err
			}
		}

		// The idea is to use a dummy scanner to indicate the new database has been written.
		dbVerScanner := share.CLUSScanner{
			ID:              share.CLUSScannerDBVersionID,
			CVEDBVersion:    data.CVEDBVersion,
			CVEDBCreateTime: data.CVEDBCreateTime,
			CVEDBEntries:    len(data.CVEDB),
		}
		if err := clusHelper.PutScannerTxn(txn, &dbVerScanner); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("PutScannerTxn")
		}

		log.WithFields(log.Fields{"cvedb": newStore}).Info("CVE database written")
	}

	if err := clusHelper.PutScannerTxn(txn, &newScanner); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("PutScannerTxn")
	}
	if ok, err := txn.Apply(); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to write scanner to the cluster")
		if writeDB {
			ss.registerFailureCleanup(newStore)
		}
		return err
	} else if !ok {
		err = errors.New("Atomic write failed")
		log.Error(err.Error())
		return err
	}

	// Remove old stores. Ignore failure, missed keys will be removed the next update.
	if writeDB && len(oldStores) > 0 {
		txn.Reset()
		for _, store := range oldStores {
			txn.DeleteTree(store)
		}
		if _, err := txn.Apply(); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("txn.Apply")
		}
	}

	// Create scanner stats if not exist
	if err := clusHelper.CreateScannerStats(newScanner.ID); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("CreateScannerStats")
	}
	return nil
}

func (ss *ScanService) ScannerDeregister(ctx context.Context, data *share.ScannerDeregisterData) (*share.RPCVoid, error) {
	log.WithFields(log.Fields{"scanner": data.ID}).Info()

	clusHelper := kv.GetClusterHelper()
	if err := clusHelper.DeleteScanner(data.ID); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("DeleteScanner")
	}
	return &share.RPCVoid{}, nil
}

func (ss *ScanService) SubmitScanResult(ctx context.Context, result *share.ScanResult) (*share.RPCVoid, error) {
	log.WithFields(log.Fields{
		"registry": result.Registry, "repository": result.Repository, "tag": result.Tag,
	}).Info()

	err := scanner.StoreRepoScanResult(result)
	return &share.RPCVoid{}, err
}

func (s *ScanService) GetCaps(ctx context.Context, v *share.RPCVoid) (*share.ControllerCaps, error) {
	return &share.ControllerCaps{
		CriticalVul:              true,
		ScannerSettings:          true,
		SupportScannerRegisterV3: true,
	}, nil
}

func (s *ScanService) GetScannerSettings(ctx context.Context, v *share.RPCVoid) (*share.ScannerSettings, error) {
	acc := access.NewReaderAccessControl()
	cfg := cacher.GetSystemConfig(acc)
	return &share.ScannerSettings{
		EnableTLSVerification: cfg.EnableTLSVerification,
		CACerts:               strings.Join(cfg.GlobalCaCerts, "\n"),
		HttpProxy:             httpclient.GetHttpProxy(),
		HttpsProxy:            httpclient.GetHttpsProxy(),
		NoProxy:               "",
	}, nil
}

// --

type ScanAdapterService struct {
}

func (sas *ScanAdapterService) GetScanners(context.Context, *share.RPCVoid) (*share.GetScannersResponse, error) {
	var c share.GetScannersResponse

	acc := access.NewReaderAccessControl()
	cfg := cacher.GetSystemConfig(acc)

	busy, idle := rpc.ScannerAcquisitionMgr.CountScanners()
	scanners, dbTime, dbVer := cacher.GetScannerCount(acc)
	c.Scanners = uint32(scanners)
	c.IdleScanners = idle
	c.ScannerDBTime = dbTime
	c.ScannerVersion = dbVer

	// MaxScanner means max number of available scanners, including those to be scaled up. The number can be larger than c.Scanners.
	if cfg.ScannerAutoscale.Strategy != api.AutoScaleNone {
		if cfg.ScannerAutoscale.MaxPods > busy {
			c.MaxScanners = cfg.ScannerAutoscale.MaxPods - busy
		}
	} else {
		if c.Scanners > busy {
			c.MaxScanners = c.Scanners - busy
		}
	}

	return &c, nil
}

func (sas *ScanAdapterService) ScanImage(ctxunused context.Context, req *share.AdapterScanImageRequest) (*share.ScanResult, error) {
	log.WithFields(log.Fields{"request": req}).Debug("Scan image request")

	ctx, cancel := context.WithTimeout(context.Background(), repoScanTimeout)
	defer cancel()

	scanReq := &share.ScanImageRequest{
		Registry:    req.Registry,
		Repository:  req.Repository,
		Tag:         req.Tag,
		Token:       req.Token,
		ScanLayers:  req.ScanLayers,
		ScanSecrets: false,
	}

	result, err := rpc.ScanImage("", ctx, scanReq)
	if result == nil || result.Error != share.ScanErrorCode_ScanErrNone {
		return result, err
	}

	// store the scan result so it can be used by admission control
	scan.FixRegRepoForAdmCtrl(result)
	if err := scanner.StoreRepoScanResult(result); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("StoreRepoScanResult")
	}

	// Fill the detail and filter the result
	for _, v := range result.Vuls {
		scanUtils.FillVul(nvdb.GlobalCVECache(), v)
	}
	vpf := cacher.GetVulnerabilityProfileInterface(share.DefaultVulnerabilityProfileName)
	result.Vuls = vpf.FilterVuls(result.Vuls, []api.RESTIDName{{DisplayName: fmt.Sprintf("%s:%s", result.Repository, result.Tag)}})

	return result, err
}

// --
type CapService struct {
}

func (s *CapService) IsGRPCCompressed(ctx context.Context, v *share.RPCVoid) (*share.CLUSBoolean, error) {
	return &share.CLUSBoolean{Value: true}, nil
}

// --
type UpgradeService struct {
}

// const tmpDir string = "/tmp/"
// const dstDir string = "/etc/neuvector/db/"

func (s *UpgradeService) SupportUpgradeDB(context.Context, *share.RPCVoid) (*share.CLUSBoolean, error) {
	return &share.CLUSBoolean{Value: false}, nil
}

func (s *UpgradeService) SupportRegularDB(context.Context, *share.RPCVoid) (*share.CLUSBoolean, error) {
	return &share.CLUSBoolean{Value: true}, nil
}

func (s *UpgradeService) UpgradeScannerDB(stream share.ControllerUpgradeService_UpgradeScannerDBServer) error {
	return status.Error(codes.Unimplemented, "Database update API is deprecated")
}

const reportChanSize = 128

func agentReportWorker(ch chan []*share.CLUSConnection) {
	for conns := range ch {
		cache.UpdateConnections(conns)

		var wg sync.WaitGroup
		eps := cacher.GetAllControllerRPCEndpoints(access.NewReaderAccessControl())
		for _, ep := range eps {
			if ep.ID != Ctrler.ID {
				wg.Add(1)
				go func(ClusterIP string, RPCServerPort uint16) {
					// TODO: what if this fail? Or we could just transfer the graph update
					if _, err := rpc.ReportConnections(ClusterIP, RPCServerPort, conns); err != nil {
						log.WithFields(log.Fields{"error": err}).Debug("ReportConnections")
					}
					wg.Done()
				}(ep.ClusterIP, ep.RPCServerPort)
			}
		}
		wg.Wait()
	}
}

type ControllerAgentService struct {
	reportCh chan []*share.CLUSConnection
}

func (as *ControllerAgentService) IsCompressed(ctx context.Context, v *share.RPCVoid) (*share.CLUSBoolean, error) {
	return &share.CLUSBoolean{Value: true}, nil
}

func (as *ControllerAgentService) RequestAdmission(ctx context.Context, req *share.CLUSAdmissionRequest) (*share.CLUSAdmissionResponse, error) {
	return cache.AgentAdmissionRequest(req), nil
}

func (as *ControllerAgentService) ReportProcProfile(ctx context.Context, profs *share.CLUSProcProfileArray) (*share.CLUSReportResponse, error) {
	//group the request
	if !kv.IsImporting() {
		var ok bool
		gproc := make(map[string][]*share.CLUSProcessProfileEntry)
		for _, prof := range profs.Processes {
			proc := &share.CLUSProcessProfileEntry{
				Name:      prof.Name,
				Path:      prof.Path,
				User:      prof.User,
				Uid:       prof.Uid,
				Hash:      prof.Hash,
				Action:    prof.Action,
				CfgType:   share.Learned,
				CreatedAt: time.Now().UTC(),
				UpdatedAt: time.Now().UTC(),
			}

			var procs []*share.CLUSProcessProfileEntry
			if procs, ok = gproc[prof.GroupName]; ok {
				procs = append(procs, proc)
			} else {
				procs = []*share.CLUSProcessProfileEntry{proc}
			}
			gproc[prof.GroupName] = procs
		}

		if ok := cache.AddProcessReport(gproc); !ok {
			return &share.CLUSReportResponse{Action: share.ReportRespAction_Resend}, nil
		}
	}
	return &share.CLUSReportResponse{Action: share.ReportRespAction_Done}, nil
}

func (as *ControllerAgentService) ReportFileAccessRule(ctx context.Context, rarray *share.CLUSFileAccessRuleArray) (*share.CLUSReportResponse, error) {
	if !kv.IsImporting() {
		if ok := cache.AddFileRuleReport(rarray.Rules); !ok {
			return &share.CLUSReportResponse{Action: share.ReportRespAction_Resend}, nil
		}
	}
	return &share.CLUSReportResponse{Action: share.ReportRespAction_Done}, nil
}

// Handling connection report is synchronized because we hold the graph lock, so we put the request
// in a channel so the agent call is not blocked. Throttle logic is also added. We assume,
// in most cases, by reporting with longer interval, number of sessions of each entry will increase,
// but not the number of connection entries.
func (as *ControllerAgentService) ReportConnections(ctx context.Context, rarray *share.CLUSConnectionArray) (*share.CLUSReportResponse, error) {
	if !Ctrler.Leader {
		return &share.CLUSReportResponse{Action: share.ReportRespAction_Resend}, nil
	}

	hosts := cacher.GetHostCount(access.NewReaderAccessControl())
	interval := (hosts-1)/10*5 + 5
	if hosts > 100 {
		interval = 50
	}

	if len(as.reportCh) >= reportChanSize {
		// TODO: a count to be added
		interval += 25
		return &share.CLUSReportResponse{Action: share.ReportRespAction_Resend, ReportInterval: uint32(interval)}, nil
	}

	as.reportCh <- rarray.Connections
	return &share.CLUSReportResponse{Action: share.ReportRespAction_Done, ReportInterval: uint32(interval)}, nil
}

const ctrlSyncChunkSize int = 2 * 1024 * 1024

type ControllerService struct {
}

func (cs *ControllerService) IsCompressed(ctx context.Context, v *share.RPCVoid) (*share.CLUSBoolean, error) {
	return &share.CLUSBoolean{Value: true}, nil
}

func (cs *ControllerService) ReqSync(ctx context.Context, req *share.CLUSSyncRequest) (*share.CLUSSyncReply, error) {
	log.WithFields(log.Fields{"category": req.Category, "from": req.From}).Debug("Receive sync request")
	data := cache.GetSyncTxData(req.Category)
	return &share.CLUSSyncReply{Category: req.Category, Data: data}, nil
}

func (cs *ControllerService) ReqSyncStream(req *share.CLUSSyncRequest, stream share.ControllerCtrlService_ReqSyncStreamServer) error {
	log.WithFields(log.Fields{"category": req.Category, "from": req.From}).Debug("Receive sync request")

	reply := &share.CLUSSyncReply{Category: req.Category}
	data := cache.GetSyncTxData(req.Category)

	offset := 0
	size := len(data)
	for {
		if size-offset < ctrlSyncChunkSize {
			reply.Data = data[offset:]
			if err := stream.Send(reply); err != nil {
				log.WithFields(log.Fields{"error": err}).Debug("Send")
			}
			break
		} else {
			reply.Data = data[offset : offset+ctrlSyncChunkSize]
			if err := stream.Send(reply); err != nil {
				log.WithFields(log.Fields{"error": err}).Debug("Send")
			}
			offset += ctrlSyncChunkSize
		}
	}
	return nil
}

func (cs *ControllerService) TriggerSync(ctx context.Context, v *share.RPCVoid) (*share.RPCVoid, error) {
	cache.SyncFromLeader()
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) TriggerSyncLearnedPolicy(ctx context.Context, v *share.RPCVoid) (*share.RPCVoid, error) {
	cache.SyncLearnedPolicyFromCluster()
	//schedule a task to remove unused learned group with 0 member
	if Ctrler.Leader {
		cache.SchedulePruneGroups()
	}
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) ProfilingCmd(ctx context.Context, req *share.CLUSProfilingRequest) (*share.RPCVoid, error) {
	go utils.PerfProfile(req, share.ProfileFolder, "ctl.")
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) CheckPolicySyncStatus(ctx context.Context, v *share.RPCVoid) (*share.CLUSPolicySyncStatus, error) {
	ss := cache.CheckPolicySyncStatus()
	return ss, nil
}

func (cs *ControllerService) ReportConnections(ctx context.Context, rarray *share.CLUSConnectionArray) (*share.RPCVoid, error) {
	cache.UpdateConnections(rarray.Connections)
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) GetControllerCounter(ctx context.Context, v *share.RPCVoid) (*share.CLUSControllerCounter, error) {
	pid := os.Getpid()
	// Suppress error: diagnostic commands, failures are non-fatal
	lsof, err := sh.Command("lsof", "-Pn", "-p", strconv.Itoa(pid)).Command("grep", "-v", "IPv4\\|IPv6").Output()
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Failed to run lsof")
	}

	// Finding correct group pid
	var ps []byte
	name, err := os.Readlink("/proc/1/exe")
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Failed to readlink /proc/1/exe")
	}
	if name == "/usr/local/bin/monitor" { // when pid mode != host
		ps, err = sh.Command("ps", "-o", "pid,ppid,vsz,rss,comm", "-A").Output()
	} else {
		// processes under the controller
		ps, err = sh.Command("ps", "-o", "pid,ppid,vsz,rss,comm", "-g", strconv.Itoa(Ctrler.Pid)).Output()
	}
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Debug("Failed to run ps")
	}

	c := share.CLUSControllerCounter{
		GoRoutines: uint32(runtime.NumGoroutine()),
		Lsof:       lsof,
		PS:         ps,
	}
	return &c, nil
}

func (cs *ControllerService) DeleteConversation(ctx context.Context, ops *share.CLUSGraphOps) (*share.RPCVoid, error) {
	if ops.From == "" && ops.To == "" {
		cache.DeleteAllConvers()
	} else {
		cache.DeleteConver(ops.From, ops.To)
	}
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) DeleteEndpoint(ctx context.Context, ops *share.CLUSGraphOps) (*share.RPCVoid, error) {
	cache.DeleteEndpoint(ops.Endpoint)
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) SetEndpointAlias(ctx context.Context, ops *share.CLUSGraphOps) (*share.RPCVoid, error) {
	cache.ConfigEndpoint(ops.Endpoint, ops.Alias)
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) PauseResumeStoreWatcher(ctx context.Context, ops *share.CLUSStoreWatcherInfo) (*share.RPCVoid, error) {
	cache.PauseResumeStoreWatcher(ops.CtrlerID, ops.Key, ops.Action)
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) KickLoginSessions(ctx context.Context, ops *share.CLUSKickLoginSessionsRequest) (*share.RPCVoid, error) {
	rest.KickLoginSessions(ops)
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) GetStats(ctx context.Context, v *share.RPCVoid) (*share.CLUSStats, error) {
	stats := share.CLUSStats{
		Interval: statsInterval,
		Total:    &share.CLUSMetry{},
		Span1:    &share.CLUSMetry{},
		Span12:   &share.CLUSMetry{},
		Span60:   &share.CLUSMetry{},
	}

	gInfo.mutex.Lock()
	system.PopulateSystemStats(&stats, &gInfo.stats)
	gInfo.mutex.Unlock()
	return &stats, nil
}

func (cs *ControllerService) ResetLoginTokenTimer(ctx context.Context, ops *share.CLUSLoginTokenInfo) (*share.RPCVoid, error) {
	rest.ResetLoginTokenTimer(ops)
	return &share.RPCVoid{}, nil
}

func (cs *ControllerService) ReportK8SResToOPA(ctx context.Context, ops *share.CLUSKubernetesResInfo) (*share.RPCVoid, error) {
	rest.ReportK8SResToOPA(ops)
	log.WithFields(log.Fields{"ops": ops}).Debug("ReportK8SResToOPA (gprc-server)")
	return &share.RPCVoid{}, nil
}

func startGRPCServer(port uint16) (*cluster.GRPCServer, uint16) {
	var grpc *cluster.GRPCServer
	var err error

	if port == 0 {
		port = cluster.DefaultControllerGRPCPort
	}

	log.WithFields(log.Fields{"port": port}).Info("")
	for {
		grpc, err = cluster.NewGRPCServerTCP(fmt.Sprintf(":%d", port))
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Fail to create GRPC server")
			time.Sleep(time.Second * 5)
		} else {
			break
		}
	}

	ch := make(chan []*share.CLUSConnection, reportChanSize)
	go agentReportWorker(ch)

	share.RegisterControllerScanServiceServer(grpc.GetServer(), new(ScanService))
	share.RegisterControllerScanAdapterServiceServer(grpc.GetServer(), new(ScanAdapterService))
	share.RegisterControllerCapServiceServer(grpc.GetServer(), new(CapService))
	share.RegisterControllerUpgradeServiceServer(grpc.GetServer(), new(UpgradeService))
	share.RegisterControllerAgentServiceServer(grpc.GetServer(), &ControllerAgentService{reportCh: ch})
	share.RegisterControllerCtrlServiceServer(grpc.GetServer(), new(ControllerService))
	go grpc.Start()

	log.Info("GRPC server started")

	return grpc, port
}
