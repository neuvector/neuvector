package rest

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/neuvector/neuvector/controller/api"
	log "github.com/sirupsen/logrus"
)

var errTooManyJobs = errors.New("Too many concurrent jobs")
var errDuplicateJob = errors.New("Duplicate job")
var errMaxRetryReached = errors.New("Maximum job retry attempts reached")

type JobStatus int

// Define the possible statuses of a job
// Pending: The job is in the queue and waiting to be processed
// Retry: The job needs to be retried due to a previous failure
// Completed: The job has finished successfully
// Failed: The job has encountered an error and cannot be completed
const (
	Pending JobStatus = iota
	Retry
	Completed
	Failed
)

type longpollOnceTask interface {
	Run(arg interface{}) (interface{}, *JobError)
	ShouldRetry(arg interface{}) bool
}

type longpollOnceJob struct {
	ID         interface{}      // Unique identifier for the job
	StartTime  time.Time        // Timestamp when the job started
	DataChan   chan interface{} // Channel for exchanging data
	Timeout    time.Duration    // Time allowed before the job times out
	RetryCount int              // Number of retry attempts on failure
	Status     JobStatus        // Current status of the job
	Error      *JobError        // Error details, if the job encountered an issue
}

type JobError struct {
	Err    error
	Code   int
	Detail interface{}
}

func NewJobError(code int, err error, detail interface{}) *JobError {
	return &JobError{
		Code:   code,
		Err:    err,
		Detail: detail,
	}
}

func (e *JobError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("JobError Code: %d, Error: %v", e.Code, e.Err)
	}
	return fmt.Sprintf("JobError Code: %d", e.Code)
}

func newLongPollOnceJob(key interface{}, timeout time.Duration) *longpollOnceJob {
	return &longpollOnceJob{
		ID:         key,
		StartTime:  time.Now(),
		DataChan:   make(chan interface{}, 1),
		Timeout:    timeout,
		RetryCount: 0,
		Status:     Pending,
	}
}

type PollWorkItem struct {
	key  interface{}
	args interface{}
	task longpollOnceTask
}

type longpollOnceMgr struct {
	mux                        sync.RWMutex
	timeout                    time.Duration
	jobs                       map[interface{}]*longpollOnceJob // use as a queue
	jobQueue                   chan PollWorkItem
	shutdownCh                 chan struct{}
	jobFailRetryMax            int // Maximum retry attempts
	maxConcurrentRepoScanTasks int
	staleJobCleanupInterval    time.Duration // Interval for cleaning up stale jobs
	workerWG                   sync.WaitGroup
}

// Poll waits for the job to complete or timeout.
// If the job fails, it returns nil and the associated JobError.
// If the job is still pending or needs to retry, it returns nil, nil.
// If the job completes successfully, it returns the result and nil.
func (m *longpollOnceMgr) Poll(key interface{}) (interface{}, *JobError) {
	m.mux.RLock()
	j, exists := m.jobs[key]
	m.mux.RUnlock()
	if exists {
		select {
		case <-time.After(m.timeout):
			return nil, j.Error
		case result, ok := <-j.DataChan:
			m.mux.Lock()
			delete(m.jobs, key)
			m.mux.Unlock()
			if !ok {
				log.Error("DataChan closed")
				return nil, j.Error
			}
			return result, j.Error
		}
	}
	return nil, NewJobError(api.RESTErrPollJobNotFoundError, fmt.Errorf("job with key %v not found", key), nil)
}

// Process each job in the queue and update its status based on the task result
// - If the task completes successfully, mark the job as Completed
// - If the task should be retried, mark the job as Retry
// - If the task fails, mark the job as Failed
func (m *longpollOnceMgr) pollWorker() {
	for {
		select {
		case <-m.shutdownCh:
			return
		case workItem, ok := <-m.jobQueue:
			if !ok {
				return
			}
			m.mux.RLock()
			_, exists := m.jobs[workItem.key]
			m.mux.RUnlock()

			if exists {
				result, jobError := workItem.task.Run(workItem.args)
				var status JobStatus
				if jobError == nil {
					status = Completed
				} else if workItem.task.ShouldRetry(jobError) {
					status = Retry
				} else {
					status = Failed
				}

				m.updateJobStatus(workItem.key, status, result, jobError)
			} else {
				log.WithFields(log.Fields{"key": workItem.key}).Error("Job not found in manager")
			}
		}
	}
}

func (m *longpollOnceMgr) updateJobStatus(jobKey interface{}, jobStatus JobStatus, jobResult interface{}, jobError *JobError) {
	m.mux.Lock()
	defer m.mux.Unlock()
	job, exists := m.jobs[jobKey]
	if exists {
		job.Status = jobStatus
		job.Error = jobError
		if jobResult != nil {
			select {
			case job.DataChan <- jobResult:
			default:
				log.Errorf("DataChan for job %v is full or closed", jobKey)
			}
		}
	}
}

// NewLongPollOnceMgr initializes the repository scan manager with the specified parameters.
// - repoScanLongPollTimeout: The timeout duration for long polling operations.
// - staleScanJobCleanupIntervalHour: The interval for cleaning up stale jobs.
// - maxConcurrentRepoScanWorkers: The maximum number of concurrent repository scan tasks allowed.
// - scanJobQueueCapacity: The capacity of the job queue for managing repository scan tasks.
// - scanJobFailRetryMax: The maximum number of retry attempts for failed jobs.
func NewLongPollOnceMgr(repoScanLongPollTimeout, staleScanJobCleanupIntervalHour time.Duration, maxConcurrentRepoScanTasks, scanJobQueueCapacity, scanJobFailRetryMax int) *longpollOnceMgr {
	mgr := &longpollOnceMgr{
		maxConcurrentRepoScanTasks: maxConcurrentRepoScanTasks,
		timeout:                    repoScanLongPollTimeout,
		jobs:                       make(map[interface{}]*longpollOnceJob),
		shutdownCh:                 make(chan struct{}),                                   // Ensure the running is close
		jobQueue:                   make(chan PollWorkItem, max(0, scanJobQueueCapacity)), // Ensure the jobQueue size does not become negative.
		jobFailRetryMax:            scanJobFailRetryMax,
		staleJobCleanupInterval:    staleScanJobCleanupIntervalHour,
	}

	// Run a work pool to maintain the speed for process the jobs in jobs Map
	for i := 0; i < mgr.maxConcurrentRepoScanTasks; i++ {
		mgr.workerWG.Add(1)
		go func() {
			defer mgr.workerWG.Done()
			mgr.pollWorker()
		}()
	}

	// Start the job garbage collector to periodically clean up stale jobs
	mgr.workerWG.Add(1)
	go func() {
		defer mgr.workerWG.Done()
		mgr.startJobGarbageCollector()
	}()
	return mgr
}

func (m *longpollOnceMgr) GetJobCount() int {
	m.mux.RLock()
	defer m.mux.RUnlock()
	return len(m.jobs)
}

func (m *longpollOnceMgr) RemoveJob(key interface{}) {
	m.mux.Lock()
	defer m.mux.Unlock()
	delete(m.jobs, key)
}

// Cleans up stale jobs that have not been used for a specified duration.
// Only jobs with a status of 'Completed' are removed, as 'InProgress' or 'Failed' jobs may eventually complete.
func (m *longpollOnceMgr) cleanupStaleJobs() {
	m.mux.Lock()
	defer m.mux.Unlock()

	now := time.Now()
	for key, job := range m.jobs {
		if now.Sub(job.StartTime) >= m.staleJobCleanupInterval {
			close(job.DataChan)
			delete(m.jobs, key)
		}
	}
}

// Periodically triggers the cleanup of stale jobs at intervals defined by m.staleJobCleanupInterval.
func (m *longpollOnceMgr) startJobGarbageCollector() {
	ticker := time.NewTicker(m.staleJobCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.shutdownCh:
			return
		case <-ticker.C:
			m.cleanupStaleJobs()
		}
	}
}

// Attempts to enqueue a job into the job queue.
// Returns an error if the job queue has reached its capacity.
func (m *longpollOnceMgr) scheduleJobToQueue(key interface{}, task longpollOnceTask, args interface{}, job *longpollOnceJob) error {
	select {
	case m.jobQueue <- PollWorkItem{key: key, args: args, task: task}:
		job.Status = Pending
		m.jobs[key] = job
		return nil
	default:
		log.WithFields(log.Fields{"key": key}).Error("jobQueue is full")
		return errTooManyJobs
	}
}

// NewJob attempts to create and enqueue a new job in the longpoll manager.
// It handles errors related to job queue capacity and retry limits.
// If a job with the given key already exists and is not pending, it checks the retry status.
// If the job is in retry status and has not exceeded the retry limit, it increments the retry count and re-enqueues the job.
// If the retry limit is reached, it returns an error indicating the maximum retry attempts have been reached.
func (m *longpollOnceMgr) NewJob(key interface{}, task longpollOnceTask, args interface{}) (*longpollOnceJob, error) {
	m.mux.Lock()
	defer m.mux.Unlock()

	var job *longpollOnceJob
	var err error
	job, ok := m.jobs[key]

	if !ok {
		job = newLongPollOnceJob(key, m.timeout)
		err = m.scheduleJobToQueue(key, task, args, job)
		if err != nil {
			delete(m.jobs, key)
			job = nil
		}
	} else if job.Status != Pending {
		if job.Status == Retry {
			if job.RetryCount < m.jobFailRetryMax {
				job.RetryCount++
				err = m.scheduleJobToQueue(key, task, args, job)
				if err != nil {
					delete(m.jobs, key)
					job = nil
				}
			} else {
				job = nil
				delete(m.jobs, key)
				err = errMaxRetryReached
			}
		}
	}

	return job, err
}

// Ensure no goroutine leaks
func (m *longpollOnceMgr) Shutdown() {
	close(m.shutdownCh) // Signal all goroutines to stop
	close(m.jobQueue)   // Close the jobQueue to stop pollWorkers from waiting on it
	m.workerWG.Wait()
}

// --

type SignalFunc func()

type longpollManyTask interface {
	Run(arg interface{}, signal SignalFunc)
	Read() interface{}
	Delete()
}

type longpollManyJob struct {
	polling bool
	start   time.Time
	dataCh  chan interface{}
	polled  chan interface{}
	timeout time.Duration
	task    longpollManyTask
}

func newLongPollManyJob(timeout time.Duration, task longpollManyTask) *longpollManyJob {
	return &longpollManyJob{
		start:   time.Now(),
		dataCh:  make(chan interface{}, 1),
		polled:  make(chan interface{}, 1),
		timeout: timeout,
		task:    task,
	}
}

// return the original polling state
func (j *longpollManyJob) toggleIfNotPolling() bool {
	if j.polling {
		return true
	} else {
		j.polling = true
		return false
	}
}

// return data, if task is done, and a duration since start
func (j *longpollManyJob) Poll() (interface{}, bool, time.Duration) {
	select {
	case <-time.After(j.timeout):
		j.polling = false
		return nil, false, j.timeout
	case _, alive := <-j.dataCh:
		data := j.task.Read()
		if !alive {
			j.polled <- nil
		}
		j.polling = false
		return data, !alive, time.Since(j.start)
	}
}

type longpollManyMgr struct {
	mux                        sync.Mutex
	max                        int
	maxConcurrentRepoScanTasks int
	timeout                    time.Duration
	linger                     time.Duration
	jobs                       map[interface{}]*longpollManyJob
}

func NewLongPollManyMgr(timeout, linger time.Duration, max, maxConcurrentRepoScanTasks int) *longpollManyMgr {
	return &longpollManyMgr{
		max:                        max,
		timeout:                    timeout,
		linger:                     linger,
		maxConcurrentRepoScanTasks: maxConcurrentRepoScanTasks,
		jobs:                       make(map[interface{}]*longpollManyJob),
	}
}

func (m *longpollManyMgr) GetJobCount() int {
	return len(m.jobs)
}

func (m *longpollManyMgr) NewJob(key interface{}, task longpollManyTask, arg interface{}) (*longpollManyJob, error) {
	m.mux.Lock()
	defer m.mux.Unlock()

	job, ok := m.jobs[key]
	if !ok {
		if m.max > 0 && len(m.jobs) >= m.max {
			return nil, errTooManyJobs
		}

		job = newLongPollManyJob(m.timeout, task)
		m.jobs[key] = job

		go func() {
			// Whenever the 'Run' function has new data, it calls the signal function.
			// The function indicate the data is available by sending into dataCh.
			task.Run(arg, func() {
				select {
				case job.dataCh <- nil:
				default: // has data, do nothing
				}
			})
			close(job.dataCh)

			// In case polling returned, wait a while before discarding the record
			select {
			case <-time.After(m.linger):
			case <-job.polled:
			}

			m.mux.Lock()
			delete(m.jobs, key)
			m.mux.Unlock()

			task.Delete()
		}()

		return job, nil
	} else if job.toggleIfNotPolling() {
		return nil, errDuplicateJob
	} else {
		return job, nil
	}
}
