package rest

import (
	"errors"
	"sync"
	"time"
)

var errTooManyJobs = errors.New("Too many concurrent jobs")
var errDuplicateJob = errors.New("Duplicate job")

type longpollOnceTask interface {
	Run(arg interface{}) interface{}
}

type longpollOnceJob struct {
	polling bool
	start   time.Time
	dataCh  chan interface{}
	polled  chan interface{}
	timeout time.Duration
}

func newLongPollOnceJob(timeout time.Duration) *longpollOnceJob {
	return &longpollOnceJob{
		polling: true,
		start:   time.Now(),
		dataCh:  make(chan interface{}, 1),
		polled:  make(chan interface{}, 1),
		timeout: timeout,
	}
}

// return the original polling state
func (j *longpollOnceJob) toggleIfNotPolling() bool {
	if j.polling {
		return true
	} else {
		j.polling = true
		return false
	}
}

func (j *longpollOnceJob) Poll() (interface{}, time.Duration) {
	select {
	case <-time.After(j.timeout):
		j.polling = false
		return nil, j.timeout
	case data := <-j.dataCh:
		j.polled <- nil
		return data, time.Since(j.start)
	}
}

type longpollOnceMgr struct {
	mux     sync.Mutex
	max     int
	timeout time.Duration
	linger  time.Duration
	jobs    map[interface{}]*longpollOnceJob
}

func NewLongPollOnceMgr(timeout, linger time.Duration, max int) *longpollOnceMgr {
	return &longpollOnceMgr{
		max:     max,
		timeout: timeout,
		linger:  linger,
		jobs:    make(map[interface{}]*longpollOnceJob),
	}
}

func (m *longpollOnceMgr) GetJobCount() int {
	return len(m.jobs)
}

func (m *longpollOnceMgr) NewJob(key interface{}, task longpollOnceTask, arg interface{}) (*longpollOnceJob, error) {
	m.mux.Lock()
	defer m.mux.Unlock()

	job, ok := m.jobs[key]
	if !ok {
		if m.max > 0 && len(m.jobs) >= m.max {
			return nil, errTooManyJobs
		}

		job = newLongPollOnceJob(m.timeout)
		m.jobs[key] = job

		go func() {
			job.dataCh <- task.Run(arg)

			// In case polling returned, wait a while before discarding the record
			select {
			case <-time.After(m.linger):
			case <-job.polled:
			}

			m.mux.Lock()
			delete(m.jobs, key)
			m.mux.Unlock()
		}()

		return job, nil
	} else if job.toggleIfNotPolling() {
		return nil, errDuplicateJob
	} else {
		return job, nil
	}
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
	mux     sync.Mutex
	max     int
	timeout time.Duration
	linger  time.Duration
	jobs    map[interface{}]*longpollManyJob
}

func NewLongPollManyMgr(timeout, linger time.Duration, max int) *longpollManyMgr {
	return &longpollManyMgr{
		max:     max,
		timeout: timeout,
		linger:  linger,
		jobs:    make(map[interface{}]*longpollManyJob),
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
