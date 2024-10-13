package scheduler

import (
	"fmt"
	"sync"
)

type Priority int

const PriorityHigh Priority = 0
const PriorityLow Priority = 1

type Action int

const (
	TaskActionDone Action = iota
	TaskActionWait
	TaskActionRetry
	TaskActionRequeue
	TaskActionRequeueWait
)

type Processor struct {
	name     string
	currTask Task
}

type Task interface {
	Key() string
	Priority() Priority
	Handler(proc string) Action
	StartTimer()
	CancelTimer()
	Print(msg string)
}

type Schd struct {
	procs         []*Processor
	taskQueueHigh []Task
	taskQueueLow  []Task
	mutex         sync.Mutex
	notifyChan    chan bool
}

func (s *Schd) lock() {
	s.mutex.Lock()
}

func (s *Schd) unlock() {
	s.mutex.Unlock()
}

func (s *Schd) TaskCount() int {
	s.lock()
	defer s.unlock()
	return len(s.taskQueueHigh) + len(s.taskQueueLow)
}

func (s *Schd) AddProcessor(name string) error {
	s.lock()
	for _, proc := range s.procs {
		if proc.name == name {
			s.unlock()
			return fmt.Errorf("proc %s already exists", name)
		}
	}
	s.procs = append(s.procs, &Processor{name: name})
	s.unlock()
	s.taskNotify()
	return nil
}

func (s *Schd) DelProcessor(name string) (string, error) {
	var i int
	var proc *Processor
	var found bool

	s.lock()
	defer s.unlock()
	for i, proc = range s.procs {
		if proc.name == name {
			found = true
			break
		}
	}
	if !found {
		return "", fmt.Errorf("proc %s doesn't exist", name)
	} else {
		s.procs = append(s.procs[:i], s.procs[i+1:]...)
	}

	// cancel running jobs on this processor
	if proc.currTask != nil {
		proc.currTask.CancelTimer()
		return proc.currTask.Key(), nil
	}
	return "", nil
}

func getTaskIdxFromQueue(key string, queue []Task) int {
	for i, t := range queue {
		if t.Key() == key {
			return i
		}
	}
	return -1
}

func removeTaskFromQueue(key string, queue []Task) ([]Task, Task) {
	var task Task
	i := getTaskIdxFromQueue(key, queue)
	if i == -1 {
		return queue, nil
	} else {
		task = queue[i]
		queue = append(queue[:i], queue[i+1:]...)
	}
	return queue, task
}

func (s *Schd) AddTask(task Task, toHead bool) {
	priority := task.Priority()

	s.lock()
	if priority == PriorityLow {
		if toHead {
			s.taskQueueLow = append([]Task{task}, s.taskQueueLow...)
		} else {
			s.taskQueueLow = append(s.taskQueueLow, task)
		}
	} else if priority == PriorityHigh {
		if toHead {
			s.taskQueueHigh = append([]Task{task}, s.taskQueueHigh...)
		} else {
			s.taskQueueHigh = append(s.taskQueueHigh, task)
		}
	}
	s.unlock()
	s.taskNotify()
}

func (s *Schd) DeleteTask(key string, priority Priority) bool {
	var found bool
	var t Task

	// If the task is already running, the task will not be deleted
	s.lock()
	if priority == PriorityLow {
		s.taskQueueLow, t = removeTaskFromQueue(key, s.taskQueueLow)
	} else if priority == PriorityHigh {
		s.taskQueueHigh, t = removeTaskFromQueue(key, s.taskQueueHigh)
	}
	s.unlock()

	if t != nil {
		found = true
		t.CancelTimer()
	}
	return found
}

func (s *Schd) ClearTaskQueue(priority Priority) {
	s.lock()
	if priority == PriorityLow {
		s.taskQueueLow = nil
	} else if priority == PriorityHigh {
		s.taskQueueHigh = nil
	}
	s.unlock()
}

func (s *Schd) TaskDone(task Task, action Action) {
	key := task.Key()

	s.lock()
	for _, proc := range s.procs {
		if proc.currTask != nil && proc.currTask.Key() == key {
			proc.currTask = nil
			break
		}
	}
	s.unlock()

	task.CancelTimer()
	switch action {
	case TaskActionRetry:
		s.AddTask(task, true)
	case TaskActionRequeue:
		s.AddTask(task, false)
	default:
		// In case task is done after the task is rescheduled
		s.DeleteTask(key, task.Priority())
		s.taskNotify()
	}
}

func (s *Schd) getAvailableProc() *Processor {
	s.lock()
	defer s.unlock()
	for _, proc := range s.procs {
		if proc.currTask == nil {
			return proc
		}
	}
	return nil
}

func (s *Schd) getNextTask() Task {
	s.lock()
	defer s.unlock()
	if len(s.taskQueueHigh) > 0 {
		task := s.taskQueueHigh[0]
		s.taskQueueHigh, _ = removeTaskFromQueue(task.Key(), s.taskQueueHigh)
		return task
	} else if len(s.taskQueueLow) > 0 {
		task := s.taskQueueLow[0]
		s.taskQueueLow, _ = removeTaskFromQueue(task.Key(), s.taskQueueLow)
		return task
	}
	return nil
}

func (s *Schd) taskNotify() {
	if len(s.notifyChan) < 2 {
		s.notifyChan <- true
	}
}

func (s *Schd) taskWorker() {
	for {
		select {
		case <-s.notifyChan:
			for {
				proc := s.getAvailableProc()
				if proc == nil {
					break
				}
				task := s.getNextTask()
				if task == nil {
					break
				}
				action := task.Handler(proc.name)
				switch action {
				case TaskActionWait:
					task.StartTimer()
					s.lock()
					proc.currTask = task
					s.unlock()
				case TaskActionRetry:
					s.AddTask(task, true)
				case TaskActionRequeue:
					s.AddTask(task, false)
				case TaskActionRequeueWait:
					/* the task will be requeued when the timer expires */
					task.StartTimer()
				case TaskActionDone:
				}
			}
		}
	}
}

func (s *Schd) Init() {
	// Make chanel size 2 just to be safe. May not be necessary.
	s.notifyChan = make(chan bool, 2)
	go s.taskWorker()
}

func (s *Schd) Reset() {
	s.lock()
	defer s.unlock()
	s.taskQueueLow = nil
	s.taskQueueHigh = nil
	for _, proc := range s.procs {
		if proc.currTask != nil {
			proc.currTask.CancelTimer()
			proc.currTask = nil
		}
	}
	s.procs = nil
}
