package utils

import (
	"errors"
	"sync"
	"time"
)

type TimerWheel struct {
	tickDuration  time.Duration
	roundDuration time.Duration
	wheelCount    int
	wheel         []*Iterator
	tick          *time.Ticker
	lock          sync.Mutex
	wheelCursor   int
	mask          int
}

type TimerTask interface {
	Expire()
}

type Iterator struct {
	items map[string]*WheelTimeOut
}

type WheelTimeOut struct {
	delay  time.Duration
	index  int
	rounds int
	task   TimerTask
}

const (
	default_tick_duration = time.Second
	default_wheel_count   = 3600
)

func NewTimerWheel() *TimerWheel {
	return &TimerWheel{
		tickDuration:  default_tick_duration,
		wheelCount:    default_wheel_count,
		wheel:         createWheel(default_wheel_count),
		wheelCursor:   0,
		mask:          default_wheel_count - 1,
		roundDuration: default_tick_duration * default_wheel_count,
	}
}

func NewTimerWheelWithTick(tick time.Duration) *TimerWheel {
	return &TimerWheel{
		tickDuration:  tick,
		wheelCount:    default_wheel_count,
		wheel:         createWheel(default_wheel_count),
		wheelCursor:   0,
		mask:          default_wheel_count - 1,
		roundDuration: default_tick_duration * default_wheel_count,
	}
}

func (t *TimerWheel) Start() {
	t.tick = time.NewTicker(t.tickDuration)
	go func() {
		for range t.tick.C {
			t.lock.Lock()
			t.wheelCursor++
			if t.wheelCursor == t.wheelCount {
				t.wheelCursor = 0
			}

			iterator := t.wheel[t.wheelCursor]
			tasks := t.fetchExpiredTimeouts(iterator)
			t.lock.Unlock()

			t.notifyExpiredTimeOut(tasks)
		}
	}()
}

func (t *TimerWheel) Stop() {
	t.tick.Stop()
}

func createWheel(wheelCount int) []*Iterator {
	arr := make([]*Iterator, wheelCount)

	for v := 0; v < wheelCount; v++ {
		arr[v] = &Iterator{items: make(map[string]*WheelTimeOut)}
	}
	return arr
}

func (t *TimerWheel) AddTask(task TimerTask, delay time.Duration) (string, error) {
	if task == nil {
		return "", errors.New("task is empty")
	}
	if delay <= 0 {
		return "", errors.New("delay Must be greater than zero")
	}
	timeOut := &WheelTimeOut{
		delay: delay,
		task:  task,
	}

	tid, err := t.scheduleTimeOut(timeOut)

	return tid, err
}

func (t *TimerWheel) RemoveTask(taskId string) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	for _, it := range t.wheel {
		for k := range it.items {
			if taskId == k {
				delete(it.items, k)
			}
		}
	}
	return nil
}

func (t *TimerWheel) scheduleTimeOut(timeOut *WheelTimeOut) (string, error) {
	if timeOut.delay < t.tickDuration {
		timeOut.delay = t.tickDuration // smallest unit delay
	}
	lastRoundDelay := timeOut.delay % t.roundDuration  // position within a boundary (3600 seconds)
	relativeIndex := lastRoundDelay / t.tickDuration   // relative slot index (after the current slot index)
	remainingRounds := timeOut.delay / t.roundDuration // repeating counter; if tm < 3600s, it is 0

	t.lock.Lock()
	defer t.lock.Unlock()
	stopIndex := t.wheelCursor + int(relativeIndex) // real slot index from current slot index
	if stopIndex >= t.wheelCount {                  // wrap around
		stopIndex = stopIndex - t.wheelCount
	}

	// task's slot assignment
	timeOut.rounds = int(remainingRounds)
	timeOut.index = stopIndex
	item := t.wheel[stopIndex]
	if item == nil {
		item = &Iterator{
			items: make(map[string]*WheelTimeOut),
		}
	}

	// In case GetGuid is not random enough ??
	for i := 0; i < 16; i++ {
		key, err := GetGuid()
		if err != nil {
			return "", err
		}
		if _, ok := item.items[key]; !ok {
			// Good, no collision
			item.items[key] = timeOut
			t.wheel[stopIndex] = item
			return key, nil
		}
	}

	return "", errors.New("Failed to create unique task key")
}

func (t *TimerWheel) fetchExpiredTimeouts(iterator *Iterator) []*WheelTimeOut {
	task := []*WheelTimeOut{}

	for k, v := range iterator.items {
		if v.rounds <= 0 {
			task = append(task, v)
			delete(iterator.items, k)
		} else {
			v.rounds--
		}
	}

	return task
}

func (t *TimerWheel) notifyExpiredTimeOut(tasks []*WheelTimeOut) {
	for _, task := range tasks {
		go task.task.Expire()
	}
}
