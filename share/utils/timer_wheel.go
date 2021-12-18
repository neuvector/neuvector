package utils

import (
	"errors"
	"sync"
	"time"
)

type TimerWheel struct {
	state         int
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
	t.lock.Lock()
	t.tick = time.NewTicker(t.tickDuration)
	defer t.lock.Unlock()
	go func() {
		for {
			select {
			case <-t.tick.C:
				t.wheelCursor++
				if t.wheelCursor == t.wheelCount {
					t.wheelCursor = 0
				}

				iterator := t.wheel[t.wheelCursor]
				tasks := t.fetchExpiredTimeouts(iterator)
				t.notifyExpiredTimeOut(tasks)
			}
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
		for k, _ := range it.items {
			if taskId == k {
				delete(it.items, k)
			}
		}
	}
	return nil
}

func (t *TimerWheel) scheduleTimeOut(timeOut *WheelTimeOut) (string, error) {
	if timeOut.delay < t.tickDuration {
		timeOut.delay = t.tickDuration
	}
	lastRoundDelay := timeOut.delay % t.roundDuration
	lastTickDelay := timeOut.delay % t.tickDuration

	relativeIndex := lastRoundDelay / t.tickDuration
	if lastTickDelay != 0 {
		relativeIndex = relativeIndex + 1
	}

	remainingRounds := timeOut.delay / t.roundDuration
	if lastRoundDelay == 0 {
		remainingRounds = remainingRounds - 1
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	stopIndex := t.wheelCursor + int(relativeIndex)
	if stopIndex >= t.wheelCount {
		stopIndex = stopIndex - t.wheelCount
		timeOut.rounds = int(remainingRounds) + 1
	} else {
		timeOut.rounds = int(remainingRounds)
	}
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
	t.lock.Lock()
	defer t.lock.Unlock()

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
