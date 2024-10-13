package scheduler

// Temporarily commented out since this test function is not currently in use.

// var wheel *utils.TimerWheel
// var scher Schd

// const testTick = time.Millisecond * 50
// const testMilliTick = time.Microsecond * 50

// type workerFunc func(id string, life time.Duration)

// type task struct {
// 	id      string
// 	timer   string
// 	expired bool
// 	runs    int
// 	worker  workerFunc
// 	life    int
// 	timeout int
// }

// func (t *task) Key() string {
// 	return t.id
// }

// func (t *task) Priority() Priority {
// 	return PriorityLow
// }

// func (t *task) Print(msg string) {
// }

// func (t *task) StartTimer() {
// 	t.timer, _ = wheel.AddTask(t, testTick*time.Duration(t.timeout))
// }

// func (t *task) CancelTimer() {
// 	if t.timer != "" {
// 		wheel.RemoveTask(t.timer)
// 	}
// }

// func (t *task) Handler(proc string) Action {
// 	t.runs++
// 	go t.worker(t.id, testTick*time.Duration(t.life))
// 	return TaskActionWait
// }

// func (t *task) Expire() {
// 	t.expired = true
// }

// func workerNone(id string, life time.Duration) {
// 	time.Sleep(life)
// }

// func workerRequeue(t *task, life time.Duration) {
// 	time.Sleep(life)
// 	scher.TaskDone(t, TaskActionRequeue)
// }

// func workerDone(t *task, life time.Duration) {
// 	time.Sleep(life)
// 	scher.TaskDone(t, TaskActionDone)
// }

// func TestTimeout(t *testing.T) {
// 	/* This test is timing-bound
// 	wheel = utils.NewTimerWheelWithTick(testTick)
// 	wheel.Start()

// 	scher.Init()
// 	scher.AddProcessor("self")

// 	tk := &task{id: "1", timeout: 1, worker: workerDone, life: 2}
// 	scher.AddTask(tk, PriorityLow, false)
// 	time.Sleep(testTick * 3)
// 	if tk.runs != 1 || !tk.expired || len(scher.taskQueueLow) != 0 {
// 		t.Errorf("Error: runs=%d expired=%v tasks=%v\n", tk.runs, tk.expired, len(scher.taskQueueLow))
// 	}
// 	scher.ClearTaskQueue(PriorityLow)

// 	tk = &task{id: "2", timeout: 5, worker: workerRequeue, life: 1}
// 	scher.AddTask(tk, PriorityLow, false)
// 	time.Sleep(testMilliTick * 3500)
// 	if tk.runs != 4 || tk.expired || len(scher.taskQueueLow) != 0 {
// 		t.Errorf("Error: runs=%d expired=%v tasks=%v\n", tk.runs, tk.expired, len(scher.taskQueueLow))
// 	}
// 	scher.ClearTaskQueue(PriorityLow)

// 	tk = &task{id: "3", timeout: 2, worker: workerNone, life: 1}
// 	scher.AddTask(tk, PriorityLow, false)
// 	time.Sleep(testTick * 3)
// 	if tk.runs != 1 || !tk.expired || len(scher.taskQueueLow) != 1 {
// 		t.Errorf("Error: runs=%d expired=%v tasks=%v\n", tk.runs, tk.expired, len(scher.taskQueueLow))
// 	}
// 	scher.ClearTaskQueue(PriorityLow)
// 	*/
// }
