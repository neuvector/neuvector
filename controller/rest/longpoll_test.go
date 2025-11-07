package rest

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// MockTask represents a mock implementation of a task that can be run.
// It simulates work by sleeping for a specified duration and returns a predefined result.
type MockTask struct {
	result        interface{}
	sleepDuration time.Duration
	started       chan struct{}
}

// NewMockTask creates a new instance of MockTask with the given result and sleep duration.
// Parameters:
// - result: The result to return after the task is run.
// - sleepDuration: The duration to sleep to simulate work.
func NewMockTask(result interface{}, sleepDuration time.Duration, started chan struct{}) MockTask {
	return MockTask{
		result:        result,
		sleepDuration: sleepDuration,
		started:       started,
	}
}

// Run executes the mock task.
// It sleeps for the duration specified in sleepDuration and then returns the predefined result.
// Parameters:
// - arg: An argument that can be used to influence the task's behavior (unused in this mock).
// Returns:
// - The predefined result after sleeping.
func (m *MockTask) Run(arg interface{}) (interface{}, *JobError) {
	if m.started != nil {
		close(m.started)
	}
	time.Sleep(m.sleepDuration)
	return m.result, nil
}

func (m *MockTask) ShouldRetry(arg interface{}) bool {
	return false
}

var (
	taskResult = "task result"
)

// TestErrorVariable verifies that the error variables contain the correct error messages.
func TestErrorVariable(t *testing.T) {
	assert.Equal(t, "Too many concurrent jobs", errTooManyJobs.Error())
	assert.Equal(t, "Duplicate job", errDuplicateJob.Error())
	assert.Equal(t, "Maximum job retry attempts reached", errMaxRetryReached.Error())
}

// TestNewJobError verifies the creation of a new JobError and its fields.
func TestNewJobError(t *testing.T) {
	expectedErr := "test error"
	err := errors.New(expectedErr)
	detail := "some detail"
	errCode := 404
	jobError := NewJobError(errCode, err, detail)

	assert.Equal(t, errCode, jobError.Code)
	assert.Equal(t, expectedErr, jobError.Error())
	assert.Equal(t, detail, jobError.Detail)
}

// TestNewLongPollOnceJob verifies the creation of a new long poll once job and its fields.
func TestNewLongPollOnceJob(t *testing.T) {
	key := "testKey"
	timeout := 2 * time.Second
	job := newLongPollOnceJob(key, timeout)

	assert.Equal(t, key, job.ID)
	assert.WithinDuration(t, time.Now(), job.StartTime, time.Second)
	assert.Equal(t, timeout, job.Timeout)
	assert.Equal(t, 0, job.RetryCount)
	assert.Equal(t, Pending, job.Status)
	assert.NotNil(t, job.DataChan)
}

// TestPoll verifies the Poll method of a long poll once job for both timeout and data received cases.
func TestPoll(t *testing.T) {
	key := "testKey"
	mockTimeOut := 1 * time.Second
	mockPoolSize := 1
	mockJobQueueCapacity := 1
	mockRetry := 1
	mockStaleJobCleanupInterval := 10 * time.Second

	mgr := NewLongPollOnceMgr(mockTimeOut, mockStaleJobCleanupInterval, mockPoolSize, mockJobQueueCapacity, mockRetry)
	defer mgr.Shutdown()

	mockTask := NewMockTask(taskResult, 100*time.Millisecond, nil)
	job, jobErr := mgr.NewJob(key, &mockTask, nil)
	assert.NotNil(t, job, "Expected job to be non-nil for key %s", key)
	assert.Nil(t, jobErr, "Unexpected error creating job %s: %v", key, jobErr)

	result, pollErr := mgr.Poll(key)
	assert.Equal(t, taskResult, result)
	assert.Nil(t, pollErr)
}

// TestGetJobCount verifies that the GetJobCount method accurately reflects the number of jobs managed.
func TestJobCount(t *testing.T) {
	mockTimeOut := 1 * time.Second
	mockPoolSize := 1
	mockJobQueueCapacity := 1
	mockRetry := 1
	mockStaleJobCleanupInterval := 10 * time.Second

	mgr := NewLongPollOnceMgr(mockTimeOut, mockStaleJobCleanupInterval, mockPoolSize, mockJobQueueCapacity, mockRetry)
	defer mgr.Shutdown()

	// Ensure the job count is 0
	assert.Equal(t, mgr.GetJobCount(), 0)

	// Add a job manually
	job := newLongPollOnceJob("job1", 5*time.Second)
	mgr.jobs["job1"] = job
	assert.Equal(t, mgr.GetJobCount(), 1)
}

// TestNewJob verifies that a job fails correctly after exceeding the maximum number of retry attempts
func TestNewJob(t *testing.T) {
	mockTimeOut := 1 * time.Second
	mockTaskDuration := 3 * mockTimeOut
	mockPoolSize := 1
	mockJobQueueCapacity := 1
	mockRetry := 10
	mockStaleJobCleanupInterval := 10 * time.Second

	mgr := NewLongPollOnceMgr(mockTimeOut, mockStaleJobCleanupInterval, mockPoolSize, mockJobQueueCapacity, mockRetry)
	defer mgr.Shutdown()
	mockTask := NewMockTask(taskResult, mockTaskDuration, nil)

	// Create a job that will fail and retry
	retryMaxJob, err := mgr.NewJob("retryMaxJob", &mockTask, nil)
	assert.Nil(t, err)
	assert.NotNil(t, retryMaxJob)
	assert.Equal(t, Pending, retryMaxJob.Status)

	// Simulate job failure and set retry count to maximum allowed
	retryMaxJob.Status = Retry
	retryMaxJob.RetryCount = mockRetry

	// Attempt to create the job again, expecting it to fail due to max retries reached
	retryMaxJob, err = mgr.NewJob("retryMaxJob", &mockTask, nil)
	assert.Nil(t, retryMaxJob)
	assert.Equal(t, errMaxRetryReached, err)
}

// TestNewJobWithJobQueueFull verifies that a job fails correctly when the job queue is full
func TestNewJobWithJobQueueFull(t *testing.T) {
	// Configuration
	mockTimeOut := 1 * time.Second
	mockTaskDuration := 5 * time.Second // Long enough to keep workers busy
	mockPoolSize := 1                   // Single worker to control execution
	mockJobQueueCapacity := 1           // Small queue capacity to fill easily
	mockRetry := 10
	mockStaleJobCleanupInterval := 10 * time.Second

	// Initialize the manager
	mgr := NewLongPollOnceMgr(mockTimeOut, mockStaleJobCleanupInterval, mockPoolSize, mockJobQueueCapacity, mockRetry)
	defer mgr.Shutdown()

	// Create a mock task that takes time to execute
	taskResult := "task completed"
	firstTask := NewMockTask(taskResult, mockTaskDuration, make(chan struct{}))
	secondTask := NewMockTask(taskResult, mockTaskDuration, nil)
	thirdTask := NewMockTask(taskResult, mockTaskDuration, nil)

	// Fill the worker pool (1 worker) with a long-running job
	firstJob, err := mgr.NewJob("firstJob", &firstTask, nil)
	assert.Nil(t, err)
	assert.NotNil(t, firstJob)
	assert.Equal(t, Pending, firstJob.Status)
	<-firstTask.started // wait for the job to start

	// Step 2: Fill the job queue (capacity = 1) with another job
	secondJob, err := mgr.NewJob("secondJob", &secondTask, nil)
	assert.Nil(t, err)
	assert.NotNil(t, secondJob)
	assert.Equal(t, Pending, secondJob.Status)

	// Step 4: Attempt to add a third job, which should fail due to a full queue
	thirdJob, err := mgr.NewJob("thirdJob", &thirdTask, nil)
	assert.Nil(t, thirdJob)
	assert.Equal(t, errTooManyJobs, err)

	// Verify the job count
	assert.Equal(t, 2, mgr.GetJobCount(), "Expected 2 jobs in the manager (1 running, 1 queued)")
}

// TestNewJobWithLargeScaleConcurrency tests the creation and processing of 1000 jobs concurrently to ensure scalability and thread safety.
func TestNewJobWithLargeScaleConcurrency(t *testing.T) {
	mockTimeOut := 1 * time.Second
	mockPoolSize := 32
	mockJobQueueCapacity := 1000
	mockRetry := 1
	mockStaleJobCleanupInterval := 5 * time.Second
	waitMockStaleJobCleanupInterval := 8 * time.Second

	mgr := NewLongPollOnceMgr(mockTimeOut, mockStaleJobCleanupInterval, mockPoolSize, mockJobQueueCapacity, mockRetry)
	defer mgr.Shutdown()

	var wg sync.WaitGroup
	for i := 0; i < mockJobQueueCapacity; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", index)

			mockTask := NewMockTask(taskResult, 100*time.Millisecond, nil)
			job, err := mgr.NewJob(key, &mockTask, nil)
			assert.Nil(t, err, "Unexpected error creating job %s: %v", key, err)
			assert.NotNil(t, job, "Expected job to be non-nil for key %s", key)
			assert.Equal(t, Pending, job.Status)

			result, _ := mgr.Poll(key)
			for result == nil {
				result, _ = mgr.Poll(key)
			}

			assert.Equal(t, result, taskResult, "Job result mismatch for key %s", key)

			// Wait for job processing to complete
			time.Sleep(mockTimeOut)
		}(i)
	}

	wg.Wait()

	// Wait for cleanup to occur
	time.Sleep(waitMockStaleJobCleanupInterval)
	assert.Equal(t, 0, mgr.GetJobCount(), "Expected all jobs to be cleaned up after concurrency test")
}

// TestJobQueueCapacityZero tests that when queue capacity is 0 and no workers are available,
// attempting to add a job should immediately return an error.
// We set poolSize to 0 to ensure no worker goroutines are listening on the channel,
// which guarantees that the select statement in scheduleJobToQueue will hit the default case.
func TestJobQueueCapacityZero(t *testing.T) {
	mockTimeOut := 1 * time.Second
	mockPoolSize := 0         // No workers to consume from the queue
	mockJobQueueCapacity := 0 // Zero capacity channel
	mockRetry := 1
	mockStaleJobCleanupInterval := 10 * time.Second

	mgr := NewLongPollOnceMgr(mockTimeOut, mockStaleJobCleanupInterval, mockPoolSize, mockJobQueueCapacity, mockRetry)
	defer mgr.Shutdown()

	mockTask := NewMockTask(taskResult, 100*time.Millisecond, nil)
	// Attempt to add a job should immediately return an error
	// because there's no buffer and no worker to receive
	job, err := mgr.NewJob("key1", &mockTask, nil)
	assert.Nil(t, job, "Expected no job to be created when queue capacity is zero and no workers")
	assert.Equal(t, errTooManyJobs, err, "Expected errTooManyJobs when queue capacity is zero and no workers")
}

// TestShutdownResourceCleanup verifies that Shutdown correctly cleans up all resources,
// closes the jobQueue, and ensures no goroutine leaks.
func TestShutdownResourceCleanup(t *testing.T) {
	initialGoroutines := runtime.NumGoroutine()
	mockTimeOut := 1 * time.Second
	mockPoolSize := 2
	mockJobQueueCapacity := 5
	mockRetry := 1
	mockStaleJobCleanupInterval := 10 * time.Second

	mgr := NewLongPollOnceMgr(mockTimeOut, mockStaleJobCleanupInterval, mockPoolSize, mockJobQueueCapacity, mockRetry)

	// Add some mock jobs to the queue
	mockTask := NewMockTask(taskResult, 100*time.Millisecond, nil)
	jobKeys := []string{"key1", "key2", "key3"}
	for _, key := range jobKeys {
		job, err := mgr.NewJob(key, &mockTask, nil)
		assert.Nil(t, err, "Unexpected error creating job %s: %v", key, err)
		assert.NotNil(t, job, "Expected job to be non-nil for key %s", key)
	}

	// Create a channel to signal when all jobs have been processed
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(len(jobKeys))

	// Launch goroutines to poll each job
	for _, key := range jobKeys {
		go func(k string) {
			defer wg.Done()
			result, err := mgr.Poll(k)
			assert.Equal(t, taskResult, result, "Job result mismatch for key %s", k)
			assert.Nil(t, err, "Unexpected error polling job %s: %v", k, err)
		}(key)
	}

	// Wait for all polling goroutines to finish
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All jobs have been processed
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for jobs to be processed")
	}

	// Verify that the job count is zero before shutdown
	assert.Equal(t, 0, mgr.GetJobCount(), "Expected job count to be zero after processing all jobs")

	// Shutdown the manager
	mgr.Shutdown()

	_, ok := <-mgr.jobQueue
	assert.False(t, ok, "Expected jobQueue to be closed after Shutdown")
	assert.Equal(t, 0, mgr.GetJobCount(), "Expected all jobs to be cleaned up after Shutdown")

	finalGoroutines := runtime.NumGoroutine()
	assert.Equal(t, finalGoroutines, initialGoroutines, "Goroutine leak detected after Shutdown")
}
