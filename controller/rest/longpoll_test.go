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
}

// NewMockTask creates a new instance of MockTask with the given result and sleep duration.
// Parameters:
// - result: The result to return after the task is run.
// - sleepDuration: The duration to sleep to simulate work.
func NewMockTask(result interface{}, sleepDuration time.Duration) MockTask {
	return MockTask{
		result:        result,
		sleepDuration: sleepDuration,
	}
}

// Run executes the mock task.
// It sleeps for the duration specified in sleepDuration and then returns the predefined result.
// Parameters:
// - arg: An argument that can be used to influence the task's behavior (unused in this mock).
// Returns:
// - The predefined result after sleeping.
func (m *MockTask) Run(arg interface{}) (interface{}, *JobError) {
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
	err := errors.New("test error")
	detail := "some detail"
	jobError := NewJobError(404, err, detail)

	assert.Equal(t, 404, jobError.Code)
	assert.Equal(t, "test error", jobError.Message)
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

	mgr := NewLongPollOnceMgr(mockTimeOut, mockPoolSize, mockJobQueueCapacity, mockRetry, mockStaleJobCleanupInterval)
	defer mgr.Shutdown()

	mockTask := NewMockTask(taskResult, 100*time.Millisecond)
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

	mgr := NewLongPollOnceMgr(mockTimeOut, mockPoolSize, mockJobQueueCapacity, mockRetry, mockStaleJobCleanupInterval)
	defer mgr.Shutdown()

	// Ensure the job count is 0
	assert.Equal(t, mgr.GetJobCount(), 0)

	// Add a job manually
	job := newLongPollOnceJob("job1", 5*time.Second)
	mgr.jobs["job1"] = job
	assert.Equal(t, mgr.GetJobCount(), 1)
}

// TestNewJob verifies that a job fails correctly after exceeding the maximum number of retry attempts, and queeu capacity
func TestNewJob(t *testing.T) {
	mockTimeOut := 1 * time.Second
	mockPoolSize := 1
	mockJobQueueCapacity := 1
	mockRetry := 10
	mockStaleJobCleanupInterval := 10 * time.Second

	mgr := NewLongPollOnceMgr(mockTimeOut, mockPoolSize, mockJobQueueCapacity, mockRetry, mockStaleJobCleanupInterval)
	defer mgr.Shutdown()
	mockTask := NewMockTask(taskResult, 1*time.Second)

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

	// Create a job that will fail and retry
	time.Sleep(1 * time.Second) // wait for job to be done
	retryEnqueueFailJob, err := mgr.NewJob("retryEnqueueFail", &mockTask, nil)
	assert.Nil(t, err)
	assert.NotNil(t, retryEnqueueFailJob)
	assert.Equal(t, Pending, retryEnqueueFailJob.Status)

	// Fill the job queue by adding a dummy job
	dummyTask := NewMockTask(taskResult, 10*time.Second)
	dummyJob, err := mgr.NewJob("dummyJob", &dummyTask, nil)
	assert.Nil(t, err)
	assert.NotNil(t, dummyJob)
	assert.Equal(t, Pending, dummyJob.Status)

	// Simulate job failure and retry
	retryEnqueueFailJob.Status = Retry
	// Attempt to create the job again, expecting it to fail due to max retries reached
	retryEnqueueFailJob, err = mgr.NewJob("retryEnqueueFail", &mockTask, nil)
	assert.Nil(t, retryEnqueueFailJob)
	assert.Equal(t, errTooManyJobs, err)
}

// TestNewJobWithLargeScaleConcurrency tests the creation and processing of 1000 jobs concurrently to ensure scalability and thread safety.
func TestNewJobWithLargeScaleConcurrency(t *testing.T) {
	mockTimeOut := 1 * time.Second
	mockPoolSize := 32
	mockJobQueueCapacity := 1000
	mockRetry := 1
	mockStaleJobCleanupInterval := 5 * time.Second
	waitMockStaleJobCleanupInterval := 8 * time.Second

	mgr := NewLongPollOnceMgr(mockTimeOut, mockPoolSize, mockJobQueueCapacity, mockRetry, mockStaleJobCleanupInterval)
	defer mgr.Shutdown()

	var wg sync.WaitGroup
	for i := 0; i < mockJobQueueCapacity; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", index)

			mockTask := NewMockTask(taskResult, 100*time.Millisecond)
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

// TestNewJobWithLargeScaleConcurrency tests when capacity is 0, make sure we get fail
func TestJobQueueCapacityZero(t *testing.T) {
	mockTimeOut := 1 * time.Second
	mockPoolSize := 1
	mockJobQueueCapacity := 0
	mockRetry := 1
	mockStaleJobCleanupInterval := 10 * time.Second

	mgr := NewLongPollOnceMgr(mockTimeOut, mockPoolSize, mockJobQueueCapacity, mockRetry, mockStaleJobCleanupInterval)
	defer mgr.Shutdown()

	mockTask := NewMockTask(taskResult, 100*time.Millisecond)
	// Attempt to add a job should immediately return an error
	job, err := mgr.NewJob("key1", &mockTask, nil)
	assert.Nil(t, job, "Expected no job to be created when queue capacity is zero")
	assert.Equal(t, errTooManyJobs, err, "Expected errTooManyJobs when queue capacity is zero")
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

	mgr := NewLongPollOnceMgr(mockTimeOut, mockPoolSize, mockJobQueueCapacity, mockRetry, mockStaleJobCleanupInterval)

	// Add some mock jobs to the queue
	mockTask := NewMockTask(taskResult, 100*time.Millisecond)
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
