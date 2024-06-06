package k8slock

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/pointer"

	coordinationv1 "k8s.io/api/coordination/v1"
	coordinationclientv1 "k8s.io/client-go/kubernetes/typed/coordination/v1"
)

// Locker implements the Locker interface using the kubernetes Lease resource
type Locker struct {
	clientset         *kubernetes.Clientset
	leaseClient       coordinationclientv1.LeaseInterface
	namespace         string
	name              string
	clientID          string
	retryWait         time.Duration
	ttl               time.Duration
	skipLeaseCreation bool
}

type option func(*Locker)

// Namespace is the namespace used to store the Lease
func Namespace(ns string) func(*Locker) {
	return func(l *Locker) {
		l.namespace = ns
	}
}

// InClusterConfig configures the Kubernetes client assuming it is running inside a pod
func InClusterConfig() func(*Locker) {
	return func(l *Locker) {
		c, err := inClusterClientset()
		if err != nil {
			panic(fmt.Sprintf("could not create config: %v", err))
		}
		l.clientset = c
	}
}

// Clientset configures a custom Kubernetes Clientset
func Clientset(c *kubernetes.Clientset) func(*Locker) {
	return func(l *Locker) {
		l.clientset = c
	}
}

// RetryWaitDuration is the duration the Lock function will wait before retrying
// after failing to acquire the lock
func RetryWaitDuration(d time.Duration) func(*Locker) {
	return func(l *Locker) {
		l.retryWait = d
	}
}

// ClientID is a unique ID for the client acquiring the lock
func ClientID(id string) func(*Locker) {
	return func(l *Locker) {
		l.clientID = id
	}
}

// TTL is the duration a lock can exist before it can be forcibly acquired
// by another client
func TTL(ttl time.Duration) func(*Locker) {
	return func(l *Locker) {
		l.ttl = ttl
	}
}

// CreateLease specifies whether to create lease when it's absent.
func CreateLease(create bool) func(*Locker) {
	return func(l *Locker) {
		l.skipLeaseCreation = !create
	}
}

// NewLocker creates a Locker
func NewLocker(name string, options ...option) (*Locker, error) {
	locker := &Locker{
		name: name,
	}

	for _, opt := range options {
		opt(locker)
	}

	if locker.namespace == "" {
		locker.namespace = "default"
	}

	if locker.clientID == "" {
		locker.clientID = uuid.New().String()
	}

	if locker.retryWait == 0 {
		locker.retryWait = time.Duration(1) * time.Second
	}

	if locker.clientset == nil {
		c, err := localClientset()
		if err != nil {
			return nil, err
		}
		locker.clientset = c
	}

	leaseClient := locker.clientset.CoordinationV1().Leases(locker.namespace)

	if !locker.skipLeaseCreation {
		// create the Lease if it doesn't exist
		_, err := leaseClient.Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			if !k8serrors.IsNotFound(err) {
				return nil, err
			}

			lease := &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{
					Name: name,
				},
				Spec: coordinationv1.LeaseSpec{
					LeaseTransitions: pointer.Int32Ptr(0),
				},
			}

			_, err := leaseClient.Create(context.TODO(), lease, metav1.CreateOptions{})
			if err != nil {
				return nil, err
			}
		}
	}

	locker.leaseClient = leaseClient
	return locker, nil
}

// Lock will block until the client is the holder of the Lease resource
func (l *Locker) Lock() {
	// block until we get a lock
	for {
		// get the Lease
		lease, err := l.leaseClient.Get(context.TODO(), l.name, metav1.GetOptions{})
		if err != nil {
			panic(fmt.Sprintf("could not get Lease resource for lock: %v", err))
		}

		if lease.Spec.HolderIdentity != nil {
			if lease.Spec.LeaseDurationSeconds == nil {
				// The lock is already held and has no expiry
				time.Sleep(l.retryWait)
				continue
			}

			acquireTime := lease.Spec.AcquireTime.Time
			leaseDuration := time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second

			if acquireTime.Add(leaseDuration).After(time.Now()) {
				// The lock is already held and hasn't expired yet
				time.Sleep(l.retryWait)
				continue
			}
		}

		// nobody holds the lock, try and lock it
		lease.Spec.HolderIdentity = pointer.StringPtr(l.clientID)
		if lease.Spec.LeaseTransitions != nil {
			lease.Spec.LeaseTransitions = pointer.Int32Ptr((*lease.Spec.LeaseTransitions) + 1)
		} else {
			lease.Spec.LeaseTransitions = pointer.Int32Ptr((*lease.Spec.LeaseTransitions) + 1)
		}
		lease.Spec.AcquireTime = &metav1.MicroTime{time.Now()}
		if l.ttl.Seconds() > 0 {
			lease.Spec.LeaseDurationSeconds = pointer.Int32Ptr(int32(l.ttl.Seconds()))
		}
		_, err = l.leaseClient.Update(context.TODO(), lease, metav1.UpdateOptions{})
		if err == nil {
			// we got the lock, break the loop
			break
		}

		if !k8serrors.IsConflict(err) {
			// if the error isn't a conflict then something went horribly wrong
			panic(fmt.Sprintf("lock: error when trying to update Lease: %v", err))
		}

		// Another client beat us to the lock
		time.Sleep(l.retryWait)
	}
}

// Unlock will remove the client as the holder of the Lease resource
func (l *Locker) Unlock() {
	lease, err := l.leaseClient.Get(context.TODO(), l.name, metav1.GetOptions{})
	if err != nil {
		panic(fmt.Sprintf("could not get Lease resource for lock: %v", err))
	}

	// the holder has to have a value and has to be our ID for us to be able to unlock
	if lease.Spec.HolderIdentity == nil {
		panic("unlock: no lock holder value")
	}

	if *lease.Spec.HolderIdentity != l.clientID {
		panic("unlock: not the lock holder")
	}

	lease.Spec.HolderIdentity = nil
	lease.Spec.AcquireTime = nil
	lease.Spec.LeaseDurationSeconds = nil
	_, err = l.leaseClient.Update(context.TODO(), lease, metav1.UpdateOptions{})
	if err != nil {
		panic(fmt.Sprintf("unlock: error when trying to update Lease: %v", err))
	}
}

func localClientset() (*kubernetes.Clientset, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{}
	config, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, err
	}

	if config == nil {
		config = &rest.Config{}
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

func inClusterClientset() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}
