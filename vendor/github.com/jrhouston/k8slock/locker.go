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
	clientset         kubernetes.Interface
	leaseClient       coordinationclientv1.LeaseInterface
	namespace         string
	name              string
	clientID          string
	retryWait         time.Duration
	ttl               time.Duration
	skipLeaseCreation bool
}

type lockerOption func(*Locker) error

// Namespace is the namespace used to store the Lease
func Namespace(ns string) lockerOption {
	return func(l *Locker) error {
		l.namespace = ns
		return nil
	}
}

// InClusterConfig configures the Kubernetes client assuming it is running inside a pod
func InClusterConfig() lockerOption {
	return func(l *Locker) error {
		c, err := inClusterClientset()
		if err != nil {
			return err
		}
		l.clientset = c
		return nil
	}
}

// Clientset configures a custom Kubernetes Clientset
func Clientset(c kubernetes.Interface) lockerOption {
	return func(l *Locker) error {
		l.clientset = c
		return nil
	}
}

// RetryWaitDuration is the duration the Lock function will wait before retrying
// after failing to acquire the lock
func RetryWaitDuration(d time.Duration) lockerOption {
	return func(l *Locker) error {
		l.retryWait = d
		return nil
	}
}

// ClientID is a unique ID for the client acquiring the lock
func ClientID(id string) lockerOption {
	return func(l *Locker) error {
		l.clientID = id
		return nil
	}
}

// TTL is the duration a lock can exist before it can be forcibly acquired
// by another client
func TTL(ttl time.Duration) lockerOption {
	return func(l *Locker) error {
		l.ttl = ttl
		return nil
	}
}

// CreateLease specifies whether to create lease when it's absent.
func CreateLease(create bool) lockerOption {
	return func(l *Locker) error {
		l.skipLeaseCreation = !create
		return nil
	}
}

// NewLocker creates a Locker
func NewLocker(name string, options ...lockerOption) (*Locker, error) {
	locker := &Locker{
		name: name,
	}

	for _, opt := range options {
		err := opt(locker)
		if err != nil {
			return nil, fmt.Errorf("locker options: %v", err)
		}
	}

	if locker.namespace == "" {
		locker.namespace = "default"
	}

	if locker.clientID == "" {
		locker.clientID = uuid.NewString()
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
					LeaseTransitions: pointer.Int32(0),
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

func (l *Locker) lock(ctx context.Context) error {
	// block until we get a lock
	for {
		// get the Lease
		lease, err := l.leaseClient.Get(ctx, l.name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("could not get Lease resource for lock: %w", err)
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
		lease.Spec.HolderIdentity = pointer.String(l.clientID)
		if lease.Spec.LeaseTransitions != nil {
			lease.Spec.LeaseTransitions = pointer.Int32((*lease.Spec.LeaseTransitions) + 1)
		} else {
			lease.Spec.LeaseTransitions = pointer.Int32((*lease.Spec.LeaseTransitions) + 1)
		}
		lease.Spec.AcquireTime = &metav1.MicroTime{
			Time: time.Now(),
		}
		if l.ttl.Seconds() > 0 {
			lease.Spec.LeaseDurationSeconds = pointer.Int32(int32(l.ttl.Seconds()))
		}
		_, err = l.leaseClient.Update(ctx, lease, metav1.UpdateOptions{})
		if err == nil {
			// we got the lock, break the loop
			break
		}

		if !k8serrors.IsConflict(err) {
			// if the error isn't a conflict then something went horribly wrong
			return fmt.Errorf("lock: error when trying to update Lease: %w", err)
		}

		// Another client beat us to the lock
		time.Sleep(l.retryWait)
	}

	return nil
}

func (l *Locker) unlock(ctx context.Context) error {
	lease, err := l.leaseClient.Get(ctx, l.name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("could not get Lease resource for lock: %w", err)
	}

	// the holder has to have a value and has to be our ID for us to be able to unlock
	if lease.Spec.HolderIdentity == nil {
		return fmt.Errorf("unlock: no lock holder value")
	}

	if *lease.Spec.HolderIdentity != l.clientID {
		return fmt.Errorf("unlock: not the lock holder (%v != %v)", *lease.Spec.HolderIdentity, l.clientID)
	}

	lease.Spec.HolderIdentity = nil
	lease.Spec.AcquireTime = nil
	lease.Spec.LeaseDurationSeconds = nil
	_, err = l.leaseClient.Update(ctx, lease, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("unlock: error when trying to update Lease: %w", err)
	}

	return nil
}

// Lock will block until the client is the holder of the Lease resource
func (l *Locker) Lock() {
	err := l.lock(context.Background())
	if err != nil {
		panic(err)
	}
}

// Unlock will remove the client as the holder of the Lease resource
func (l *Locker) Unlock() {
	err := l.unlock(context.Background())
	if err != nil {
		panic(err)
	}
}

// LockContext will block until the client is the holder of the Lease resource
func (l *Locker) LockContext(ctx context.Context) error {
	return l.lock(ctx)
}

// UnlockContext will remove the client as the holder of the Lease resource
func (l *Locker) UnlockContext(ctx context.Context) error {
	return l.unlock(ctx)
}

func localClientset() (kubernetes.Interface, error) {
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

func inClusterClientset() (kubernetes.Interface, error) {
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
