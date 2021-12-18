// package ringbuffer implements a sequential compact FIFO and LILO. Also called a Queue.
// To Use:
//          type myThing ringbuffer.RingElement
//          var whatever == myThing("whatever") // Assuming a conversion from string.
//          rb := RingBuffer.New(40)
//          rb.Write(myThing) // Et cetera
//          aThing := rb.Read()
//          for 0 < rb.Size() {
//              doSomethingWith(rb.Read())
//          }
//
//  THIS IS NOT CONCURRENT —— ONE GOROUTINE ONLY.
package ringbuffer

import (
	"fmt"
)

// A ring buffer is stored in an array of ringbuffer.RingElement, of the size requested.
type RingElement interface{}

type RingBuffer struct {
	data    []RingElement
	in, out int // Place of next in (Write). Place of next out (Read).  These are subscripts.
	size    int // Number of items currenly in the ring buffer.
}

type RingBufferError struct {
	What string
}

// "Convert" ringbuffer.RingBufferError into a string.
func (e *RingBufferError) Error() string {
	return e.What
}

///// Inspect the internal state of the ring buffer and complain if not ok. ////
var invNum int // invNum is an error code.

// New() allocates and initializes a new ring buffer of specified size
func New(n int) *RingBuffer {
	b := &RingBuffer{data: make([]RingElement, n), // Contents
		in: 0, out: 0, size: 0}
	return b
}

// next() does a 'wrapping increment' of a subscript to point to the next element.
func (b *RingBuffer) next(subscript int) int {
	subscript++
	if subscript >= cap(b.data) { // I suspect this is quicker than a modulus calculation.
		subscript = 0
	}
	return subscript
}

// Write inserts an element into the ring buffer.
func (b *RingBuffer) Write(datum RingElement) error {
	if b.size >= cap(b.data) {
		//fmt.Printf("!Full b %p, size %d, cap %d\n", b, b.size, cap(b.data))
		// JW: return &RingBufferError{"RingBuffer is full"}
		b.Read() // JW: dump the oldest element
	}

	b.data[b.in] = datum
	b.in = b.next(b.in)
	b.size++
	if 0 >= b.size {
		fmt.Printf("\n\tError: b.size %d, b %p, cap(b.data) %d\n", b.size, b, cap(b.data))
	}

	return nil
}

// Read fetches the next element from the ring buffer.
func (b *RingBuffer) Read() RingElement {
	if 0 >= b.size {
		return nil // Nil is our EOF.  Could use an error return, too.
		//return &RingBufferError{"RingBuffer is empty\n"}
	}
	b.size--
	tmp := b.data[b.out]
	b.out = b.next(b.out)
	return tmp
}

// Number of slots currently in use.  Total writes - Total reads.
func (b *RingBuffer) Leng() int {
	return b.size
}

// Is the buffer currently full?
func (b *RingBuffer) Full() bool {
	if nil == b {
		return true // best we can do? Even Possible?
	}
	return (nil != b.data) &&
		(b.size >= cap(b.data))
}

// Any left to read?
func (b *RingBuffer) HasAny() bool {
	return b.size > 0
}

// Obliterate, Purge, and Remove the contents of the ring buffer.
// Support your local Garbage Collector!
func (b *RingBuffer) Clear() {
	b.in, b.out, b.size = 0, 0, 0
	for i := 0; i < len(b.data); i++ { // Remove dangling references to avoid leaks.
		b.data[i] = nil
	}
	b.data = nil // Let GC collect the array.
}
