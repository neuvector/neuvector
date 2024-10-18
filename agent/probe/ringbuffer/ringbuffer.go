// THIS IS NOT CONCURRENT —— ONE GOROUTINE ONLY.
package ringbuffer

type Element interface{}
type RingBuffer struct {
	data []Element
	head int
	tail int
	size int
}

func New(capacity int) *RingBuffer {
	return &RingBuffer{
		data: make([]Element, capacity+1), // +1
		head: 0,
		tail: 0, // empty
		size: capacity + 1,
	}
}

func (r *RingBuffer) Write(value Element) {
	r.data[r.tail] = value
	r.tail = (r.tail + 1) % r.size
	if r.tail == r.head {
		r.head = (r.head + 1) % r.size // next
	}
}

func (r *RingBuffer) Read(i int) Element {
	if r.head == r.tail {
		return nil // Buffer is empty
	}
	return r.data[(r.head+i)%r.size]
}

func (r *RingBuffer) Length() int {
	if r.tail >= r.head {
		return r.tail - r.head
	}
	return r.tail + r.size - r.head
}

func (r *RingBuffer) Clear() {
	r.head, r.tail, r.size = 0, 0, 0
	clear(r.data)
}

func (r *RingBuffer) DumpExt() []Element {
	var elements []Element
	for i := 0; i < r.Length(); i++ {
		elements = append(elements, r.Read(i)) // starts from head
	}
	return elements
}
