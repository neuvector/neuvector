/*
Open Source Initiative OSI - The MIT License (MIT):Licensing

The MIT License (MIT)
Copyright (c) 2013 Ralph Caraveo (deckarep@gmail.com)

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package utils

import (
	"fmt"
	"reflect"
	"strings"
)

type Set interface {
	// Adds an element to the set. Returns whether
	// the item was added.
	Add(i interface{}) bool

	// Returns the number of elements in the set.
	Cardinality() int

	// Removes all elements from the set, leaving
	// the emtpy set.
	Clear()

	// Returns a clone of the set using the same
	// implementation, duplicating all keys.
	Clone() Set

	// Returns whether the given items
	// are all in the set.
	Contains(i ...interface{}) bool

	// Returns the difference between this set
	// and other. The returned set will contain
	// all elements of this set that are not also
	// elements of other.
	//
	// Note that the argument to Difference
	// must be of the same type as the receiver
	// of the method. Otherwise, Difference will
	// panic.
	Difference(other Set) Set

	// Determines if two sets are equal to each
	// other. If they have the same cardinality
	// and contain the same elements, they are
	// considered equal. The order in which
	// the elements were added is irrelevant.
	//
	// Note that the argument to Equal must be
	// of the same type as the receiver of the
	// method. Otherwise, Equal will panic.
	Equal(other Set) bool

	// Returns a new set containing only the elements
	// that exist only in both sets.
	//
	// Note that the argument to Intersect
	// must be of the same type as the receiver
	// of the method. Otherwise, Intersect will
	// panic.
	Intersect(other Set) Set

	// Determines if every element in the other set
	// is in this set.
	//
	// Note that the argument to IsSubset
	// must be of the same type as the receiver
	// of the method. Otherwise, IsSubset will
	// panic.
	IsSubset(other Set) bool

	// Determines if every element in this set is in
	// the other set.
	//
	// Note that the argument to IsSuperset
	// must be of the same type as the receiver
	// of the method. Otherwise, IsSuperset will
	// panic.
	IsSuperset(other Set) bool

	// Returns a channel of elements that you can
	// range over.
	Iter() threadUnsafeSet

	// Remove a single element from the set.
	Remove(i interface{})

	// Provides a convenient string representation
	// of the current state of the set.
	String() string

	// Returns a new set with all elements which are
	// in either this set or the other set but not in both.
	//
	// Note that the argument to SymmetricDifference
	// must be of the same type as the receiver
	// of the method. Otherwise, SymmetricDifference
	// will panic.
	SymmetricDifference(other Set) Set

	// Returns a new set with all elements in both sets.
	//
	// Note that the argument to Union must be of the
	// same type as the receiver of the method.
	// Otherwise, IsSuperset will panic.
	Union(other Set) Set

	// Returns the members of the set as a slice.
	ToSlice() []interface{}
	ToInt32Slice() []int32
	ToStringSlice() []string

	// Returns one member of the set.
	Any() interface{}
}

func NewSet(s ...interface{}) Set {
	set := newThreadUnsafeSet()
	for _, item := range s {
		set.Add(item)
	}
	return &set
}

func NewSetFromSliceKind(slice interface{}) Set {
	s := reflect.ValueOf(slice)
	if s.Kind() != reflect.Slice {
		return nil
	}

	a := newThreadUnsafeSet()
	for i := 0; i < s.Len(); i++ {
		a.Add(s.Index(i).Interface())
	}

	return &a
}

func NewSetFromStringSlice(stringSlice []string) Set {
	interfaceSlice := make([]interface{}, len(stringSlice))
	for i := range stringSlice {
		interfaceSlice[i] = stringSlice[i]
	}
	return NewSetFromSlice(interfaceSlice)
}

func NewSetFromSlice(s []interface{}) Set {
	a := newThreadUnsafeSet()
	for _, item := range s {
		a.Add(item)
	}
	return &a
}

type threadUnsafeSet map[interface{}]struct{}

/*
type orderedPair struct {
	first  interface{}
	second interface{}
}
*/

func newThreadUnsafeSet() threadUnsafeSet {
	return make(threadUnsafeSet)
}

/*
func (pair *orderedPair) Equal(other orderedPair) bool {
	if pair.first == other.first &&
		pair.second == other.second {
		return true
	}

	return false
}
*/

func (set *threadUnsafeSet) Add(i interface{}) bool {
	_, found := (*set)[i]
	(*set)[i] = struct{}{}
	return !found //False if it existed already
}

func (set *threadUnsafeSet) Contains(i ...interface{}) bool {
	for _, val := range i {
		if _, ok := (*set)[val]; !ok {
			return false
		}
	}
	return true
}

func (set *threadUnsafeSet) IsSubset(other Set) bool {
	_ = other.(*threadUnsafeSet)
	for elem := range *set {
		if !other.Contains(elem) {
			return false
		}
	}
	return true
}

func (set *threadUnsafeSet) IsSuperset(other Set) bool {
	return other.IsSubset(set)
}

func (set *threadUnsafeSet) Union(other Set) Set {
	o := other.(*threadUnsafeSet)

	unionedSet := newThreadUnsafeSet()

	for elem := range *set {
		unionedSet.Add(elem)
	}
	for elem := range *o {
		unionedSet.Add(elem)
	}
	return &unionedSet
}

func (set *threadUnsafeSet) Intersect(other Set) Set {
	o := other.(*threadUnsafeSet)

	intersection := newThreadUnsafeSet()
	// loop over smaller set
	if set.Cardinality() < other.Cardinality() {
		for elem := range *set {
			if other.Contains(elem) {
				intersection.Add(elem)
			}
		}
	} else {
		for elem := range *o {
			if set.Contains(elem) {
				intersection.Add(elem)
			}
		}
	}
	return &intersection
}

func (set *threadUnsafeSet) Difference(other Set) Set {
	_ = other.(*threadUnsafeSet)

	difference := newThreadUnsafeSet()
	for elem := range *set {
		if !other.Contains(elem) {
			difference.Add(elem)
		}
	}
	return &difference
}

func (set *threadUnsafeSet) SymmetricDifference(other Set) Set {
	_ = other.(*threadUnsafeSet)

	aDiff := set.Difference(other)
	bDiff := other.Difference(set)
	return aDiff.Union(bDiff)
}

func (set *threadUnsafeSet) Clear() {
	*set = newThreadUnsafeSet()
}

func (set *threadUnsafeSet) Remove(i interface{}) {
	delete(*set, i)
}

func (set *threadUnsafeSet) Cardinality() int {
	return len(*set)
}

func (set *threadUnsafeSet) Iter() threadUnsafeSet {
	return *set
}

func (set *threadUnsafeSet) Equal(other Set) bool {
	_ = other.(*threadUnsafeSet)

	if set.Cardinality() != other.Cardinality() {
		return false
	}
	for elem := range *set {
		if !other.Contains(elem) {
			return false
		}
	}
	return true
}

func (set *threadUnsafeSet) Clone() Set {
	clonedSet := newThreadUnsafeSet()
	for elem := range *set {
		clonedSet.Add(elem)
	}
	return &clonedSet
}

func (set *threadUnsafeSet) String() string {
	items := make([]string, 0, len(*set))

	for elem := range *set {
		items = append(items, fmt.Sprintf("%v", elem))
	}
	return fmt.Sprintf("{%s}", strings.Join(items, ", "))
}

/*
	func (pair orderedPair) String() string {
		return fmt.Sprintf("(%v, %v)", pair.first, pair.second)
	}
*/

func (set *threadUnsafeSet) ToSlice() []interface{} {
	keys := make([]interface{}, 0, set.Cardinality())
	for elem := range *set {
		keys = append(keys, elem)
	}

	return keys
}

func (set *threadUnsafeSet) ToInt32Slice() []int32 {
	keys := make([]int32, 0, set.Cardinality())
	for elem := range *set {
		if e, ok := elem.(int32); ok {
			keys = append(keys, e)
		} else if e, ok := elem.(int); ok {
			keys = append(keys, int32(e))
		}
	}

	return keys
}

func (set *threadUnsafeSet) ToStringSlice() []string {
	keys := make([]string, 0, set.Cardinality())
	for elem := range *set {
		if e, ok := elem.(string); ok {
			keys = append(keys, e)
		}
	}

	return keys
}

func (set *threadUnsafeSet) Any() interface{} {
	for elem := range *set {
		return elem
	}
	return nil
}
