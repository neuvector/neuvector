// Copyright 2016 Russell Haering et al.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package saml2

import "github.com/russellhaering/gosaml2/types"

// Values is a convenience wrapper for a map of strings to Attributes, which
// can be used for easy access to the string values of Attribute lists.
type Values map[string]types.Attribute

// valueString returns the string form of an AttributeValue: the value of a
// nested NameID element if one is present (e.g. eduPersonTargetedID),
// otherwise the text content.
func valueString(v types.AttributeValue) string {
	if v.NameID != nil && v.NameID.Value != "" {
		return v.NameID.Value
	}
	return v.Value
}

// Get is a safe method (nil maps will not panic) for returning the first value
// for an attribute at a key, or the empty string if none exists.
func (vals Values) Get(k string) string {
	if vals == nil {
		return ""
	}
	if v, ok := vals[k]; ok && len(v.Values) > 0 {
		return valueString(v.Values[0])
	}
	return ""
}

//GetSize returns the number of values for an attribute at a key.
//Returns '0' in case of error or if key is not found.
func (vals Values) GetSize(k string) int {
	if vals == nil {
		return 0
	}

	v, ok := vals[k]
	if ok {
		return len(v.Values)
	}

	return 0
}

//GetAll returns all the values for an attribute at a key.
//Returns an empty slice in case of error of if key is not found.
func (vals Values) GetAll(k string) []string {
	var av []string

	if vals == nil {
		return av
	}

	if v, ok := vals[k]; ok && len(v.Values) > 0 {
		for i := 0; i < len(v.Values); i++ {
			av = append(av, valueString(v.Values[i]))
		}
	}

	return av
}
