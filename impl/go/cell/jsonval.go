// SPDX-FileCopyrightText: 2026 Enthropic Data LLC
// SPDX-License-Identifier: Apache-2.0

package cell

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// Value is a parsed JSON value: nil, bool, float64, string, []Value or *Object.
//
// Go's map[string]any loses key order, and v1.0/v1.1 cells hash their header as
// JSON.stringify wrote it — in insertion order, not sorted (spec §12). A cell in
// those versions parsed into a map can therefore never be re-serialized to the
// bytes it was signed over. Hence an ordered object type rather than a map.
type Value any

// Object is a JSON object that remembers the order its keys arrived in.
type Object struct {
	keys   []string
	values map[string]Value
}

// NewObject returns an empty ordered object.
func NewObject() *Object {
	return &Object{values: map[string]Value{}}
}

// Set appends a key (or replaces its value, keeping the original position).
func (o *Object) Set(key string, value Value) {
	if _, exists := o.values[key]; !exists {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

// Get returns the value for key and whether it was present.
func (o *Object) Get(key string) (Value, bool) {
	if o == nil {
		return nil, false
	}
	v, ok := o.values[key]
	return v, ok
}

// GetObject returns a nested object, or nil if absent or not an object.
func (o *Object) GetObject(key string) *Object {
	v, _ := o.Get(key)
	nested, _ := v.(*Object)
	return nested
}

// GetString returns a string field, or "" if absent or not a string.
func (o *Object) GetString(key string) string {
	v, _ := o.Get(key)
	s, _ := v.(string)
	return s
}

// GetArray returns an array field, or nil if absent or not an array.
func (o *Object) GetArray(key string) []Value {
	v, _ := o.Get(key)
	a, _ := v.([]Value)
	return a
}

// GetInt returns an integer field, or fallback if absent or not a number.
func (o *Object) GetInt(key string, fallback int) int {
	v, _ := o.Get(key)
	f, ok := v.(float64)
	if !ok {
		return fallback
	}
	return int(f)
}

// Delete removes a key. Used only by tests that build tampered cells.
func (o *Object) Delete(key string) {
	if _, ok := o.values[key]; !ok {
		return
	}
	delete(o.values, key)
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

// Keys returns the keys in insertion order.
func (o *Object) Keys() []string {
	if o == nil {
		return nil
	}
	return o.keys
}

// Has reports whether key is present, distinguishing an explicit null from an
// absent key — a distinction §6.4 makes load-bearing for share_index.
func (o *Object) Has(key string) bool {
	if o == nil {
		return false
	}
	_, ok := o.values[key]
	return ok
}

// ParseValue decodes JSON while preserving object key order.
func ParseValue(data []byte) (Value, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := parseValue(decoder)
	if err != nil {
		return nil, err
	}
	// Reject trailing content rather than silently ignoring it: a cell with a
	// second document appended is not a cell.
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data after JSON document", ErrMalformed)
	}
	return value, nil
}

func parseValue(decoder *json.Decoder) (Value, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return parseFromToken(decoder, token)
}

func parseFromToken(decoder *json.Decoder, token json.Token) (Value, error) {
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			object := NewObject()
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("%w: object key is not a string", ErrMalformed)
				}
				value, err := parseValue(decoder)
				if err != nil {
					return nil, err
				}
				object.Set(key, value)
			}
			if _, err := decoder.Token(); err != nil { // consume '}'
				return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
			}
			return object, nil
		case '[':
			array := []Value{}
			for decoder.More() {
				value, err := parseValue(decoder)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			if _, err := decoder.Token(); err != nil { // consume ']'
				return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
			}
			return array, nil
		}
		return nil, fmt.Errorf("%w: unexpected delimiter %v", ErrMalformed, t)
	case json.Number:
		// Every JSON number is a float64 to JavaScript, and the canonical form
		// is defined by what JavaScript prints. Converting here means a literal
		// of "1.0" and one of "1" produce identical canonical bytes, exactly as
		// JSON.parse followed by JSON.stringify would.
		f, err := t.Float64()
		if err != nil {
			return nil, fmt.Errorf("%w: number %q is not representable", ErrMalformed, t.String())
		}
		return f, nil
	default:
		return t, nil // string, bool, or nil
	}
}
