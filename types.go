// Copyright 2014 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pdf

import (
	"bytes"
	"io"
	"io/ioutil"
	"sort"
)

// Kind represents the kind of value stored in an Object.
type Kind int

const (
	Null Kind = iota
	Bool
	Integer
	Real
	String
	Name
	Dict
	Array
	Stream
	Indirect // Reference: 1 0 R; renamed from Ptr to avoid collision with Ptr struct
	Keyword  // Internal: obj, endobj, etc.
)

// Object represents a PDF object using a tagged union approach to avoid interface{} boxing.
type Object struct {
	Kind         Kind
	BoolVal      bool
	Int64Val     int64
	Float64Val   float64
	NameVal      string
	StringVal    string
	KeywordVal   string
	ArrayVal     []Object
	DictVal      map[string]Object
	PtrVal       objptr
	StreamOffset int64 // For Stream, DictVal holds the header
}

// Internal types
type objptr struct {
	id  uint32
	gen uint16
}

type objdef struct {
	ptr objptr
	obj Object
}

// A Value represents a value in a PDF file.
type Value struct {
	r   *Reader // the reader, for resolving references
	ptr objptr  // the pointer to the object, if any
	obj Object  // the actual data
	err error   // if non-nil, the error that occurred during resolution or access
}

// Err returns the error associated with the value, if any.
func (v Value) Err() error {
	return v.err
}

// Kind returns the kind of value v is.
func (v Value) Kind() Kind {
	if v.err != nil {
		return Null
	}
	return v.obj.Kind
}

// IsNull reports whether v is a null value.
func (v Value) IsNull() bool {
	return v.Kind() == Null
}

// Bool returns v's boolean value.
func (v Value) Bool() bool {
	if v.err != nil {
		return false
	}
	return v.obj.BoolVal
}

// Int64 returns v's integer value.
func (v Value) Int64() int64 {
	if v.err != nil {
		return 0
	}
	if v.obj.Kind == Integer {
		return v.obj.Int64Val
	}
	if v.obj.Kind == Real {
		return int64(v.obj.Float64Val)
	}
	return 0
}

// Float64 returns v's float value.
func (v Value) Float64() float64 {
	if v.err != nil {
		return 0
	}
	if v.obj.Kind == Real {
		return v.obj.Float64Val
	}
	if v.obj.Kind == Integer {
		return float64(v.obj.Int64Val)
	}
	return 0
}

// RawString returns v's string value.
func (v Value) RawString() string {
	if v.err != nil {
		return ""
	}
	return v.obj.StringVal
}

// String returns a textual representation of the value v.
func (v Value) String() string {
	if v.err != nil {
		return ""
	}
	return objfmt(v.obj)
}

// Text returns v's string value interpreted as a “text string” (defined in the PDF spec)
// and converted to UTF-8.
func (v Value) Text() string {
	if v.err != nil {
		return ""
	}
	s := v.obj.StringVal
	if isPDFDocEncoded(s) {
		return pdfDocDecode(s)
	}
	if isUTF16(s) {
		return utf16Decode(s[2:])
	}
	return s
}

// Reader returns a reader for the stream v.
func (v Value) Reader() io.ReadCloser {
	if v.err != nil {
		return &errorReadCloser{v.err}
	}
	if v.obj.Kind == Stream {
		return newStreamReader(v.obj, v.r)
	}
	return ioutil.NopCloser(bytes.NewReader(nil))
}

// Data returns the raw data of the stream v.
func (v Value) Data() []byte {
	if v.err != nil {
		return nil
	}
	if v.obj.Kind == Stream {
		data, _ := io.ReadAll(newStreamReader(v.obj, v.r))
		return data
	}
	return nil
}

// Ptr represents a PDF Object Reference (Indirect Object)
// This is the public API struct.
type Ptr struct {
	id  uint32
	gen uint16
}

// NewPtr returns a reference to the object with the given number and generation.
func NewPtr(id uint32, gen uint16) Ptr {
	return Ptr{id: id, gen: gen}
}

// GetID returns the object number.
func (p Ptr) GetID() uint32 {
	return p.id
}

// GetGen returns the generation number.
func (p Ptr) GetGen() uint16 {
	return p.gen
}

// Name returns v's name value.
func (v Value) Name() string {
	if v.err != nil {
		return ""
	}
	return v.obj.NameVal
}

// Len returns the number of elements in the array v.
func (v Value) Len() int {
	if v.err != nil {
		return 0
	}
	if v.obj.Kind == Array {
		return len(v.obj.ArrayVal)
	}
	return 0
}

// Index returns the i'th element of the array v.
func (v Value) Index(i int) Value {
	if v.err != nil {
		return Value{err: v.err}
	}
	if v.obj.Kind != Array {
		return Value{}
	}
	a := v.obj.ArrayVal
	if i < 0 || i >= len(a) {
		return Value{}
	}
	return v.r.resolve(v.ptr, a[i])
}

// Keys returns the keys of the dictionary v, sorted alphabetically.
func (v Value) Keys() []string {
	if v.err != nil {
		return nil
	}
	var keys []string
	if v.obj.Kind == Dict || v.obj.Kind == Stream {
		for k := range v.obj.DictVal {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// Key returns the value associated with the key k in the dictionary v.
func (v Value) Key(key string) Value {
	if v.err != nil {
		return Value{err: v.err}
	}
	if v.obj.Kind == Dict || v.obj.Kind == Stream {
		if val, ok := v.obj.DictVal[key]; ok {
			return v.r.resolve(v.ptr, val)
		}
	}
	return Value{}
}

// GetPtr returns the object reference for the value.
func (v Value) GetPtr() Ptr {
	return Ptr{id: v.ptr.id, gen: v.ptr.gen}
}

// Header returns the header dictionary for the stream v.
func (v Value) Header() Value {
	if v.err != nil {
		return Value{err: v.err}
	}
	if v.obj.Kind == Stream {
		// Create a Value for the header (which is a Dict)
		hdrObj := Object{
			Kind:    Dict,
			DictVal: v.obj.DictVal,
		}
		return v.r.createValue(objptr{}, hdrObj)
	}
	return Value{}
}
