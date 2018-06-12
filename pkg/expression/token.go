// Copyright 2018 Capsule8, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package expression

import (
	"time"
)

// ValueType represents the type of a value in an expression
type ValueType int

const (
	// ValueTypeUnspecified is an unspecified type
	ValueTypeUnspecified ValueType = iota

	// ValueTypeString is a string
	ValueTypeString

	// ValueTypeSignedInt8 is a signed 8-bit integer
	ValueTypeSignedInt8
	// ValueTypeSignedInt16 is a signed 16-bit integer
	ValueTypeSignedInt16
	// ValueTypeSignedInt32 is a signed 32-bit integer
	ValueTypeSignedInt32
	// ValueTypeSignedInt64 is a signed 64-bit integer
	ValueTypeSignedInt64
	// ValueTypeUnsignedInt8 is an unisnged 8-bit integer
	ValueTypeUnsignedInt8
	// ValueTypeUnsignedInt16 is an unsigned 16-bit integer
	ValueTypeUnsignedInt16
	// ValueTypeUnsignedInt32 is an unsigned 32-bit integer
	ValueTypeUnsignedInt32
	// ValueTypeUnsignedInt64 is an unsigned 64-bit integer
	ValueTypeUnsignedInt64

	// ValueTypeBool is a bool
	ValueTypeBool
	// ValueTypeDouble is a 64-bit floating point
	ValueTypeDouble
	// ValueTypeTimestamp is a timestamp with nanosecond granularity
	ValueTypeTimestamp
)

// ValueTypeStrings is a mapping of value type constants to human-readble string
// representations
var ValueTypeStrings = map[ValueType]string{
	ValueTypeUnspecified:   "<<invalid>>",
	ValueTypeString:        "string",
	ValueTypeSignedInt8:    "int8",
	ValueTypeSignedInt16:   "int16",
	ValueTypeSignedInt32:   "int32",
	ValueTypeSignedInt64:   "int64",
	ValueTypeUnsignedInt8:  "uint8",
	ValueTypeUnsignedInt16: "uint16",
	ValueTypeUnsignedInt32: "uint32",
	ValueTypeUnsignedInt64: "uint64",
	ValueTypeBool:          "bool",
	ValueTypeDouble:        "float64",
	ValueTypeTimestamp:     "uint64",
}

// ValueTypeOf returns the value type of a value
func ValueTypeOf(i interface{}) ValueType {
	switch i.(type) {
	case string:
		return ValueTypeString
	case int8:
		return ValueTypeSignedInt8
	case int16:
		return ValueTypeSignedInt16
	case int32:
		return ValueTypeSignedInt32
	case int64:
		return ValueTypeSignedInt64
	case uint8:
		return ValueTypeUnsignedInt8
	case uint16:
		return ValueTypeUnsignedInt16
	case uint32:
		return ValueTypeUnsignedInt32
	case uint64:
		return ValueTypeUnsignedInt64
	case bool:
		return ValueTypeBool
	case float64:
		return ValueTypeDouble
	case time.Time:
		return ValueTypeTimestamp
	}
	return ValueTypeUnspecified
}

// IsInteger returns true if the specified ValueType represents an integer
// type.
func (t ValueType) IsInteger() bool {
	switch t {
	case ValueTypeSignedInt8, ValueTypeSignedInt16, ValueTypeSignedInt32,
		ValueTypeSignedInt64, ValueTypeUnsignedInt8,
		ValueTypeUnsignedInt16, ValueTypeUnsignedInt32,
		ValueTypeUnsignedInt64:
		return true
	}
	return false
}

// IsNumeric returns true if the specified ValueType represents a numeric type
// type (integer or double)
func (t ValueType) IsNumeric() bool {
	switch t {
	case ValueTypeSignedInt8, ValueTypeSignedInt16, ValueTypeSignedInt32,
		ValueTypeSignedInt64, ValueTypeUnsignedInt8,
		ValueTypeUnsignedInt16, ValueTypeUnsignedInt32,
		ValueTypeUnsignedInt64, ValueTypeDouble:
		return true
	}
	return false
}

// IsString returns true if the specified ValueType represents a string type.
func (t ValueType) IsString() bool {
	return t == ValueTypeString
}

type binaryOp int

const (
	binaryOpInvalid binaryOp = iota

	binaryOpLogicalAnd
	binaryOpLogicalOr

	binaryOpEQ
	binaryOpNE
	binaryOpLT
	binaryOpLE
	binaryOpGT
	binaryOpGE
	binaryOpLike

	binaryOpBitwiseAnd
)

var binaryOpStrings = map[binaryOp]string{
	binaryOpLogicalAnd: "AND",
	binaryOpLogicalOr:  "OR",
	binaryOpEQ:         "=",
	binaryOpNE:         "!=",
	binaryOpLT:         "<",
	binaryOpLE:         "<=",
	binaryOpGT:         ">",
	binaryOpGE:         ">=",
	binaryOpLike:       "LIKE",
	binaryOpBitwiseAnd: "&",
}

var binaryOpKernelStrings = map[binaryOp]string{
	binaryOpLogicalAnd: "&&",
	binaryOpLogicalOr:  "||",
	binaryOpEQ:         "==",
	binaryOpNE:         "!=",
	binaryOpLT:         "<",
	binaryOpLE:         "<=",
	binaryOpGT:         ">",
	binaryOpGE:         ">=",
	binaryOpLike:       "~",
	binaryOpBitwiseAnd: "&",
}

type unaryOp int

const (
	unaryOpInvalid unaryOp = iota

	unaryOpIsNull
	unaryOpIsNotNull
)

var unaryOpStrings = map[unaryOp]string{
	unaryOpIsNull:    "IS NULL",
	unaryOpIsNotNull: "IS NOT NULL",
}
