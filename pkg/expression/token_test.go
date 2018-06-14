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
	"testing"
	"time"
)

func TestValueTypeOf(t *testing.T) {
	if ValueTypeOf("string") != ValueTypeString {
		t.Error("ValueTypeOf failure")
	}
	if ValueTypeOf(int8(8)) != ValueTypeSignedInt8 {
		t.Error("ValueTypeOf failure")
	}
	if ValueTypeOf(int16(8)) != ValueTypeSignedInt16 {
		t.Error("ValueTypeOf failure")
	}
	if ValueTypeOf(int32(8)) != ValueTypeSignedInt32 {
		t.Error("ValueTypeOf failure")
	}
	if ValueTypeOf(int64(8)) != ValueTypeSignedInt64 {
		t.Error("ValueTypeOf failure")
	}
	if ValueTypeOf(uint8(8)) != ValueTypeUnsignedInt8 {
		t.Error("ValueTypeOf failure")
	}
	if ValueTypeOf(uint16(8)) != ValueTypeUnsignedInt16 {
		t.Error("ValueTypeOf failure")
	}
	if ValueTypeOf(uint32(8)) != ValueTypeUnsignedInt32 {
		t.Error("ValueTypeOf failure")
	}
	if ValueTypeOf(uint64(8)) != ValueTypeUnsignedInt64 {
		t.Error("ValueTypeOf failure")
	}
	if ValueTypeOf(true) != ValueTypeBool {
		t.Error("ValueTypeOf failure")
	}
	if ValueTypeOf(8.8) != ValueTypeDouble {
		t.Error("ValueTypeOf failure")
	}
	if ValueTypeOf(time.Now()) != ValueTypeTimestamp {
		t.Error("ValueTypeOf failure")
	}

	// Obviously we cannot perform an exhaustive test of all types that
	// should map to ValueTypeUnspecified, but this will at least get us
	// coverage of that case.
	if ValueTypeOf(make(chan interface{})) != ValueTypeUnspecified {
		t.Error("ValueTypeOf failure")
	}
}

func TestValueTypeIsInteger(t *testing.T) {
	if ValueTypeUnspecified.IsInteger() {
		t.Error("ValueTypeUnspecified is not an integer")
	}
	if ValueTypeString.IsInteger() {
		t.Error("ValueTypeString is not an integer")
	}
	if !ValueTypeSignedInt8.IsInteger() {
		t.Error("ValueTypeSignedInt8 is an integer")
	}
	if !ValueTypeSignedInt16.IsInteger() {
		t.Error("ValueTypeSignedInt16 is an integer")
	}
	if !ValueTypeSignedInt32.IsInteger() {
		t.Error("ValueTypeSignedInt32 is an integer")
	}
	if !ValueTypeSignedInt64.IsInteger() {
		t.Error("ValueTypeSignedInt64 is an integer")
	}
	if !ValueTypeUnsignedInt8.IsInteger() {
		t.Error("ValueTypeUnsignedInt8 is an integer")
	}
	if !ValueTypeUnsignedInt16.IsInteger() {
		t.Error("ValueTypeUnsignedInt16 is an integer")
	}
	if !ValueTypeUnsignedInt32.IsInteger() {
		t.Error("ValueTypeUnsignedInt32 is an integer")
	}
	if !ValueTypeUnsignedInt64.IsInteger() {
		t.Error("ValueTypeUnsignedInt64 is an integer")
	}
	if ValueTypeBool.IsInteger() {
		t.Error("ValueTypeBool is not an integer")
	}
	if ValueTypeDouble.IsInteger() {
		t.Error("ValueTypeDouble is not an integer")
	}
	if ValueTypeTimestamp.IsInteger() {
		t.Error("ValueTypeTimestamp is not an integer")
	}
}

func TestValueTypeIsNumeric(t *testing.T) {
	if ValueTypeUnspecified.IsNumeric() {
		t.Error("ValueTypeUnspecified is not numeric")
	}
	if ValueTypeString.IsNumeric() {
		t.Error("ValueTypeString is not numeric")
	}
	if !ValueTypeSignedInt8.IsNumeric() {
		t.Error("ValueTypeSignedInt8 is numeric")
	}
	if !ValueTypeSignedInt16.IsNumeric() {
		t.Error("ValueTypeSignedInt16 is numeric")
	}
	if !ValueTypeSignedInt32.IsNumeric() {
		t.Error("ValueTypeSignedInt32 is numeric")
	}
	if !ValueTypeSignedInt64.IsNumeric() {
		t.Error("ValueTypeSignedInt64 is numeric")
	}
	if !ValueTypeUnsignedInt8.IsNumeric() {
		t.Error("ValueTypeUnsignedInt8 is numeric")
	}
	if !ValueTypeUnsignedInt16.IsNumeric() {
		t.Error("ValueTypeUnsignedInt16 is numeric")
	}
	if !ValueTypeUnsignedInt32.IsNumeric() {
		t.Error("ValueTypeUnsignedInt32 is numeric")
	}
	if !ValueTypeUnsignedInt64.IsNumeric() {
		t.Error("ValueTypeUnsignedInt64 is numeric")
	}
	if ValueTypeBool.IsNumeric() {
		t.Error("ValueTypeBool is not numeric")
	}
	if !ValueTypeDouble.IsNumeric() {
		t.Error("ValueTypeDouble is numeric")
	}
	if ValueTypeTimestamp.IsNumeric() {
		t.Error("ValueTypeTimestamp is not numeric")
	}
}
func TestValueTypeIsString(t *testing.T) {
	if ValueTypeUnspecified.IsNumeric() {
		t.Error("ValueTypeUnspecified is not a string")
	}
	if !ValueTypeString.IsString() {
		t.Error("ValueTypeString is a string")
	}
	if ValueTypeSignedInt8.IsString() {
		t.Error("ValueTypeSignedInt8 is not a string")
	}
	if ValueTypeSignedInt16.IsString() {
		t.Error("ValueTypeSignedInt16 is not a string")
	}
	if ValueTypeSignedInt32.IsString() {
		t.Error("ValueTypeSignedInt32 is not a string")
	}
	if ValueTypeSignedInt64.IsString() {
		t.Error("ValueTypeSignedInt64 is not a string")
	}
	if ValueTypeUnsignedInt8.IsString() {
		t.Error("ValueTypeUnsignedInt8 is not a string")
	}
	if ValueTypeUnsignedInt16.IsString() {
		t.Error("ValueTypeUnsignedInt16 is not a string")
	}
	if ValueTypeUnsignedInt32.IsString() {
		t.Error("ValueTypeUnsignedInt32 is not a string")
	}
	if ValueTypeUnsignedInt64.IsString() {
		t.Error("ValueTypeUnsignedInt64 is not a string")
	}
	if ValueTypeBool.IsString() {
		t.Error("ValueTypeBool is not a string")
	}
	if ValueTypeDouble.IsString() {
		t.Error("ValueTypeDouble is not a string")
	}
	if ValueTypeTimestamp.IsString() {
		t.Error("ValueTypeTimestamp is not a string")
	}
}
