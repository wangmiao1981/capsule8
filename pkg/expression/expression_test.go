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

	api "github.com/capsule8/capsule8/api/v0"

	"github.com/golang/protobuf/ptypes/timestamp"
)

func TestExpressionStruct(t *testing.T) {
	if _, err := NewExpression(nil); err == nil {
		t.Error("NewExpression failure")
	}

	expr, err := NewExpression(Equal(Identifier("foo"), Value(uint8(8))))
	if err != nil {
		t.Errorf("NewExpression failure: %v", err)
		return
	}

	if s := expr.String(); s != "foo = 8" {
		t.Errorf("Expression.String failure; got %s", s)
	}
	if s := expr.KernelFilterString(); s != "foo == 8" {
		t.Errorf("Expression.KernelFilterString failure; got %s", s)
	}

	if err = expr.ValidateKernelFilter(); err != nil {
		t.Errorf("Expression.ValidateKernelFilter: %v", err)
	}

	types := FieldTypeMap{
		"foo": ValueTypeUnsignedInt8,
	}
	if err = expr.Validate(types); err != nil {
		t.Errorf("Expression.Validate: %v", err)
	}

	values := FieldValueMap{
		"foo": uint8(8),
	}
	result, err := expr.Evaluate(types, values)
	if err != nil {
		t.Errorf("Expression.Evaluate: %v", err)
	} else if !IsValueTrue(result) {
		t.Errorf("Expression.Evaluate: unexpected result: %v", result)
	}
}

func TestIsValueTrue(t *testing.T) {
	if IsValueTrue("") {
		t.Error("IsValueTrue failure")
	}
	if !IsValueTrue("string") {
		t.Error("IsValueTrue failure")
	}

	if IsValueTrue(int8(0)) {
		t.Error("IsValueTrue failure")
	}
	if !IsValueTrue(int8(8)) {
		t.Error("IsValueTrue failure")
	}

	if IsValueTrue(int16(0)) {
		t.Error("IsValueTrue failure")
	}
	if !IsValueTrue(int16(8)) {
		t.Error("IsValueTrue failure")
	}

	if IsValueTrue(int32(0)) {
		t.Error("IsValueTrue failure")
	}
	if !IsValueTrue(int32(8)) {
		t.Error("IsValueTrue failure")
	}

	if IsValueTrue(int64(0)) {
		t.Error("IsValueTrue failure")
	}
	if !IsValueTrue(int64(8)) {
		t.Error("IsValueTrue failure")
	}

	if IsValueTrue(uint8(0)) {
		t.Error("IsValueTrue failure")
	}
	if !IsValueTrue(uint8(8)) {
		t.Error("IsValueTrue failure")
	}

	if IsValueTrue(uint16(0)) {
		t.Error("IsValueTrue failure")
	}
	if !IsValueTrue(uint16(8)) {
		t.Error("IsValueTrue failure")
	}

	if IsValueTrue(uint32(0)) {
		t.Error("IsValueTrue failure")
	}
	if !IsValueTrue(uint32(8)) {
		t.Error("IsValueTrue failure")
	}

	if IsValueTrue(uint64(0)) {
		t.Error("IsValueTrue failure")
	}
	if !IsValueTrue(uint64(8)) {
		t.Error("IsValueTrue failure")
	}

	if IsValueTrue(false) {
		t.Error("IsValueTrue failure")
	}
	if !IsValueTrue(true) {
		t.Error("IsValueTrue failure")
	}

	if IsValueTrue(0.0) {
		t.Error("IsValueTrue failure")
	}
	if !IsValueTrue(8.0) {
		t.Error("IsValueTrue failure")
	}

	if IsValueTrue(time.Unix(0, 0)) {
		t.Error("IsValueTrue failure")
	}
	if !IsValueTrue(time.Now()) {
		t.Error("IsValueTrue failure")
	}

	if IsValueTrue(make(chan interface{})) {
		t.Error("IsValueTrue failure")
	}
}

func TestNewValue(t *testing.T) {
	var v *api.Value

	v = NewValue("string")
	if v.GetStringValue() != "string" {
		t.Error("NewValue failure")
	}

	v = NewValue(int8(8))
	if v.GetSignedValue() != 8 {
		t.Error("NewValue failure")
	}

	v = NewValue(int16(8))
	if v.GetSignedValue() != 8 {
		t.Error("NewValue failure")
	}

	v = NewValue(int32(8))
	if v.GetSignedValue() != 8 {
		t.Error("NewValue failure")
	}

	v = NewValue(int64(8))
	if v.GetSignedValue() != 8 {
		t.Error("NewValue failure")
	}

	v = NewValue(uint8(8))
	if v.GetUnsignedValue() != 8 {
		t.Error("NewValue failure")
	}

	v = NewValue(uint16(8))
	if v.GetUnsignedValue() != 8 {
		t.Error("NewValue failure")
	}

	v = NewValue(uint32(8))
	if v.GetUnsignedValue() != 8 {
		t.Error("NewValue failure")
	}

	v = NewValue(uint64(8))
	if v.GetUnsignedValue() != 8 {
		t.Error("NewValue failure")
	}

	v = NewValue(true)
	if v.GetBoolValue() != true {
		t.Error("NewValue failure")
	}

	v = NewValue(8.0)
	if v.GetDoubleValue() != 8.0 {
		t.Error("NewValue failure")
	}

	ts := &timestamp.Timestamp{
		Seconds: 8,
		Nanos:   8,
	}
	v = NewValue(ts)
	if ts = v.GetTimestampValue(); ts.Seconds != 8 || ts.Nanos != 8 {
		t.Error("NewValue failure")
	}

	if NewValue(make(chan interface{})) != nil {
		t.Error("NewValue failure")
	}
}

func TestExpressionNodes(t *testing.T) {
	var e *api.Expression

	e = Identifier("foo")
	if e.GetType() != api.Expression_IDENTIFIER || e.GetIdentifier() != "foo" {
		t.Error("Identifier failure")
	}

	e = Value("foo")
	if e.GetType() != api.Expression_VALUE || e.GetValue().GetStringValue() != "foo" {
		t.Error("Value failure")
	}

	// Unary ops

	e = IsNull(Identifier("foo"))
	if e.GetType() != api.Expression_IS_NULL {
		t.Error("IsNull failure")
	} else {
		e2 := e.GetUnaryOp()
		if e2.GetType() != api.Expression_IDENTIFIER || e2.GetIdentifier() != "foo" {
			t.Error("IsNull failure")
		}
	}

	e = IsNotNull(Identifier("foo"))
	if e.GetType() != api.Expression_IS_NOT_NULL {
		t.Error("IsNotNull failure")
	} else {
		e2 := e.GetUnaryOp()
		if e2.GetType() != api.Expression_IDENTIFIER || e2.GetIdentifier() != "foo" {
			t.Error("IsNotNull failure")
		}
	}

	// Binary ops

	i := Identifier("foo")
	v := Value("string")
	v2 := Value(int32(8))

	e = Equal(i, v)
	if e.GetType() != api.Expression_EQ {
		t.Error("Equal failure")
	} else {
		if e.GetBinaryOp().GetLhs() != i {
			t.Error("Equal failure")
		}
		if e.GetBinaryOp().GetRhs() != v {
			t.Error("Equal failure")
		}
	}

	e = NotEqual(i, v)
	if e.GetType() != api.Expression_NE {
		t.Error("NotEqual failure")
	} else {
		if e.GetBinaryOp().GetLhs() != i {
			t.Error("NotEqual failure")
		}
		if e.GetBinaryOp().GetRhs() != v {
			t.Error("NotEqual failure")
		}
	}

	e = LessThan(i, v2)
	if e.GetType() != api.Expression_LT {
		t.Error("LessThan failure")
	} else {
		if e.GetBinaryOp().GetLhs() != i {
			t.Error("LessThan failure")
		}
		if e.GetBinaryOp().GetRhs() != v2 {
			t.Error("LessThan failure")
		}
	}

	e = LessThanEqualTo(i, v2)
	if e.GetType() != api.Expression_LE {
		t.Error("LessThanEqualTo failure")
	} else {
		if e.GetBinaryOp().GetLhs() != i {
			t.Error("LessThanEqualTo failure")
		}
		if e.GetBinaryOp().GetRhs() != v2 {
			t.Error("LessThanEqualTo failure")
		}
	}

	e = GreaterThan(i, v2)
	if e.GetType() != api.Expression_GT {
		t.Error("GreaterThan failure")
	} else {
		if e.GetBinaryOp().GetLhs() != i {
			t.Error("GreaterThan failure")
		}
		if e.GetBinaryOp().GetRhs() != v2 {
			t.Error("GreaterThan failure")
		}
	}

	e = GreaterThanEqualTo(i, v2)
	if e.GetType() != api.Expression_GE {
		t.Error("GreaterThanEqualTo failure")
	} else {
		if e.GetBinaryOp().GetLhs() != i {
			t.Error("GreaterThanEqualTo failure")
		}
		if e.GetBinaryOp().GetRhs() != v2 {
			t.Error("GreaterThanEqualTo failure")
		}
	}

	e = Like(i, v)
	if e.GetType() != api.Expression_LIKE {
		t.Error("Like failure")
	} else {
		if e.GetBinaryOp().GetLhs() != i {
			t.Error("Like failure")
		}
		if e.GetBinaryOp().GetRhs() != v {
			t.Error("Like failure")
		}
	}

	e = BitwiseAnd(i, v2)
	if e.GetType() != api.Expression_BITWISE_AND {
		t.Error("BitwiseAnd failure")
	} else {
		if e.GetBinaryOp().GetLhs() != i {
			t.Error("BitwiseAnd failure")
		}
		if e.GetBinaryOp().GetRhs() != v2 {
			t.Error("BitwiseAnd failure")
		}
	}

	// Do LogicalAnd and LogicalOr last after we know that Equal works
	lhs := Equal(Identifier("foo"), Value(true))
	rhs := Equal(Identifier("bar"), Value(true))

	if LogicalAnd(lhs, nil) != lhs {
		t.Error("LogicalAnd failure")
	}
	if LogicalAnd(nil, rhs) != rhs {
		t.Error("LogicalAnd failure")
	}
	e = LogicalAnd(lhs, rhs)
	if e.GetType() != api.Expression_LOGICAL_AND {
		t.Error("LogicalAnd failure")
	} else {
		if e.GetBinaryOp().GetLhs() != lhs {
			t.Error("LogicalAnd failure")
		}
		if e.GetBinaryOp().GetRhs() != rhs {
			t.Error("LogicalAnd failure")
		}
	}

	if LogicalOr(lhs, nil) != lhs {
		t.Error("LogicalOr failure")
	}
	if LogicalOr(nil, rhs) != rhs {
		t.Error("LogicalOr failure")
	}
	e = LogicalOr(lhs, rhs)
	if e.GetType() != api.Expression_LOGICAL_OR {
		t.Error("LogicalOr failure")
	} else {
		if e.GetBinaryOp().GetLhs() != lhs {
			t.Error("LogicalOr failure")
		}
		if e.GetBinaryOp().GetRhs() != rhs {
			t.Error("LogicalOr failure")
		}
	}
}
