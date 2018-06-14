// Copyright 2017 Capsule8, Inc.
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
	"reflect"
	"testing"
	"time"
)

type compareFunc func(lhs, rhs interface{}) bool

func compare(f compareFunc, lhs, rhs interface{}) (result bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(exprError); ok {
				err = e.error
			} else {
				panic(r)
			}
		}
	}()

	result = f(lhs, rhs)
	return
}

// This test tests all comparison functions except for compareLike
func TestSimpleComparisons(t *testing.T) {
	funcRefs := []compareFunc{
		compareEqual, compareNotEqual,
		compareLessThan, compareLessThanEqualTo,
		compareGreaterThan, compareGreaterThanEqualTo,
	}
	funcNames := []string{
		"compareEqual", "compareNotEqual",
		"compareLessThan", "compareLessThanEqualTo",
		"compareGreaterThan", "compareGreaterThanEqualTo",
	}

	invalidValue := make(chan interface{})

	lhs := []interface{}{
		"abc",
		int8(8), int16(8), int32(8), int64(8),
		uint8(8), uint16(8), uint32(8), uint64(8),
		true, 8.0, time.Unix(88888888, 88888888),
	}

	rhsTrue := [][]interface{}{
		// compareEqual
		lhs,
		// compareNotEqual
		[]interface{}{
			"xyz",
			int8(88), int16(88), int32(88), int64(88),
			uint8(88), uint16(88), uint32(88), uint64(88),
			false,
			88.0,
			time.Now(),
		},
		// compareLessThan
		[]interface{}{
			nil,
			int8(88), int16(88), int32(88), int64(88),
			uint(88), uint16(88), uint32(88), uint64(88),
			nil,
			88.0,
			time.Now(),
		},
		// compareLessThanEqualTo
		[]interface{}{
			nil,
			int8(8), int16(88), int32(8), int64(88),
			uint8(8), uint16(88), uint32(8), uint64(88),
			nil,
			8.0,
			time.Unix(88888888, 88888888),
		},
		// compareGreaterThan
		[]interface{}{
			nil,
			int8(0), int16(0), int32(0), int64(0),
			uint8(0), uint16(0), uint32(0), uint64(0),
			nil,
			0.0,
			time.Unix(0, 0),
		},
		// compareGreaterThanEqualTo
		[]interface{}{
			nil,
			int8(0), int16(8), int32(0), int64(8),
			uint8(0), uint16(8), uint32(0), uint64(8),
			nil,
			8.0,
			time.Unix(88888888, 88888888),
		},
	}
	rhsFalse := [][]interface{}{
		// compareEqual
		rhsTrue[1],
		// compareNotEqual
		rhsTrue[0],
		// compareLessThan
		rhsTrue[5],
		// compareLessThanEqualTo
		rhsTrue[4],
		// compareGreaterThan
		rhsTrue[3],
		// compareGreaterThanEqualTo
		rhsTrue[2],
	}

	for i, f := range funcRefs {
		name := funcNames[i]
		for j := range lhs {
			if v := rhsTrue[i][j]; reflect.ValueOf(v).Kind() != reflect.Invalid {
				if r, err := compare(f, lhs[j], v); err != nil {
					t.Errorf("Unexpected error for %s(%v, %v): %v",
						name, lhs[j], v, err)
				} else if !r {
					t.Errorf("Unexpected false for %s(%v, %v)",
						name, lhs[j], v)
				}
			} else {
				if _, err := compare(f, lhs[j], lhs[j]); err == nil {
					t.Errorf("Expected error for %s(%v, %v)",
						name, lhs[j], lhs[j])
				}
			}
			if v := rhsFalse[i][j]; reflect.ValueOf(v).Kind() != reflect.Invalid {
				if r, err := compare(f, lhs[j], v); err != nil {
					t.Errorf("Unexpected error for %s(%v, %v): %v",
						name, lhs[j], v, err)
				} else if r {
					t.Errorf("Unexpected true for %s(%v, %v)",
						name, lhs[j], v)
				}
			} else {
				if _, err := compare(f, lhs[j], lhs[j]); err == nil {
					t.Errorf("Expected error for %s(%v, %v)",
						name, lhs[j], lhs[j])
				}
			}
		}
		if _, err := compare(f, invalidValue, invalidValue); err == nil {
			t.Errorf("Expected error for %s with invalid type", name)
		}
	}
}

func TestCompareLike(t *testing.T) {
	// compareLike only works for strings. All other types should return
	// an error.

	lhs := "the quick brown fox jumped over the lazy dog"
	truePatterns := []string{
		"*lazy dog",
		"*brown fox*",
		"the quick brown fox*",
		"the quick brown fox jumped over the lazy dog",
	}
	falsePatterns := []string{
		"*the brown fox",
		"*aloof cat*",
		"the lazy dog*",
		"the lazy dog jumped over the quick brown fox",
	}

	for i := range truePatterns {
		tp := truePatterns[i]
		if r, err := compare(compareLike, lhs, tp); err != nil {
			t.Errorf("Unexpected error for compareLike(%q, %q): %v",
				lhs, tp, err)
		} else if !r {
			t.Errorf("Unexpected false for compareLike(%q, %q)",
				lhs, tp)
		}
		fp := falsePatterns[i]
		if r, err := compare(compareLike, lhs, fp); err != nil {
			t.Errorf("Unexpected error for compareLike(%q, %q): %v",
				lhs, fp, err)
		} else if r {
			t.Errorf("Unexpected true for compareLike(%q, %q)",
				lhs, fp)
		}
	}

	invalidValues := []interface{}{
		int8(8), int16(8), int32(8), int64(8),
		uint8(8), uint16(8), uint32(8), uint64(8),
		true,
		8.0,
		time.Now(),
		make(chan interface{}),
	}
	for _, v := range invalidValues {
		if _, err := compare(compareLike, v, v); err == nil {
			t.Errorf("Expected error for compareLike with invalid type %s",
				reflect.TypeOf(v))
		}
	}
}

func TestEvaluateExpression(t *testing.T) {
	types := FieldTypeMap{
		"s":   ValueTypeString,
		"i8":  ValueTypeSignedInt8,
		"i16": ValueTypeSignedInt16,
		"i32": ValueTypeSignedInt32,
		"i64": ValueTypeSignedInt64,
		"u8":  ValueTypeUnsignedInt8,
		"u16": ValueTypeUnsignedInt16,
		"u32": ValueTypeUnsignedInt32,
		"u64": ValueTypeUnsignedInt64,
		"b":   ValueTypeBool,
		"d":   ValueTypeDouble,
		"t":   ValueTypeTimestamp,
	}
	values := FieldValueMap{
		"s":   "string",
		"i8":  int8(8),
		"i16": int16(8),
		"i32": int32(8),
		"i64": int64(8),
		"u8":  uint8(8),
		"u16": uint16(8),
		"u32": uint32(8),
		"u64": uint64(8),
		"b":   true,
		//"d":   8.0,         << this is intentionally omitted! >>
		"t": "wrong type", // << this is intentionally the wrong type! >>
	}

	//
	// identExpr
	//

	ie := identExpr{name: "foo"}
	if _, err := evaluateExpression(ie, types, values); err == nil {
		t.Error("evaluateExpression failure")
	}

	ie = identExpr{name: "d"}
	if v, err := evaluateExpression(ie, types, values); err != nil {
		t.Errorf("evaluateExpression failure: %v", err)
	} else if v != nil {
		t.Errorf("evaluateExpression failure: got %v", v)
	}

	ie = identExpr{name: "t"}
	if _, err := evaluateExpression(ie, types, values); err == nil {
		t.Errorf("evaluateExpression failure")
	}

	ie = identExpr{name: "s"}
	if v, err := evaluateExpression(ie, types, values); err != nil {
		t.Errorf("evaluateExpression failure: %v", err)
	} else if v != "string" {
		t.Errorf("evaluateExpression failure: got %v", v)
	}

	//
	// valueExpr
	//

	ve := valueExpr{v: int32(8)}
	if v, err := evaluateExpression(ve, types, values); err != nil {
		t.Errorf("evaluateExpression failure: %v", err)
	} else if v != int32(8) {
		t.Errorf("evaluateExpression failure: got %v", v)
	}

	//
	// binaryExpr
	//

	logicalOps := []binaryOp{
		binaryOpLogicalAnd, binaryOpLogicalOr,
	}
	for _, op := range logicalOps {
		be := binaryExpr{
			x:  valueExpr{v: "string"},
			op: op,
		}
		if _, err := evaluateExpression(be, types, values); err == nil {
			t.Errorf("evaluateExpression failure for %s", binaryOpStrings[op])
		}
	}

	be := binaryExpr{
		x:  identExpr{name: "b"},
		y:  valueExpr{v: false},
		op: binaryOpLogicalAnd,
	}
	if r, err := evaluateExpression(be, types, values); err != nil {
		t.Errorf("evaluateExpression failure: %v", err)
	} else if v, ok := r.(bool); !ok {
		t.Errorf("evaluateExpression failure: expected false; got %v", r)
	} else if v != false {
		t.Errorf("evaluateExpression failure: expected false; got %v", r)
	}

	be = binaryExpr{
		x:  valueExpr{v: false},
		y:  identExpr{name: "b"},
		op: binaryOpLogicalOr,
	}
	if r, err := evaluateExpression(be, types, values); err != nil {
		t.Errorf("evaluateExpression failure: %v", err)
	} else if v, ok := r.(bool); !ok {
		t.Errorf("evaluateExpression failure: expected true; got %v", r)
	} else if v != true {
		t.Errorf("evaluateExpression failure: expected true; got %v", r)
	}

	binaryOps := map[binaryOp]bool{
		binaryOpEQ:   true,
		binaryOpNE:   false,
		binaryOpLT:   false,
		binaryOpLE:   true,
		binaryOpGT:   false,
		binaryOpGE:   true,
		binaryOpLike: false,
	}
	for op, expected := range binaryOps {
		be = binaryExpr{
			x:  identExpr{name: "d"},
			y:  valueExpr{v: 8.0},
			op: op,
		}
		// This should be false because: d IS NULL
		if r, err := evaluateExpression(be, types, values); err != nil {
			t.Errorf("evaluateExpression failure: %v", err)
		} else if v, ok := r.(bool); !ok {
			t.Errorf("evaluateExpression failure: expected false; got %v", r)
		} else if v != false {
			t.Errorf("evaluateExpression failure: expected false; got %v", r)
		}

		// This should generate a type mismatch error
		be = binaryExpr{
			x:  identExpr{name: "u64"},
			y:  valueExpr{v: "string"},
			op: op,
		}
		if _, err := evaluateExpression(be, types, values); err == nil {
			t.Errorf("evaluateExpression failure for %s (expected type mismatch error)",
				binaryOpStrings[op])
		}

		if op == binaryOpLike {
			be = binaryExpr{
				x:  identExpr{name: "s"},
				y:  valueExpr{v: "foobarbaz"},
				op: op,
			}
		} else {
			be = binaryExpr{
				x:  identExpr{name: "i16"},
				y:  valueExpr{v: int16(8)},
				op: op,
			}
		}
		if r, err := evaluateExpression(be, types, values); err != nil {
			t.Errorf("evaluateExpression failure for %s: %v",
				binaryOpStrings[op], err)
		} else if v, ok := r.(bool); !ok {
			t.Errorf("evaluateExpresion failure for %s: expected %v; got %v",
				binaryOpStrings[op], expected, r)
		} else if expected != v {
			t.Errorf("evaluateExpresion failure for %s: expected %v; got %v",
				binaryOpStrings[op], expected, r)
		}
	}

	be = binaryExpr{
		x:  identExpr{name: "i8"},
		y:  identExpr{name: "u8"},
		op: binaryOpBitwiseAnd,
	}
	// This should generate a type mismatch error
	if _, err := evaluateExpression(be, types, values); err == nil {
		t.Errorf("evaluateExpression failure (expected type mismatch error)")
	}

	be = binaryExpr{
		x:  identExpr{name: "s"},
		y:  valueExpr{v: "string"},
		op: binaryOpBitwiseAnd,
	}
	// This should generate an integer required error
	if _, err := evaluateExpression(be, types, values); err == nil {
		t.Errorf("evaluateExpression failure (expected type must be integer error)")
	}

	testCases := map[string]interface{}{
		"i8":  int8(8),
		"i16": int16(8),
		"i32": int32(8),
		"i64": int64(8),
		"u8":  uint8(8),
		"u16": uint16(8),
		"u32": uint32(8),
		"u64": uint64(8),
	}
	for name, value := range testCases {
		be = binaryExpr{
			x:  identExpr{name: name},
			y:  valueExpr{v: value},
			op: binaryOpBitwiseAnd,
		}
		if r, err := evaluateExpression(be, types, values); err != nil {
			t.Errorf("evaluateExpression failure for %s: %v",
				reflect.TypeOf(value), err)
		} else if !reflect.DeepEqual(r, value) {
			t.Errorf("evaluateExpression failure for %s: want %v; got %v",
				reflect.TypeOf(value), value, r)
		}
	}

	//
	// unaryExpr
	//

	ue := unaryExpr{
		x:  identExpr{name: "s"},
		op: unaryOpIsNull,
	}
	if r, err := evaluateExpression(ue, types, values); err != nil {
		t.Errorf("evaluateExpression failure: %v", err)
	} else if v, ok := r.(bool); !ok {
		t.Errorf("evaluateExpression failure: expected false; got %v", r)
	} else if v != false {
		t.Errorf("evaluateExpression failure: expected false; got %v", r)
	}
	ue.op = unaryOpIsNotNull
	if r, err := evaluateExpression(ue, types, values); err != nil {
		t.Errorf("evaluateExpression failure: %v", err)
	} else if v, ok := r.(bool); !ok {
		t.Errorf("evaluateExpression failure: expected true; got %v", r)
	} else if v != true {
		t.Errorf("evaluateExpression failure: expected true; got %v", r)
	}

	ue = unaryExpr{
		x:  identExpr{name: "d"},
		op: unaryOpIsNull,
	}
	if r, err := evaluateExpression(ue, types, values); err != nil {
		t.Errorf("evaluateExpression failure: %v", err)
	} else if v, ok := r.(bool); !ok {
		t.Errorf("evaluateExpression failure: expected true; got %v", r)
	} else if v != true {
		t.Errorf("evaluateExpression failure: expected true; got %v", r)
	}
	ue.op = unaryOpIsNotNull
	if r, err := evaluateExpression(ue, types, values); err != nil {
		t.Errorf("evaluateExpression failure: %v", err)
	} else if v, ok := r.(bool); !ok {
		t.Errorf("evaluateExpression failure: expected false; got %v", r)
	} else if v != false {
		t.Errorf("evaluateExpression failure: expected false; got %v", r)
	}
}

func TestEvaluateBadStackPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("evalContext.evaluateExpression did not panic as expected")
		}
	}()

	// This should leave the stack with three elements instead of just 1
	// since the initialization is creating a stack of len 2 initially.
	c := evalContext{
		stack: make([]interface{}, 2),
	}
	c.evaluateExpression(valueExpr{v: "string"})
}

func TestEvaluateNodePanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("evalContext.evaluateNode did not panic as expected")
		}
	}()

	c := evalContext{}
	c.evaluateNode(invalidExpr{})
}

func TestEvaluateBinaryExprPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("evalContext.evaluateUnaryExpr did not panic as expected")
		}
	}()

	c := evalContext{}
	c.evaluateBinaryExpr(binaryExpr{op: 239487})
}

func TestEvaluateUnaryExprPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("evalContext.evaluateUnaryExpr did not panic as expected")
		}
	}()

	c := evalContext{}
	c.evaluateUnaryExpr(unaryExpr{op: 239487})
}
