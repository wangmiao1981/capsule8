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
	"fmt"
	"testing"
	"time"
)

func TestValueExprStringPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("valueExpr.String did not panic as expected")
		}
	}()
	valueExpr{v: make(chan interface{})}.String()
}

func TestBinaryExprStringPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("binaryExpr.String did not panic as expected")
		}
	}()
	binaryExpr{op: 397485}.String()
}

func TestBinaryExprKernelStringPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("binaryExpr.KernelString did not panic as expected")
		}
	}()
	binaryExpr{op: 9238745}.KernelString()
}

func TestUnaryExprStringPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("unaryExpr.String did not panic as expected")
		}
	}()
	unaryExpr{op: 234987}.String()
}

func TestValueExpressionString(t *testing.T) {
	if v := (valueExpr{v: "string"}); v.String() != "\"string\"" {
		t.Errorf("valueExpr.String() failure")
	}
	if v := (valueExpr{v: int8(8)}); v.String() != "8" {
		t.Errorf("valueExpr.String() failure")
	}
	if v := (valueExpr{v: int16(8)}); v.String() != "8" {
		t.Errorf("valueExpr.String() failure")
	}
	if v := (valueExpr{v: int32(8)}); v.String() != "8" {
		t.Errorf("valueExpr.String() failure")
	}
	if v := (valueExpr{v: int64(8)}); v.String() != "8" {
		t.Errorf("valueExpr.String() failure")
	}
	if v := (valueExpr{v: uint8(8)}); v.String() != "8" {
		t.Errorf("valueExpr.String() failure")
	}
	if v := (valueExpr{v: uint16(8)}); v.String() != "8" {
		t.Errorf("valueExpr.String() failure")
	}
	if v := (valueExpr{v: uint32(8)}); v.String() != "8" {
		t.Errorf("valueExpr.String() failure")
	}
	if v := (valueExpr{v: uint64(8)}); v.String() != "8" {
		t.Errorf("valueExpr.String() failure")
	}
	if v := (valueExpr{v: true}); v.String() != "TRUE" {
		t.Errorf("valueExpr.String() failure")
	}
	if v := (valueExpr{v: false}); v.String() != "FALSE" {
		t.Errorf("valueExpr.String() failure")
	}
	if v := (valueExpr{v: 8.0}); v.String() != fmt.Sprintf("%f", 8.0) {
		t.Errorf("valueExpr.String() failure")
	}
	now := time.Now()
	if v := (valueExpr{v: now}); v.String() != fmt.Sprintf("TIMESTAMP(%d)", now.UnixNano()) {
		t.Errorf("valueExpr.String() failure")
	}
}

func TestValueExprIsInteger(t *testing.T) {
	if v := (valueExpr{v: make(chan interface{})}); v.isInteger() {
		t.Errorf("valueExpr.isInteger() failure")
	}
	if v := (valueExpr{v: "string"}); v.isInteger() {
		t.Errorf("valueExpr.isInteger() failure")
	}
	if v := (valueExpr{v: int8(8)}); !v.isInteger() {
		t.Errorf("valueExpr.isInteger() failure")
	}
	if v := (valueExpr{v: int16(8)}); !v.isInteger() {
		t.Errorf("valueExpr.isInteger() failure")
	}
	if v := (valueExpr{v: int32(8)}); !v.isInteger() {
		t.Errorf("valueExpr.isInteger() failure")
	}
	if v := (valueExpr{v: int64(8)}); !v.isInteger() {
		t.Errorf("valueExpr.isInteger() failure")
	}
	if v := (valueExpr{v: uint8(8)}); !v.isInteger() {
		t.Errorf("valueExpr.isInteger() failure")
	}
	if v := (valueExpr{v: uint16(8)}); !v.isInteger() {
		t.Errorf("valueExpr.isInteger() failure")
	}
	if v := (valueExpr{v: uint32(8)}); !v.isInteger() {
		t.Errorf("valueExpr.isInteger() failure")
	}
	if v := (valueExpr{v: uint64(8)}); !v.isInteger() {
		t.Errorf("valueExpr.isInteger() failure")
	}
	if v := (valueExpr{v: true}); v.isInteger() {
		t.Errorf("valueExpr.isInteger() failure")
	}
	if v := (valueExpr{v: 8.0}); v.isInteger() {
		t.Errorf("valueExpr.isInteger() failure")
	}
	if v := (valueExpr{v: time.Now()}); v.isInteger() {
		t.Errorf("valueExpr.isInteger() failure")
	}
}

func TestValueExprIsNumeric(t *testing.T) {
	if v := (valueExpr{v: make(chan interface{})}); v.isNumeric() {
		t.Errorf("valueExpr.isNumeric() failure")
	}
	if v := (valueExpr{v: "string"}); v.isNumeric() {
		t.Errorf("valueExpr.isNumeric() failure")
	}
	if v := (valueExpr{v: int8(8)}); !v.isNumeric() {
		t.Errorf("valueExpr.isNumeric() failure")
	}
	if v := (valueExpr{v: int16(8)}); !v.isNumeric() {
		t.Errorf("valueExpr.isNumeric() failure")
	}
	if v := (valueExpr{v: int32(8)}); !v.isNumeric() {
		t.Errorf("valueExpr.isNumeric() failure")
	}
	if v := (valueExpr{v: int64(8)}); !v.isNumeric() {
		t.Errorf("valueExpr.isNumeric() failure")
	}
	if v := (valueExpr{v: uint8(8)}); !v.isNumeric() {
		t.Errorf("valueExpr.isNumeric() failure")
	}
	if v := (valueExpr{v: uint16(8)}); !v.isNumeric() {
		t.Errorf("valueExpr.isNumeric() failure")
	}
	if v := (valueExpr{v: uint32(8)}); !v.isNumeric() {
		t.Errorf("valueExpr.isNumeric() failure")
	}
	if v := (valueExpr{v: uint64(8)}); !v.isNumeric() {
		t.Errorf("valueExpr.isNumeric() failure")
	}
	if v := (valueExpr{v: true}); v.isNumeric() {
		t.Errorf("valueExpr.isNumeric() failure")
	}
	if v := (valueExpr{v: 8.0}); !v.isNumeric() {
		t.Errorf("valueExpr.isNumeric() failure")
	}
	if v := (valueExpr{v: time.Now()}); !v.isNumeric() {
		t.Errorf("valueExpr.isNumeric() failure")
	}
}

func TestValueExprIsString(t *testing.T) {
	if v := (valueExpr{v: make(chan interface{})}); v.isString() {
		t.Errorf("valueExpr.isString() failure")
	}
	if v := (valueExpr{v: "string"}); !v.isString() {
		t.Errorf("valueExpr.isString() failure")
	}
	if v := (valueExpr{v: int8(8)}); v.isString() {
		t.Errorf("valueExpr.isString() failure")
	}
	if v := (valueExpr{v: int16(8)}); v.isString() {
		t.Errorf("valueExpr.isString() failure")
	}
	if v := (valueExpr{v: int32(8)}); v.isString() {
		t.Errorf("valueExpr.isString() failure")
	}
	if v := (valueExpr{v: int64(8)}); v.isString() {
		t.Errorf("valueExpr.isString() failure")
	}
	if v := (valueExpr{v: uint8(8)}); v.isString() {
		t.Errorf("valueExpr.isString() failure")
	}
	if v := (valueExpr{v: uint16(8)}); v.isString() {
		t.Errorf("valueExpr.isString() failure")
	}
	if v := (valueExpr{v: uint32(8)}); v.isString() {
		t.Errorf("valueExpr.isString() failure")
	}
	if v := (valueExpr{v: uint64(8)}); v.isString() {
		t.Errorf("valueExpr.isString() failure")
	}
	if v := (valueExpr{v: true}); v.isString() {
		t.Errorf("valueExpr.isString() failure")
	}
	if v := (valueExpr{v: 8.0}); v.isString() {
		t.Errorf("valueExpr.isString() failure")
	}
	if v := (valueExpr{v: time.Now()}); v.isString() {
		t.Errorf("valueExpr.isString() failure")
	}
}

func TestBinaryExprIsValid(t *testing.T) {
	binaryOps := []binaryOp{
		binaryOpLogicalAnd, binaryOpLogicalOr,
		binaryOpEQ, binaryOpNE, binaryOpLT, binaryOpLE,
		binaryOpGT, binaryOpGE, binaryOpLike,
		binaryOpBitwiseAnd,
	}

	for _, op := range binaryOps {
		be := binaryExpr{op: op}
		if !be.isValid() {
			t.Errorf("isValid failure for binary op %s",
				binaryOpStrings[op])
		}
	}

	be := binaryExpr{op: 29384675}
	if be.isValid() {
		t.Error("isValid failure for invalid op")
	}
}

func TestBinaryExprString(t *testing.T) {
	be := binaryExpr{
		x: identExpr{name: "foo"},
		y: valueExpr{v: int32(8)},
	}
	binaryOps := map[binaryOp][]string{
		binaryOpEQ: []string{"foo = 8", "foo == 8"},
		binaryOpNE: []string{"foo != 8", "foo != 8"},
		binaryOpLT: []string{"foo < 8", "foo < 8"},
		binaryOpLE: []string{"foo <= 8", "foo <= 8"},
		binaryOpGT: []string{"foo > 8", "foo > 8"},
		binaryOpGE: []string{"foo >= 8", "foo >= 8"},
	}
	for op, expectations := range binaryOps {
		be.op = op
		if s := be.String(); s != expectations[0] {
			t.Errorf("binaryExpr.String failure (want %q; got %q)",
				expectations[0], s)
		}
		if s := be.KernelString(); s != expectations[1] {
			t.Errorf("binaryExpr.KernelString failure (want %q; got %q)",
				expectations[1], s)
		}
	}

	be.op = binaryOpLike
	be.y = valueExpr{v: "string"}
	expect := "foo LIKE \"string\""
	if s := be.String(); s != expect {
		t.Errorf("binaryExpr.String failure (want %q; got %q)", expect, s)
	}
	expect = "foo ~ \"string\""
	if s := be.KernelString(); s != expect {
		t.Errorf("binaryExpr.String failure (want %q; got %q)", expect, s)
	}

	logicalOps := map[binaryOp][]string{
		binaryOpLogicalAnd: []string{
			"foo = 8 AND bar = 8", "foo == 8 && bar == 8",
			"foo = 8 AND bar = 8 AND baz = 8", "foo == 8 && bar == 8 && baz == 8",
			"foo = 8 AND (bar = 8 AND baz = 8)", "foo == 8 && (bar == 8 && baz == 8)",
		},
		binaryOpLogicalOr: []string{
			"foo = 8 OR bar = 8", "foo == 8 || bar == 8",
			"foo = 8 OR bar = 8 OR baz = 8", "foo == 8 || bar == 8 || baz == 8",
			"foo = 8 OR (bar = 8 OR baz = 8)", "foo == 8 || (bar == 8 || baz == 8)",
		},
	}
	logical1 := binaryExpr{
		op: binaryOpEQ,
		x:  identExpr{name: "foo"},
		y:  valueExpr{v: int32(8)},
	}
	logical2 := binaryExpr{
		op: binaryOpEQ,
		x:  identExpr{name: "bar"},
		y:  valueExpr{v: int64(8)},
	}
	logical3 := binaryExpr{
		op: binaryOpEQ,
		x:  identExpr{name: "baz"},
		y:  valueExpr{v: uint32(8)},
	}
	for op, expectations := range logicalOps {
		be = binaryExpr{
			op: op,
			x:  logical1,
			y:  logical2,
		}
		if s := be.String(); s != expectations[0] {
			t.Errorf("binaryExpr.String failure (want %q; got %q)",
				expectations[0], s)
		}
		if s := be.KernelString(); s != expectations[1] {
			t.Errorf("binaryExpr.KernelString failure (want %q; got %q)",
				expectations[1], s)
		}

		be = binaryExpr{
			op: op,
			x: binaryExpr{
				op: op,
				x:  logical1,
				y:  logical2,
			},
			y: logical3,
		}
		if s := be.String(); s != expectations[2] {
			t.Errorf("binaryExpr.String failure (want %q; got %q)",
				expectations[2], s)
		}
		if s := be.KernelString(); s != expectations[3] {
			t.Errorf("binaryExpr.KernelString failure (want %q; got %q)",
				expectations[3], s)
		}

		be = binaryExpr{
			op: op,
			x:  logical1,
			y: binaryExpr{
				op: op,
				x:  logical2,
				y:  logical3,
			},
		}
		if s := be.String(); s != expectations[4] {
			t.Errorf("binaryExpr.String failure (want %q; got %q)",
				expectations[4], s)
		}
		if s := be.KernelString(); s != expectations[5] {
			t.Errorf("binaryExpr.KernelString failure (want %q; got %q)",
				expectations[5], s)
		}
	}

	be = binaryExpr{
		op: binaryOpNE,
		x: binaryExpr{
			op: binaryOpBitwiseAnd,
			x:  identExpr{name: "foo"},
			y:  valueExpr{v: uint32(0x8888)},
		},
		y: valueExpr{v: uint32(0)},
	}
	expect = "foo & 34952 != 0"
	if s := be.String(); s != expect {
		t.Errorf("binaryExpr.String failure (want %q; got %q)", expect, s)
	}
	expect = "foo & 34952"
	if s := be.KernelString(); s != expect {
		t.Errorf("binaryExpr.KernelString failure (want %q; got %q)", expect, s)
	}
}

func TestUnaryExprString(t *testing.T) {
	unaryOps := map[unaryOp]string{
		unaryOpIsNull:    "foo IS NULL",
		unaryOpIsNotNull: "foo IS NOT NULL",
	}
	for op, want := range unaryOps {
		ue := unaryExpr{
			op: op,
			x:  identExpr{name: "foo"},
		}
		if s := ue.String(); s != want {
			t.Errorf("unaryExpr.String failure (want %q; got %q)", want, s)
		}
		if s := ue.KernelString(); s != "" {
			t.Errorf("unaryExpr.KernelString failure (want \"\" got %q)", s)
		}
	}
}
