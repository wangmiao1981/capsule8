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
	"testing"
)

type invalidExpr struct{}

func (e invalidExpr) exprNode() {}
func (e invalidExpr) String() string {
	return "<<invalidExpr String>>"
}
func (e invalidExpr) KernelString() string {
	return "<<invalidExpr KernelString>>"
}

func testInvalidIdentifier(t *testing.T, s string) {
	err := validateIdentifier(s)
	if err == nil { // YES ==
		t.Errorf("Invalid identifier %q accepted", s)
	}
}

func testValidIdentifier(t *testing.T, s string) {
	err := validateIdentifier(s)
	if err != nil {
		t.Errorf("Valid identifier %q; got %s", s, err)
	}
}

func TestValidateIdentifier(t *testing.T) {
	testInvalidIdentifier(t, "")
	testInvalidIdentifier(t, "CON$")
	testInvalidIdentifier(t, "1234")
	testInvalidIdentifier(t, "83foo")

	testValidIdentifier(t, "x")
	testValidIdentifier(t, "abc83")
	testValidIdentifier(t, "_")
	testValidIdentifier(t, "_83_")
}

func TestValidateKernelFilter(t *testing.T) {
	// identExpr tests
	ie := identExpr{name: "foo"}
	if err := validateKernelFilterTree(ie); err != nil {
		t.Errorf("validateKernelFilterTree failure: %v", err)
	}
	ie = identExpr{name: "foo$"}
	if err := validateKernelFilterTree(ie); err == nil {
		t.Errorf("validateKernelFilterTree failure")
	}

	// valueExpr tests
	ve := valueExpr{v: "string"}
	if err := validateKernelFilterTree(ve); err != nil {
		t.Errorf("validateKernelFilterTree failure: %v", err)
	}
	ve.v = true
	if validateKernelFilterTree(ve) == nil {
		t.Errorf("validateKernelFilterTree failure")
	}

	// binaryExpr tests
	logicalOps := []binaryOp{
		binaryOpLogicalAnd, binaryOpLogicalOr,
	}
	for _, op := range logicalOps {
		be := binaryExpr{op: op}
		if validateKernelFilterTree(be) == nil {
			t.Errorf("validateKernelFilterTree failure for %s",
				binaryOpStrings[op])
		}
		be.x = valueExpr{v: "string"}
		be.y = valueExpr{v: "string"}
		if err := validateKernelFilterTree(be); err != nil {
			t.Errorf("validateKernelFilterTree failure for %s: %v",
				binaryOpStrings[op], err)
		}
	}

	binaryOps := []binaryOp{
		binaryOpEQ, binaryOpNE, binaryOpLT, binaryOpLE,
		binaryOpGT, binaryOpGE,
	}
	for _, op := range binaryOps {
		be := binaryExpr{
			op: op,
			x:  identExpr{name: "foo"},
			y:  valueExpr{v: int32(8)},
		}
		if err := validateKernelFilterTree(be); err != nil {
			t.Errorf("validateKernelFilterTree failure for %s: %v",
				binaryOpStrings[op], err)
		}
		be.x = valueExpr{v: int8(8)}
		if validateKernelFilterTree(be) == nil {
			t.Errorf("validateKernelFilterTree failure for %s",
				binaryOpStrings[op])
		}
		be.x = identExpr{name: "foo"}
		be.y = identExpr{name: "bar"}
		if validateKernelFilterTree(be) == nil {
			t.Errorf("validateKernelFilterTree failure for %s",
				binaryOpStrings[op])
		}
	}

	op := binaryOpLike
	be := binaryExpr{
		op: op,
		x:  identExpr{name: "foo"},
		y:  valueExpr{v: "string"},
	}
	if err := validateKernelFilterTree(be); err != nil {
		t.Errorf("validateKernelFilterTree failure for %s: %v",
			binaryOpStrings[op], err)
	}
	be.x = valueExpr{v: int8(8)}
	if validateKernelFilterTree(be) == nil {
		t.Errorf("validateKernelFilterTree failure for %s",
			binaryOpStrings[op])
	}
	be.x = identExpr{name: "foo"}
	be.y = identExpr{name: "bar"}
	if validateKernelFilterTree(be) == nil {
		t.Errorf("validateKernelFilterTree failure for %s",
			binaryOpStrings[op])
	}

	be = binaryExpr{
		op: binaryOpNE,
	}
	be.x = binaryExpr{ // make an invalid bitwise-and
		op: binaryOpBitwiseAnd,
		x:  identExpr{name: "foo"},
		y:  valueExpr{v: "string"},
	}
	be.y = identExpr{name: "invalid"}
	if validateKernelFilterTree(be) == nil {
		t.Error("validateKernelFilterTree failure")
	}
	be.x = binaryExpr{ // make a valid bitwise-and
		op: binaryOpBitwiseAnd,
		x:  identExpr{name: "foo"},
		y:  valueExpr{v: int32(8)},
	}
	if validateKernelFilterTree(be) == nil {
		t.Error("validateKernelFilterTree failure")
	}
	be.y = valueExpr{v: int8(8)} // invalid, signed
	if validateKernelFilterTree(be) == nil {
		t.Error("validateKernelFilterTree failure")
	}
	be.y = valueExpr{v: uint32(8)} // invalid, unsigned
	if validateKernelFilterTree(be) == nil {
		t.Error("validateKernelFilterTree failure")
	}
	be.y = valueExpr{v: "string"} // invalid, not integer
	if validateKernelFilterTree(be) == nil {
		t.Error("validateKernelFilterTree failure")
	}
	be.y = valueExpr{v: int64(0)} // VALID!
	if err := validateKernelFilterTree(be); err != nil {
		t.Errorf("validateKernelFilterTree failure: %v", err)
	}

	be = binaryExpr{
		op: binaryOpBitwiseAnd,
		x:  valueExpr{},
	}
	if validateKernelFilterTree(be) == nil {
		t.Error("validateKernelFilterTree failure")
	}
	be = binaryExpr{
		op: binaryOpBitwiseAnd,
		x:  identExpr{name: "foo"},
		y:  identExpr{name: "bar"},
	}
	if validateKernelFilterTree(be) == nil {
		t.Error("validateKernelFilterTree failure")
	}
	be = binaryExpr{
		op: binaryOpBitwiseAnd,
		x:  identExpr{name: "foo"},
		y:  valueExpr{v: "string"},
	}
	if validateKernelFilterTree(be) == nil {
		t.Error("validateKernelFilterTree failure")
	}
	be = binaryExpr{
		op: binaryOpBitwiseAnd,
		x:  identExpr{name: "foo"},
		y:  valueExpr{v: int8(8)},
	}
	if err := validateKernelFilterTree(be); err != nil {
		t.Errorf("validateKernelFilterTree failure: %v", err)
	}

	// unaryExpr tests
	ue := unaryExpr{op: unaryOpIsNull}
	if validateKernelFilterTree(ue) == nil {
		t.Errorf("validateKernelFilterTree failure")
	}

	// invalidExpr tests
	if validateKernelFilterTree(invalidExpr{}) == nil {
		t.Errorf("validateKernelFilterTree failure")
	}
}

func TestValidateTypes(t *testing.T) {
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

	for n, vt := range types {
		e := identExpr{name: n}
		if vtr, err := validateTypes(e, types); err != nil {
			t.Errorf("Unexpected error for %q: %v", n, err)
		} else if vt != vtr {
			t.Errorf("validateTypes returned wrong type for %q (want %s; got %s)",
				n, ValueTypeStrings[vt], ValueTypeStrings[vtr])
		}
	}

	if _, err := validateTypes(identExpr{name: "foo"}, types); err == nil {
		t.Error("validateTypes failure")
	}

	// valueExpr tests
	ve := valueExpr{v: "string"}
	if vt, err := validateTypes(ve, types); err != nil {
		t.Errorf("Unexpected validateTypes Error: %v", err)
	} else if vt != ValueTypeString {
		t.Errorf("Unexpected value type %s for string",
			ValueTypeStrings[vt])
	}

	ve.v = make(chan interface{})
	if _, err := validateTypes(ve, types); err == nil {
		t.Error("validateTypes failure")
	}

	// binaryExpr tests
	be := binaryExpr{}

	logicalOps := []binaryOp{
		binaryOpLogicalAnd, binaryOpLogicalOr,
	}
	for _, op := range logicalOps {
		be = binaryExpr{op: op}

		be.x = valueExpr{v: make(chan interface{})}
		if _, err := validateTypes(be, types); err == nil {
			t.Errorf("validateTypes failure for %s", binaryOpStrings[op])
		}

		be.x = identExpr{name: "s"}
		if _, err := validateTypes(be, types); err == nil {
			t.Errorf("validateTypes failure for %s", binaryOpStrings[op])
		}

		be.x = identExpr{name: "b"}
		be.y = valueExpr{v: make(chan interface{})}
		if _, err := validateTypes(be, types); err == nil {
			t.Errorf("validateTypes failure for %s", binaryOpStrings[op])
		}

		be.y = valueExpr{v: "string"}
		if _, err := validateTypes(be, types); err == nil {
			t.Errorf("validateTypes failure for %s", binaryOpStrings[op])
		}

		be.y = valueExpr{true}
		if _, err := validateTypes(be, types); err != nil {
			t.Errorf("validateTypes failure for %s: %v", binaryOpStrings[op], err)
		}
	}

	binaryOps := []binaryOp{
		binaryOpEQ, binaryOpNE, binaryOpLT, binaryOpLE,
		binaryOpGT, binaryOpGE,
	}
	for _, op := range binaryOps {
		be = binaryExpr{op: op}

		be.x = valueExpr{v: make(chan interface{})}
		if _, err := validateTypes(be, types); err == nil {
			t.Errorf("validateTypes failure for %s", binaryOpStrings[op])
		}

		be.x = identExpr{name: "u16"}
		if _, err := validateTypes(be, types); err == nil {
			t.Errorf("validateTypes failure for %s", binaryOpStrings[op])
		}

		be.y = identExpr{name: "s"}
		if _, err := validateTypes(be, types); err == nil {
			t.Errorf("validateTypes failure for %s", binaryOpStrings[op])
		}

		be.y = valueExpr{v: uint16(8)}
		if _, err := validateTypes(be, types); err != nil {
			t.Errorf("validateTypes failure for %s: %v", binaryOpStrings[op], err)
		}
	}

	binaryOps = []binaryOp{
		binaryOpLT, binaryOpLE, binaryOpGT, binaryOpGE,
	}
	for _, op := range binaryOps {
		be = binaryExpr{
			op: op,
			x:  identExpr{name: "s"},
			y:  valueExpr{v: int16(8)},
		}
		if _, err := validateTypes(be, types); err == nil {
			t.Errorf("validateTypes failure for %s", binaryOpStrings[op])
		}
	}

	op := binaryOpLike
	be = binaryExpr{op: op}

	be.x = valueExpr{v: make(chan interface{})}
	if _, err := validateTypes(be, types); err == nil {
		t.Errorf("validateTypes failure for %s", binaryOpStrings[op])
	}

	be.x = identExpr{name: "u16"}
	if _, err := validateTypes(be, types); err == nil {
		t.Errorf("validateTypes failure for %s", binaryOpStrings[op])
	}

	be.x = identExpr{name: "s"}
	if _, err := validateTypes(be, types); err == nil {
		t.Errorf("validateTypes failure for %s", binaryOpStrings[op])
	}

	be.y = identExpr{name: "u16"}
	if _, err := validateTypes(be, types); err == nil {
		t.Errorf("validateTypes failure for %s", binaryOpStrings[op])
	}

	be.y = valueExpr{v: "string"}
	if _, err := validateTypes(be, types); err != nil {
		t.Errorf("validateTypes failure for %s: %v", binaryOpStrings[op], err)
	}

	op = binaryOpBitwiseAnd
	be = binaryExpr{op: op}
	be.x = valueExpr{v: make(chan interface{})}
	if _, err := validateTypes(be, types); err == nil {
		t.Errorf("validateTypes failure for %s: %v", binaryOpStrings[op], err)
	}
	be.x = identExpr{name: "s"}
	if _, err := validateTypes(be, types); err == nil {
		t.Errorf("validateTypes failure for %s: %v", binaryOpStrings[op], err)
	}
	be.x = identExpr{name: "u32"}
	be.y = valueExpr{v: make(chan interface{})}
	if _, err := validateTypes(be, types); err == nil {
		t.Errorf("validateTypes failure for %s: %v", binaryOpStrings[op], err)
	}
	be.y = valueExpr{v: "string"}
	if _, err := validateTypes(be, types); err == nil {
		t.Errorf("validateTypes failure for %s: %v", binaryOpStrings[op], err)
	}
	be.y = valueExpr{v: uint32(8)}
	if _, err := validateTypes(be, types); err != nil {
		t.Errorf("validateTypes failure for %s: %v", binaryOpStrings[op], err)
	}

	be.op = 87364
	if _, err := validateTypes(be, types); err == nil {
		t.Error("validateTypes failure")
	}

	// unaryExpr tests
	ue := unaryExpr{}

	ue.op = unaryOpIsNull
	ue.x = identExpr{name: "s"}
	if vt, err := validateTypes(ue, types); err != nil {
		t.Errorf("Unexpected validateTypes Error: %v", err)
	} else if vt != ValueTypeBool {
		t.Errorf("Unexpected validateTypes type %s", ValueTypeStrings[vt])
	}
	ue.x = identExpr{name: "foo"}
	if _, err := validateTypes(ue, types); err == nil {
		t.Error("validateTypes failure")
	}

	ue.op = unaryOpIsNotNull
	ue.x = identExpr{name: "s"}
	if vt, err := validateTypes(ue, types); err != nil {
		t.Errorf("Unexpected validateTypes Error: %v", err)
	} else if vt != ValueTypeBool {
		t.Errorf("Unexpected validateTypes type %s", ValueTypeStrings[vt])
	}
	ue.x = identExpr{name: "foo"}
	if _, err := validateTypes(ue, types); err == nil {
		t.Error("validateTypes failure")
	}

	ue.op = 982375
	if _, err := validateTypes(ue, types); err == nil {
		t.Error("validateTypes failure")
	}

	// Test totally unsupported expr type
	if _, err := validateTypes(invalidExpr{}, types); err == nil {
		t.Error("validateTypes failure")
	}
}
