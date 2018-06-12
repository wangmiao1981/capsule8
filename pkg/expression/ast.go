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
	"fmt"
	"time"
)

type expr interface {
	exprNode()

	KernelString() string
	String() string
}

type (
	identExpr struct {
		name string
	}

	valueExpr struct {
		v interface{}
	}

	binaryExpr struct {
		x  expr
		y  expr
		op binaryOp
	}

	unaryExpr struct {
		x  expr
		op unaryOp
	}
)

func (e identExpr) exprNode()  {}
func (e valueExpr) exprNode()  {}
func (e binaryExpr) exprNode() {}
func (e unaryExpr) exprNode()  {}

func (e identExpr) String() string {
	return e.name
}

func (e identExpr) KernelString() string {
	return e.String()
}

func (e valueExpr) String() string {
	switch v := e.v.(type) {
	case string:
		return fmt.Sprintf("%q", v)
	case int8:
		return fmt.Sprintf("%d", v)
	case int16:
		return fmt.Sprintf("%d", v)
	case int32:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case uint8:
		return fmt.Sprintf("%d", v)
	case uint16:
		return fmt.Sprintf("%d", v)
	case uint32:
		return fmt.Sprintf("%d", v)
	case uint64:
		return fmt.Sprintf("%d", v)
	case bool:
		if v {
			return "TRUE"
		}
		return "FALSE"
	case float64:
		return fmt.Sprintf("%f", v)
	case time.Time:
		return fmt.Sprintf("TIMESTAMP(%d)", v.UnixNano())
	}

	panic("internal error: invalid valueExpr")
}

func (e valueExpr) KernelString() string {
	return e.String()
}

func (e valueExpr) isInteger() bool {
	switch e.v.(type) {
	case int8, int16, int32, int64, uint8, uint16, uint32, uint64:
		return true
	}
	return false
}

func (e valueExpr) isNumeric() bool {
	switch e.v.(type) {
	case float64, time.Time:
		return true
	}
	return e.isInteger()
}

func (e valueExpr) isString() bool {
	_, ok := e.v.(string)
	return ok
}

func (e binaryExpr) isValid() bool {
	switch e.op {
	case binaryOpLogicalAnd, binaryOpLogicalOr, binaryOpEQ, binaryOpNE,
		binaryOpLT, binaryOpLE, binaryOpGT, binaryOpGE, binaryOpLike,
		binaryOpBitwiseAnd:
	default:
		return false
	}
	return true
}

func (e binaryExpr) String() string {
	if !e.isValid() {
		panic("internal error: invalid binaryExpr")
	}

	if y, ok := e.y.(binaryExpr); ok {
		if y.op == binaryOpLogicalAnd || y.op == binaryOpLogicalOr {
			return fmt.Sprintf("%s %s (%s)", e.x, binaryOpStrings[e.op], e.y)
		}
	}
	return fmt.Sprintf("%s %s %s", e.x, binaryOpStrings[e.op], e.y)
}

func (e binaryExpr) KernelString() string {
	if !e.isValid() {
		panic("internal error: invalid binaryExpr")
	}

	if e.op == binaryOpNE {
		if x, ok := e.x.(binaryExpr); ok && x.op == binaryOpBitwiseAnd {
			// Assume that the rhs is 0 because prior validation
			// should ensure that to be the case
			return e.x.KernelString()
		}
	}

	if y, ok := e.y.(binaryExpr); ok {
		if y.op == binaryOpLogicalAnd || y.op == binaryOpLogicalOr {
			return fmt.Sprintf("%s %s (%s)", e.x.KernelString(),
				binaryOpKernelStrings[e.op], e.y.KernelString())
		}
	}
	return fmt.Sprintf("%s %s %s", e.x.KernelString(),
		binaryOpKernelStrings[e.op], e.y.KernelString())
}

func (e unaryExpr) String() string {
	switch e.op {
	case unaryOpIsNull, unaryOpIsNotNull:
		return fmt.Sprintf("%s %s", e.x, unaryOpStrings[e.op])
	}
	panic("internal error: invalid unaryExpr")
}

func (e unaryExpr) KernelString() string {
	return ""
}
