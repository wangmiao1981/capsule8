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
	"errors"
	"fmt"
	"time"

	api "github.com/capsule8/capsule8/api/v0"
)

func convertValue(value *api.Value) (e expr) {
	switch value.GetType() {
	case api.ValueType_STRING:
		v, ok := value.GetValue().(*api.Value_StringValue)
		if !ok {
			exprRaise(errors.New("STRING value has no StringValue set"))
		}
		e = valueExpr{v: v.StringValue}
	case api.ValueType_SINT8:
		v, ok := value.GetValue().(*api.Value_SignedValue)
		if !ok {
			exprRaise(errors.New("SINT8 value has no SignedValue set"))
		}
		e = valueExpr{v: int8(v.SignedValue)}
	case api.ValueType_SINT16:
		v, ok := value.GetValue().(*api.Value_SignedValue)
		if !ok {
			exprRaise(errors.New("SINT16 value has no SignedValue set"))
		}
		e = valueExpr{v: int16(v.SignedValue)}
	case api.ValueType_SINT32:
		v, ok := value.GetValue().(*api.Value_SignedValue)
		if !ok {
			exprRaise(errors.New("SINT32 value has no SignedValue set"))
		}
		e = valueExpr{v: int32(v.SignedValue)}
	case api.ValueType_SINT64:
		v, ok := value.GetValue().(*api.Value_SignedValue)
		if !ok {
			exprRaise(errors.New("SINT64 value has no SignedValue set"))
		}
		e = valueExpr{v: int64(v.SignedValue)}
	case api.ValueType_UINT8:
		v, ok := value.GetValue().(*api.Value_UnsignedValue)
		if !ok {
			exprRaise(errors.New("UINT8 value has no UnsignedValue set"))
		}
		e = valueExpr{v: uint8(v.UnsignedValue)}
	case api.ValueType_UINT16:
		v, ok := value.GetValue().(*api.Value_UnsignedValue)
		if !ok {
			exprRaise(errors.New("UINT16 value has no UnsignedValue set"))
		}
		e = valueExpr{v: uint16(v.UnsignedValue)}
	case api.ValueType_UINT32:
		v, ok := value.GetValue().(*api.Value_UnsignedValue)
		if !ok {
			exprRaise(errors.New("UINT32 value has no UnsignedValue set"))
		}
		e = valueExpr{v: uint32(v.UnsignedValue)}
	case api.ValueType_UINT64:
		v, ok := value.GetValue().(*api.Value_UnsignedValue)
		if !ok {
			exprRaise(errors.New("UINT64 value has no UnsignedValue set"))
		}
		e = valueExpr{v: uint64(v.UnsignedValue)}
	case api.ValueType_BOOL:
		v, ok := value.GetValue().(*api.Value_BoolValue)
		if !ok {
			exprRaise(errors.New("BOOL value has no BoolValue set"))
		}
		e = valueExpr{v: v.BoolValue}
	case api.ValueType_DOUBLE:
		v, ok := value.GetValue().(*api.Value_DoubleValue)
		if !ok {
			exprRaise(errors.New("DOUBLE value has no DoubleValue set"))
		}
		e = valueExpr{v: v.DoubleValue}
	case api.ValueType_TIMESTAMP:
		v, ok := value.GetValue().(*api.Value_TimestampValue)
		if !ok {
			exprRaise(errors.New("TIMESTAMP value has no TimestampValue set"))
		}
		t := v.TimestampValue
		e = valueExpr{v: time.Unix(t.Seconds, int64(t.Nanos))}
	default:
		exprRaise(fmt.Errorf("Unrecognized value type %d", value.GetType()))
	}
	return
}

func convertBinaryOp(node *api.Expression, op binaryOp) expr {
	operands := node.GetBinaryOp()
	if operands == nil {
		exprRaise(errors.New("BinaryOp missing for binary operation node"))
	}
	if operands.Lhs == nil {
		exprRaise(errors.New("BinaryOp missing lhs"))
	}
	if operands.Rhs == nil {
		exprRaise(errors.New("BinaryOp missing rhs"))
	}

	logical := false
	switch node.GetType() {
	case api.Expression_LOGICAL_AND, api.Expression_LOGICAL_OR:
		logical = true
	}

	return binaryExpr{
		op: op,
		x:  convertNode(operands.Lhs, logical),
		y:  convertNode(operands.Rhs, logical),
	}
}

func convertUnaryOp(node *api.Expression, op unaryOp) expr {
	operand := node.GetUnaryOp()
	if operand == nil {
		exprRaise(errors.New("UnaryOp missing for unary compare"))
	}

	return unaryExpr{
		op: op,
		x:  convertNode(operand, false),
	}
}

func convertNode(node *api.Expression, logical bool) (r expr) {
	switch op := node.GetType(); op {
	case api.Expression_IDENTIFIER:
		ident := node.GetIdentifier()
		if ident == "" {
			exprRaise(errors.New("Identifier missing for IDENTIFIER node"))
		}
		if err := validateIdentifier(ident); err != nil {
			exprRaise(err)
		}
		r = identExpr{name: ident}
	case api.Expression_VALUE:
		value := node.GetValue()
		if value == nil {
			exprRaise(errors.New("Value missing fdor VALUE node"))
		}
		r = convertValue(value)
	case api.Expression_LOGICAL_AND:
		r = convertBinaryOp(node, binaryOpLogicalAnd)
	case api.Expression_LOGICAL_OR:
		r = convertBinaryOp(node, binaryOpLogicalOr)
	case api.Expression_EQ:
		r = convertBinaryOp(node, binaryOpEQ)
	case api.Expression_NE:
		r = convertBinaryOp(node, binaryOpNE)
	case api.Expression_LT:
		r = convertBinaryOp(node, binaryOpLT)
	case api.Expression_LE:
		r = convertBinaryOp(node, binaryOpLE)
	case api.Expression_GT:
		r = convertBinaryOp(node, binaryOpGT)
	case api.Expression_GE:
		r = convertBinaryOp(node, binaryOpGE)
	case api.Expression_LIKE:
		r = convertBinaryOp(node, binaryOpLike)
	case api.Expression_BITWISE_AND:
		r = convertBinaryOp(node, binaryOpBitwiseAnd)
	case api.Expression_IS_NULL:
		r = convertUnaryOp(node, unaryOpIsNull)
	case api.Expression_IS_NOT_NULL:
		r = convertUnaryOp(node, unaryOpIsNotNull)
	default:
		exprRaise(fmt.Errorf("Unrecognized expression type %d", node.GetType()))
	}
	return
}

func convertExpression(ae *api.Expression) (ast expr, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(exprError); ok {
				err = e
			} else {
				panic(r)
			}
		}
	}()

	ast = convertNode(ae, true)
	return
}
