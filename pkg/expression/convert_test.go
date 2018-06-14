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
	"reflect"
	"testing"
	"time"

	api "github.com/capsule8/capsule8/api/v0"
)

func callConvertValue(value *api.Value) (v valueExpr, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(exprError); ok {
				err = e.error
			} else {
				panic(r)
			}
		}
	}()

	v = convertValue(value).(valueExpr)
	return
}

func TestConvertValue(t *testing.T) {
	values := map[api.ValueType]interface{}{
		api.ValueType_STRING:    "string",
		api.ValueType_SINT8:     int8(8),
		api.ValueType_SINT16:    int16(8),
		api.ValueType_SINT32:    int32(8),
		api.ValueType_SINT64:    int64(8),
		api.ValueType_UINT8:     uint8(8),
		api.ValueType_UINT16:    uint16(8),
		api.ValueType_UINT32:    uint32(8),
		api.ValueType_UINT64:    uint64(8),
		api.ValueType_BOOL:      true,
		api.ValueType_DOUBLE:    8.0,
		api.ValueType_TIMESTAMP: time.Unix(8, 8),
	}

	for valueType, value := range values {
		if _, err := callConvertValue(&api.Value{Type: valueType}); err == nil {
			t.Errorf("convertValue failure for %s",
				api.ValueType_name[int32(valueType)])
		}

		if v, err := callConvertValue(NewValue(value)); err != nil {
			t.Errorf("convertValue failure for %s: %v",
				api.ValueType_name[int32(valueType)], err)
		} else if !reflect.DeepEqual(value, v.v) {
			t.Errorf("convertValue failure for %s: %v (%s) vs. %v (%s)",
				api.ValueType_name[int32(valueType)],
				value, reflect.TypeOf(value),
				v.v, reflect.TypeOf(v.v))
		}
	}

	if _, err := callConvertValue(&api.Value{Type: 987234}); err == nil {
		t.Error("convertValue failure")
	}
}

func callConvertBinaryOp(expr *api.Expression, op binaryOp) (b binaryExpr, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(exprError); ok {
				err = e.error
			} else {
				panic(r)
			}
		}
	}()

	b = convertBinaryOp(expr, op).(binaryExpr)
	return
}

func TestConvertBinaryOp(t *testing.T) {
	expr := &api.Expression{Type: api.Expression_EQ}
	if _, err := callConvertBinaryOp(expr, binaryOpEQ); err == nil {
		t.Error("convertBinaryOp failure")
	}

	expr = newBinaryExpr(api.Expression_EQ, nil, nil)
	if _, err := callConvertBinaryOp(expr, binaryOpEQ); err == nil {
		t.Error("convertBinaryOp failure")
	}

	expr = newBinaryExpr(api.Expression_EQ, Identifier("foo"), nil)
	if _, err := callConvertBinaryOp(expr, binaryOpEQ); err == nil {
		t.Error("convertBinaryOp failure")
	}

	lhs := Identifier("foo")
	rhs := Value(int32(8))
	ops := map[api.Expression_ExpressionType]binaryOp{
		api.Expression_LOGICAL_AND: binaryOpLogicalAnd,
		api.Expression_LOGICAL_OR:  binaryOpLogicalOr,
		api.Expression_EQ:          binaryOpEQ,
		api.Expression_NE:          binaryOpNE,
		api.Expression_LT:          binaryOpLT,
		api.Expression_LE:          binaryOpLE,
		api.Expression_GT:          binaryOpGT,
		api.Expression_GE:          binaryOpGE,
		api.Expression_BITWISE_AND: binaryOpBitwiseAnd,
	}
	for apiOp, op := range ops {
		expr = newBinaryExpr(apiOp, lhs, rhs)
		if b, err := callConvertBinaryOp(expr, op); err != nil {
			t.Errorf("convertBinaryOp failure for %s: %v",
				api.Expression_ExpressionType_name[int32(apiOp)], err)
		} else if b.op != op {
			t.Errorf("convertBinaryOp failure for %s",
				api.Expression_ExpressionType_name[int32(apiOp)])
		} else if !reflect.DeepEqual(b.x, identExpr{name: "foo"}) {
			t.Errorf("convertBinaryOp failure for %s",
				api.Expression_ExpressionType_name[int32(apiOp)])
		} else if !reflect.DeepEqual(b.y, valueExpr{v: int32(8)}) {
			t.Errorf("convertBinaryOp failure for %s",
				api.Expression_ExpressionType_name[int32(apiOp)])
		}
	}
}

func callConvertUnaryOp(expr *api.Expression, op unaryOp) (u unaryExpr, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(exprError); ok {
				err = e.error
			} else {
				panic(r)
			}
		}
	}()

	u = convertUnaryOp(expr, op).(unaryExpr)
	return
}

func TestConvertUnaryOp(t *testing.T) {
	expr := &api.Expression{Type: api.Expression_IS_NULL}
	if _, err := callConvertUnaryOp(expr, unaryOpIsNull); err == nil {
		t.Error("convertUnaryOp failure")
	}

	operand := Identifier("foo")
	ops := map[api.Expression_ExpressionType]unaryOp{
		api.Expression_IS_NULL:     unaryOpIsNull,
		api.Expression_IS_NOT_NULL: unaryOpIsNotNull,
	}
	for apiOp, op := range ops {
		expr = newUnaryExpr(apiOp, operand)
		if b, err := callConvertUnaryOp(expr, op); err != nil {
			t.Errorf("convertUnaryOp failure for %s: %v",
				api.Expression_ExpressionType_name[int32(apiOp)], err)
		} else if b.op != op {
			t.Errorf("convertUnaryOp failure for %s",
				api.Expression_ExpressionType_name[int32(apiOp)])
		} else if !reflect.DeepEqual(b.x, identExpr{name: "foo"}) {
			t.Errorf("convertUnaryOp failure for %s",
				api.Expression_ExpressionType_name[int32(apiOp)])
		}
	}
}

func TestConvertExpression(t *testing.T) {
	e := &api.Expression{Type: api.Expression_IDENTIFIER}
	if _, err := convertExpression(e); err == nil {
		t.Error("convertExpression failure")
	}
	e = Identifier("foo$")
	if _, err := convertExpression(e); err == nil {
		t.Error("convertExpression failure")
	}

	e = &api.Expression{Type: api.Expression_VALUE}
	if _, err := convertExpression(e); err == nil {
		t.Error("convertExpression failure")
	}

	apiLHS := Identifier("foo")
	astLHS := identExpr{name: "foo"}
	apiRHS := Value(uint32(8))
	astRHS := valueExpr{v: uint32(8)}

	type testCase struct {
		apiExpr *api.Expression
		astExpr expr
	}
	testCases := []testCase{
		testCase{apiLHS, astLHS},
		testCase{apiRHS, astRHS},
		testCase{
			BitwiseAnd(apiLHS, apiRHS),
			binaryExpr{astLHS, astRHS, binaryOpBitwiseAnd},
		},
		testCase{
			Equal(apiLHS, apiRHS),
			binaryExpr{astLHS, astRHS, binaryOpEQ},
		},
		testCase{
			NotEqual(apiLHS, apiRHS),
			binaryExpr{astLHS, astRHS, binaryOpNE},
		},
		testCase{
			LessThan(apiLHS, apiRHS),
			binaryExpr{astLHS, astRHS, binaryOpLT},
		},
		testCase{
			LessThanEqualTo(apiLHS, apiRHS),
			binaryExpr{astLHS, astRHS, binaryOpLE},
		},
		testCase{
			GreaterThan(apiLHS, apiRHS),
			binaryExpr{astLHS, astRHS, binaryOpGT},
		},
		testCase{
			GreaterThanEqualTo(apiLHS, apiRHS),
			binaryExpr{astLHS, astRHS, binaryOpGE},
		},
		testCase{
			Like(apiLHS, apiRHS),
			binaryExpr{astLHS, astRHS, binaryOpLike},
		},
		testCase{
			IsNull(apiLHS),
			unaryExpr{astLHS, unaryOpIsNull},
		},
		testCase{
			IsNotNull(apiLHS),
			unaryExpr{astLHS, unaryOpIsNotNull},
		},
		testCase{
			LogicalAnd(apiLHS, apiRHS),
			binaryExpr{astLHS, astRHS, binaryOpLogicalAnd},
		},
		testCase{
			LogicalOr(apiLHS, apiRHS),
			binaryExpr{astLHS, astRHS, binaryOpLogicalOr},
		},
	}
	for _, tc := range testCases {
		if ast, err := convertExpression(tc.apiExpr); err != nil {
			t.Errorf("convertExpression failure for %s: %v",
				api.Expression_ExpressionType_name[int32(tc.apiExpr.Type)],
				err)
		} else if !reflect.DeepEqual(ast, tc.astExpr) {
			t.Errorf("convertExpression failure for %s",
				api.Expression_ExpressionType_name[int32(tc.apiExpr.Type)])
		}
	}
}
