package policy

import (
	"fmt"
	"github.com/antonmedv/expr"
	"reflect"
)

// Eval 计算 expr 的值
func Eval(express string, v map[string]any) (bool, error) {
	program, err := expr.Compile(express, expr.Env(v))
	if err != nil {
		return false, err
	}

	o, err := expr.Run(program, v)
	if err != nil {
		return false, err
	}

	if b, ok := o.(bool); !ok {
		return false, fmt.Errorf("expect got a bool type but got %v", reflect.TypeOf(o))
	} else {
		return b, nil
	}
}
