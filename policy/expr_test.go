package policy

import (
	"testing"
)

var strategys = []string{
	"ACT_001",
	"ACT_003",
	"ACT_001 && ACT_002",
	"ACT_003 && ACT_004",

	"ACT_001 && ACT_003",

	"ACT_001 || ACT_003",

	"( ACT_001 || ACT_003 ) && ACT_004",

	"( ACT_001 || ACT_003 ) && !ACT_004",

	"ACT_005 < 50",

	"ACT_005 >= 50",
}

var rule = map[string]any{
	"ACT_001": true,
	"ACT_002": true,
	"ACT_003": false,
	"ACT_004": false,
	"ACT_005": 50,
}

func TestEval(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
		err  error
	}{
		{"test000", strategys[0], true, nil},
		{"test001", strategys[1], false, nil},
		{"test002", strategys[2], true, nil},
		{"test003", strategys[3], false, nil},
		{"test004", strategys[4], false, nil},
		{"test005", strategys[5], true, nil},
		{"test006", strategys[6], false, nil},
		{"test007", strategys[7], true, nil},
		{"test008", strategys[8], false, nil},
		{"test009", strategys[9], true, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, err := Eval(test.in, rule); err != test.err {
				t.Fatalf("Eval(%v) failed, got error: %s", test.in, err)
			} else if got != test.want {
				t.Fatalf("Eval(%v) = %t, want %v", test.in, got, test.want)
			}
		})
	}
}
