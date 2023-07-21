package sqlrisk

//
//import "testing"
//
//func TestMatchBasicStrategies(t *testing.T) {
//	tests := []struct {
//		name string
//		env  map[string]any
//		want PreResult
//	}{
//		{
//			name: "select",
//			env:  map[string]any{Operate.ID: string(Operate.V.DQL), Action.ID: string(Action.V.Select), KeyWord.ID: string(Select)},
//			want: PreResult{Level: LowRisk, Special: false},
//		},
//		{
//			name: "unknown",
//			env:  map[string]any{Operate.ID: string(Unknown), Action.ID: string(Unknown), KeyWord.ID: string(Unknown)},
//			want: PreResult{Level: FatalRisk, Special: false},
//		},
//		{
//			name: "TableSize>2G",
//			env:  map[string]any{TabSize.ID: 4096},
//			want: PreResult{Level: HighRisk, Special: false},
//		},
//		{
//			name: "TableSize<2G",
//			env:  map[string]any{TabSize.ID: 1024},
//			want: PreResult{Level: LowRisk, Special: false},
//		},
//		{
//			name: "TableRows>20000",
//			env:  map[string]any{TabRows.ID: 30000},
//			want: PreResult{Level: HighRisk, Special: false},
//		},
//		{
//			name: "TableRows<20000",
//			env:  map[string]any{TabRows.ID: 10000},
//			want: PreResult{Level: LowRisk, Special: false},
//		},
//		{
//			name: "FreeDisk<=TableSize",
//			env:  map[string]any{TabSize.ID: 1024, FREE_DISK: 10},
//			want: PreResult{Level: FatalRisk, Special: false},
//		},
//		{
//			name: "FreeDisk>TableSize",
//			env:  map[string]any{TabSize.ID: 1024, FREE_DISK: 2048},
//			want: PreResult{Level: LowRisk, Special: false},
//		},
//	}
//
//	for _, test := range tests {
//		t.Run(test.name, func(t *testing.T) {
//			defaultEnv := newDefaultEnv()
//			for k, v := range test.env {
//				defaultEnv[k] = v
//			}
//
//			b, matchRules, err := MatchBasicStrategies(defaultEnv)
//			if err != nil {
//				t.Fatalf("MatchBasicStrategies failed, got error: %s", err)
//			}
//			if !b {
//				t.Fatalf("MatchBasicStrategies got: %v, want: %v", b, true)
//			}
//			if matchRules[0].Level != test.want.Level || matchRules[0].Special != test.want.Special {
//				t.Fatalf("MatchBasicStrategies got: %v:%v, want: %v:%v",
//					matchRules[0].Level, matchRules[0].Special, test.want.Level, test.want.Special)
//			}
//		})
//	}
//}
//
//func TestMatchSpecialStrategies(t *testing.T) {
//	tests := []struct {
//		name string
//		env  map[string]any
//		want PreResult
//	}{
//		{
//			name: "delete from && AffectRows > 20000",
//			env:  map[string]any{KeyWord.ID: string(Delete), AFFECT_ROWS: 30000},
//			want: PreResult{Level: HighRisk, Special: true},
//		},
//		{
//			name: "delete from where && !IndexExistInWhere && AffectRows > 20000",
//			env:  map[string]any{KeyWord.ID: string(DeleteWhere), INDEX_EXIST_IN_WHERE: false, AFFECT_ROWS: 30000},
//			want: PreResult{Level: HighRisk, Special: true},
//		},
//		{
//			name: "delete from where && !IndexExistInWhere && AffectRows <= 20000",
//			env:  map[string]any{KeyWord.ID: string(DeleteWhere), INDEX_EXIST_IN_WHERE: false, AFFECT_ROWS: 10000},
//			want: PreResult{Level: HighRisk, Special: false},
//		},
//		{
//			name: "delete from where && IndexExistInWhere && AffectRows > 20000",
//			env:  map[string]any{KeyWord.ID: string(DeleteWhere), INDEX_EXIST_IN_WHERE: true, AFFECT_ROWS: 30000},
//			want: PreResult{Level: HighRisk, Special: true},
//		},
//		{
//			name: "delete from where && IndexExistInWhere && AffectRows < 20000",
//			env:  map[string]any{KeyWord.ID: string(DeleteWhere), INDEX_EXIST_IN_WHERE: true, AFFECT_ROWS: 10000},
//			want: PreResult{Level: LowRisk, Special: false},
//		},
//		{
//			name: "update set",
//			env:  map[string]any{KeyWord.ID: string(Update), AFFECT_ROWS: 30000},
//			want: PreResult{Level: HighRisk, Special: true},
//		},
//		{
//			name: "update set where && !IndexExistInWhere && AffectRows > 20000",
//			env:  map[string]any{KeyWord.ID: string(UpdateWhere), INDEX_EXIST_IN_WHERE: false, AFFECT_ROWS: 30000},
//			want: PreResult{Level: HighRisk, Special: true},
//		},
//		{
//			name: "update set where && !IndexExistInWhere && AffectRows <= 20000",
//			env:  map[string]any{KeyWord.ID: string(UpdateWhere), INDEX_EXIST_IN_WHERE: false, AFFECT_ROWS: 10000},
//			want: PreResult{Level: HighRisk, Special: false},
//		},
//		{
//			name: "update set where && !IndexExistInWhere && AffectRows > 20000",
//			env:  map[string]any{KeyWord.ID: string(UpdateWhere), INDEX_EXIST_IN_WHERE: true, AFFECT_ROWS: 30000},
//			want: PreResult{Level: HighRisk, Special: true},
//		},
//		{
//			name: "update set where && !IndexExistInWhere && AffectRows <= 20000",
//			env:  map[string]any{KeyWord.ID: string(UpdateWhere), INDEX_EXIST_IN_WHERE: true, AFFECT_ROWS: 10000},
//			want: PreResult{Level: LowRisk, Special: false},
//		},
//	}
//
//	for _, test := range tests {
//		t.Run(test.name, func(t *testing.T) {
//			defaultEnv := newDefaultEnv()
//			for k, v := range test.env {
//				defaultEnv[k] = v
//			}
//
//			b, matchRules, err := MatchSpecialStrategies(defaultEnv)
//			if err != nil {
//				t.Fatalf("MatchSpecialStrategies failed, got error: %s", err)
//			}
//			if !b {
//				t.Fatalf("MatchSpecialStrategies got: %v, want: %v", b, true)
//			}
//			if matchRules[0].Level != test.want.Level || matchRules[0].Special != test.want.Special {
//				t.Fatalf("MatchSpecialStrategies got: %v:%v, want: %v:%v",
//					matchRules[0].Level, matchRules[0].Special, test.want.Level, test.want.Special)
//			}
//		})
//	}
//}
//
//func TestMatchPostRiskStrategies(t *testing.T) {
//	tests := []struct {
//		name string
//		env  map[string]any
//		want PreResult
//	}{
//		{
//			name: "CpuUsage > 70",
//			env:  map[string]any{CPU_USAGE: 90},
//			want: PreResult{Level: FatalRisk, Special: false},
//		},
//		{
//			name: "40 <= CpuUsage && CpuUsage >= 70",
//			env:  map[string]any{CPU_USAGE: 50},
//			want: PreResult{Level: HighRisk, Special: false},
//		},
//		{
//			name: "CpuUsage < 40",
//			env:  map[string]any{CPU_USAGE: 10},
//			want: PreResult{Level: LowRisk, Special: false},
//		},
//		{
//			name: "BigTransaction",
//			env:  map[string]any{TRANSACTION: true},
//			want: PreResult{Level: FatalRisk, Special: false},
//		},
//		{
//			name: "!BigTransaction",
//			env:  map[string]any{TRANSACTION: false},
//			want: PreResult{Level: LowRisk, Special: false},
//		},
//		{
//			name: "PrimaryKeyExist",
//			env:  map[string]any{PRIMARY_KEY_EXIST: true},
//			want: PreResult{Level: LowRisk, Special: false},
//		},
//		{
//			name: "!PrimaryKeyExist",
//			env:  map[string]any{PRIMARY_KEY_EXIST: false},
//			want: PreResult{Level: LowRisk, Special: false},
//		},
//		{
//			name: "ForeignKeyExist",
//			env:  map[string]any{FOREIGN_KEY_EXIST: true},
//			want: PreResult{Level: LowRisk, Special: false},
//		},
//		{
//			name: "!ForeignKeyExist",
//			env:  map[string]any{FOREIGN_KEY_EXIST: false},
//			want: PreResult{Level: LowRisk, Special: false},
//		},
//		{
//			name: "TriggerExist",
//			env:  map[string]any{TRIGGER_EXIST: true},
//			want: PreResult{Level: LowRisk, Special: false},
//		},
//		{
//			name: "!TriggerExist",
//			env:  map[string]any{TRIGGER_EXIST: false},
//			want: PreResult{Level: LowRisk, Special: false},
//		},
//	}
//
//	for _, test := range tests {
//		t.Run(test.name, func(t *testing.T) {
//			defaultEnv := newDefaultEnv()
//			for k, v := range test.env {
//				defaultEnv[k] = v
//			}
//
//			b, matchRules, err := MatchPostRiskStrategies(defaultEnv)
//			if err != nil {
//				t.Fatalf("MatchPostRiskStrategies failed, got error: %s", err)
//			}
//			if !b {
//				t.Fatalf("MatchPostRiskStrategies got: %v, want: %v", b, true)
//			}
//			if matchRules[0].Level != test.want.Level || matchRules[0].Special != test.want.Special {
//				t.Fatalf("MatchPostRiskStrategies got: %v:%v, want: %v:%v",
//					matchRules[0].Level, matchRules[0].Special, test.want.Level, test.want.Special)
//			}
//		})
//	}
//}
//
//func newDefaultEnv() map[string]any {
//	defaultEnv := map[string]any{
//		Operate.ID:           string(Operate.V.DQL),
//		Action.ID:            string(Action.V.Action.V.Select),
//		KeyWord.ID:           string(KeyWord.V.Select),
//		TabSize.ID:           1024,
//		TabRows.ID:           100,
//		AffectRows.ID:        300,
//		FreeDisk.ID:          9999,
//		PrimaryKeyExist.ID:   true,
//		ForeignKeyExist.ID:   false,
//		TriggerExist.ID:      false,
//		IndexExistInWhere.ID: true,
//		CpuUsage.ID:          10,
//		BigTransaction.ID:    false,
//	}
//	return defaultEnv
//}
