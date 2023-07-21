package sqlrisk

import (
	"github.com/sunkaimr/sql-risk/comm"
	"testing"
)

func TestStatementSQL(t *testing.T) {
	tests := []struct {
		name string
		wr   WorkRisk
		want []string
	}{
		{
			name: "test001",
			wr: WorkRisk{
				DataBase: "test",
				SQLText:  `update student set name='lisi' where id=10;delete from student where id=10;`,
			},
			want: []string{"update student set name='lisi' where id=10", "delete from student where id=10"},
		},
		{
			name: "test002",
			wr: WorkRisk{
				DataBase: "test",
				SQLText:  `update  t_prod_contract_card_info set usable_flag = 'UN_USABLE' where id in ( '3825169', '3825170', '3825171')`,
			},
			want: []string{"update  t_prod_contract_card_info set usable_flag = 'UN_USABLE' where id in ( '3825169', '3825170', '3825171')"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.wr.SplitStatement()
			if err != nil {
				t.Fatalf("%v", err)
			}

			sqlList := make([]string, 0, 10)
			for _, risk := range test.wr.SQLRisks {
				sqlList = append(sqlList, risk.SQLText)
			}

			if !comm.SlicesEqual(sqlList, test.want) {
				t.Fatalf("SplitStatement failed, got:%v, want:%v", sqlList, test.want)
			}
		})
	}
}
