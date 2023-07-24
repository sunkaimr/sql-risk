package sqlrisk

import (
	"github.com/sunkaimr/sql-risk/comm"
	"github.com/sunkaimr/sql-risk/policy"
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

func TestIdentifyWorkRiskPreRisk(t *testing.T) {
	store := policy.GetStore(policy.FileStoreType, ".policy.yaml")
	err := store.Init()
	if err != nil {
		t.Fatal(err)
	}
	err = store.PolicyWriter(policy.GenerateDefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}

	addr := "1.2.3.4"
	port := "3306"
	database := "database"
	sql := "ALTER TABLE `cowell_wxgateway`.`sms_notice_record_000` MODIFY COLUMN `phone` varchar(64) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '电话',ADD INDEX `idx_bi_phoneSafe_gc`(`business_id`, `phone_safe`, `gmt_create`) USING BTREE;\nupdate sms_notice_record_000 set phone = null WHERE gmt_create >='2023-04-13 00:00:00' and phone is not null and phone != ''\n"

	user := "root"
	passwd := "123456"

	w := NewWorkRisk("111", addr, port, user, passwd, database, sql, nil)
	err = w.IdentifyWorkRiskPreRisk()
	if err != nil {
		t.Fatalf("%v", err)
	}
}
