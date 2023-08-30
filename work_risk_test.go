package sqlrisk

import (
	"fmt"
	json "github.com/json-iterator/go"
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
		{
			name: "test003",
			wr: WorkRisk{
				DataBase: "isql_test",
				SQLText:  `DROP DATABASE isql_test`,
			},
			want: []string{"update t_prod_contract_card_info set usable_flag = 'UN_USABLE' where id in ( '3825169', '3825170', '3825171')"},
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

	addr := "10.2.66.8"
	port := "3306"
	database := "isql_test"
	sql := "CREATE TABLE `execute_activety` (\n  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT 'ID',\n  `name` varchar(32) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '步骤名称',\n  `code` varchar(32) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '步骤编码',\n  `system_type` varchar(32) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '系统类型',\n  `type` varchar(32) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '步骤类型',\n  `param` varchar(512) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '参数',\n  `remark` varchar(1024) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '备注',\n  `guide_url` varchar(1024) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '指引文档',\n  `process_id` varchar(32) COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'Camund流程ID',\n  `status` varchar(4) COLLATE utf8mb4_bin DEFAULT '0' COMMENT '状态',\n  `gmt_create` datetime DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',\n  `gmt_update` datetime DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',\n  `create_by` varchar(32) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '创建人',\n  `update_by` varchar(32) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '更新人',\n  `version` int(11) DEFAULT '0' COMMENT '版本号',\n  `extend` varchar(2048) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '扩展',\n  `camunda_url` varchar(200) COLLATE utf8mb4_bin DEFAULT NULL COMMENT 'camunda地址',\n  `apollo_app_id` varchar(32) COLLATE utf8mb4_bin DEFAULT NULL COMMENT '阿波罗KEYappId',\n  `form_page` varchar(100) COLLATE utf8mb4_bin DEFAULT 'apollo_config_common_form' COMMENT '配置页面地址',\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;\n"
	user := "yearning_dml"
	passwd := "yearning_dml"
	j := json.Config{EscapeHTML: false, IndentionStep: 2}.Froze()

	w := NewWorkRisk("111", addr, "", port, user, passwd, database, sql, nil)
	err = w.IdentifyWorkRiskPreRisk()
	b, _ := j.Marshal(w)
	fmt.Println(string(b))
	return
}
