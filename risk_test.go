package risk

import (
	"github.com/sunkaimr/sql-risk/comm"
	"github.com/sunkaimr/sql-risk/policy"
	"testing"
)

//func TestSoarVersion(t *testing.T) {
//	t.Run("SoarVersion", func(t *testing.T) {
//		if _, err := SoarVersion(); err != nil {
//			t.Fatalf("SoarVersion failed, got error: %s", err)
//		}
//	})
//}
//
//func TestSoarRun(t *testing.T) {
//	tests := []struct {
//		name string
//		sql  string
//		want []string
//	}{
//		{"test000", "select * from sakila;", []string{"CLA.001", "COL.001"}},
//		{"test001", "create index idx1 on tbl (last_name,first_name)", []string{"KEY.004"}},
//	}
//	for _, test := range tests {
//		t.Run(test.name, func(t *testing.T) {
//			got, err := SoarRun(test.sql)
//			if err != nil {
//				t.Fatalf("SoarRun(%v) failed, got error: %s", test.sql, err)
//			}
//
//			gotRules := make([]string, 0, 1)
//			for _, sql := range got {
//				for _, rule := range sql.HeuristicRules {
//					gotRules = append(gotRules, rule.Item)
//				}
//			}
//			if !slicesEqual(gotRules, test.want) {
//				t.Fatalf("SoarRun(%v) got %v, want %v", test.sql, gotRules, test.want)
//			}
//		})
//	}
//}

func TestCollectAction(t *testing.T) {
	tests := []struct {
		name    string
		input   SQLRisk
		act     policy.ActionType
		keyword policy.KeyWordType
	}{
		{"test000", SQLRisk{SQLText: "SELECT * FROM student WHERE id=2;"}, policy.Action.V.Select, policy.KeyWord.V.Select},
		{"test000", SQLRisk{SQLText: "DROP DATABASE IF EXISTS mydatabase;"}, policy.Action.V.Drop, policy.KeyWord.V.DropDB},
		{"test000", SQLRisk{SQLText: "DROP TABLE IF EXISTS mytable;"}, policy.Action.V.Drop, policy.KeyWord.V.DropTab},
		//{"test000", SQLRisk{SQLText: "DROP PROCEDURE IF EXISTS myprocedure;"}, Drop, KeyWord.V.DropProcedure},
		{"test000", SQLRisk{SQLText: "DROP VIEW IF EXISTS myview;"}, policy.Action.V.Drop, policy.KeyWord.V.DropView},
		//{"test000", SQLRisk{SQLText: "DROP TRIGGER IF EXISTS mytrigger;"}, Drop, KeyWord.V.DropTrig},
		{"test000", SQLRisk{SQLText: "TRUNCATE TABLE mytable;"}, policy.Action.V.Truncate, policy.KeyWord.V.TruncateTab},

		{"test000", SQLRisk{SQLText: "CREATE TABLE students ( id INT PRIMARY KEY, name VARCHAR(50), age INT, gender VARCHAR(10), grade VARCHAR(10) );"}, policy.Action.V.Create, policy.KeyWord.V.CreateTab},
		{"test000", SQLRisk{SQLText: "CREATE TABLE new_table AS SELECT * FROM existing_table;"}, policy.Action.V.Create, policy.KeyWord.V.CreateTabAs},
		{"test000", SQLRisk{SQLText: "CREATE TEMPORARY TABLE students ( id INT PRIMARY KEY, name VARCHAR(50), age INT, gender VARCHAR(10), grade VARCHAR(10) );"}, policy.Action.V.Create, policy.KeyWord.V.CreateTmpTab},
		{"test000", SQLRisk{SQLText: "CREATE INDEX idx_students_name ON students (name);"}, policy.Action.V.Create, policy.KeyWord.V.CreateIdx},
		{"test000", SQLRisk{SQLText: "CREATE UNIQUE INDEX idx_students_id ON students (id);"}, policy.Action.V.Create, policy.KeyWord.V.CreateUniIdx},
		{"test000", SQLRisk{SQLText: "CREATE VIEW customer_order_total AS SELECT customer_id, SUM(total_amount) AS order_total FROM orders GROUP BY customer_id;"}, policy.Action.V.Create, policy.KeyWord.V.CreateView},

		{"test000", SQLRisk{SQLText: "ALTER TABLE students ADD COLUMN score DECIMAL(5,2);"}, policy.Action.V.Alter, policy.KeyWord.V.AlertAddCol},
		{"test000", SQLRisk{SQLText: "ALTER TABLE students DROP COLUMN score;"}, policy.Action.V.Alter, policy.KeyWord.V.AlertDropCol},
		{"test000", SQLRisk{SQLText: "ALTER TABLE students MODIFY COLUMN age INT;"}, policy.Action.V.Alter, policy.KeyWord.V.AlertModCol},
		{"test000", SQLRisk{SQLText: "ALTER TABLE `cowell_wxgateway`.`call_record_000` MODIFY COLUMN `call_phone` varchar(20) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '呼叫的电话',MODIFY COLUMN `called_phone` varchar(20) CHARACTER SET utf8 COLLATE utf8_general_ci NULL DEFAULT NULL COMMENT '被呼叫的电话',ADD INDEX `inx_call_phoneSafe`(`call_phone_safe`) USING BTREE,ADD INDEX `inx_called_phoneSafe`(`called_phone_safe`) USING BTREE;"}, policy.Action.V.Alter, policy.KeyWord.V.AlertModCol},
		{"test000", SQLRisk{SQLText: "ALTER TABLE students RENAME COLUMN student_name TO full_name;"}, policy.Action.V.Alter, policy.KeyWord.V.AlertRenameCol},
		{"test000", SQLRisk{SQLText: "ALTER TABLE students CHANGE COLUMN student_name full_name VARCHAR(100);"}, policy.Action.V.Alter, policy.KeyWord.V.AlertChgCol},
		{"test000", SQLRisk{SQLText: "ALTER TABLE students ADD CONSTRAINT pk_students PRIMARY KEY (id);"}, policy.Action.V.Alter, policy.KeyWord.V.AlertAddPriKey},
		{"test000", SQLRisk{SQLText: "ALTER TABLE my_table DROP PRIMARY KEY;"}, policy.Action.V.Alter, policy.KeyWord.V.AlertDropPriKey},
		{"test000", SQLRisk{SQLText: "ALTER TABLE my_table ADD UNIQUE INDEX idx_name (column_name);"}, policy.Action.V.Alter, policy.KeyWord.V.AlertAddUni},
		{"test000", SQLRisk{SQLText: "ALTER TABLE my_table ADD INDEX idx_name (column_name);"}, policy.Action.V.Alter, policy.KeyWord.V.AlertAddIdx},
		{"test000", SQLRisk{SQLText: "ALTER TABLE my_table DROP INDEX idx_nam;"}, policy.Action.V.Alter, policy.KeyWord.V.AlertDropIdx},

		{"test000", SQLRisk{SQLText: "INSERT INTO table2 (col1, col2) SELECT col1, col2 FROM table1 WHERE id<100;"}, policy.Action.V.Insert, policy.KeyWord.V.InsertSelect},
		{"test000", SQLRisk{SQLText: "INSERT INTO my_table (col1, col2) VALUES ('Value1', 'Value2');"}, policy.Action.V.Insert, policy.KeyWord.V.Insert},

		{"test000", SQLRisk{SQLText: "REPLACE INTO my_table (id, name, age) VALUES (1, 'John', 25);"}, policy.Action.V.Replace, policy.KeyWord.V.Replace},

		{"test000", SQLRisk{SQLText: "DELETE FROM my_table"}, policy.Action.V.Delete, policy.KeyWord.V.Delete},
		{"test000", SQLRisk{SQLText: "DELETE FROM my_table WHERE id > 100;"}, policy.Action.V.Delete, policy.KeyWord.V.DeleteWhere},

		{"test000", SQLRisk{SQLText: "UPDATE my_table SET col1 = v1;"}, policy.Action.V.Update, policy.KeyWord.V.Update},
		{"test000", SQLRisk{SQLText: "UPDATE my_table SET col1 = v1, col2 = v2 WHERE id=123;"}, policy.Action.V.Update, policy.KeyWord.V.UpdateWhere},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, act, kw, err := test.input.CollectAction()
			if err != nil {
				t.Fatalf("CollectAction('%v') failed, got error: %s", test.input.SQLText, err)
			}

			if act != test.act || kw != test.keyword {
				t.Fatalf("CollectAction('%v') failed, got %s:%s, want %s:%s", test.input.SQLText,
					act, kw, test.act, test.keyword)
			}
		})
	}
}

func TestCollectAffectRows(t *testing.T) {
	var err error
	tests := []struct {
		name  string
		input SQLRisk
		want  int
	}{
		{
			name: "",
			input: SQLRisk{
				Addr:     "10.2.16.90",
				Port:     "3306",
				User:     "yearning_dml",
				Passwd:   "yearning_dml",
				DataBase: "uaa",
				SQLText:  "update user_base_info_044 set phone=null,address=null;",
			},
			want: 113,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.input.RelevantTableName, err = comm.ParseRelatedTableName(test.input.SQLText, test.input.DataBase)
			if err != nil {
				t.Fatalf("parse related table name failed, %s", err)
			}

			test.input.TableName, err = comm.ExtractingTableName(test.input.SQLText, test.input.DataBase)
			if err != nil {
				t.Fatalf("extracting table name failed, %s", err)
			}

			ope, act, keyword, err := test.input.CollectAction()
			if err != nil {
				test.input.SetItemError(policy.Action.Name, err)
			}
			test.input.SetItemValue(policy.Operate.Name, policy.Operate.ID, ope)
			test.input.SetItemValue(policy.Action.Name, policy.Action.ID, act)
			test.input.SetItemValue(policy.KeyWord.Name, policy.KeyWord.ID, keyword)

			got, err := test.input.CollectAffectRows()
			if err != nil {
				t.Fatalf("CollectAffectRows('%v') failed, got error: %s", test.input.SQLText, err)
			}

			if got != test.want {
				t.Fatalf("CollectAffectRows('%v') failed, got %d, want %d", test.input.SQLText, got, test.want)
			}
		})
	}
}
