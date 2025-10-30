package comm

import (
	"fmt"
	"testing"
)

func TestDML2Select(t *testing.T) {
	tests := []struct {
		name   string
		sql    string
		newSql string
	}{
		{"test001", "select id,name from student", "select id,name from student"},
		{"test002", "select count(*) from student", "select count(*) from student"},
		{"test003", "DELETE FROM student;", "select * from student"},
		{"test004", "DELETE FROM `info` WHERE account_no = '309' AND goods_no NOT IN ( '11', '10');", "select * from info where account_no = '309' and goods_no not in ('11', '10')"},
		{"test005", "DELETE t1, t2 FROM tab1 t1 JOIN tab2 t2 ON t1.num_id = t2.id WHERE t2.id=1;", "select * from tab1 as t1 join tab2 as t2 on t1.num_id = t2.id where t2.id = 1"},
		{"test006", "UPDATE org_info SET guidkey = '7CA',codeitemid = '013',gmt_update = NOW() WHERE status=0 AND sapcode = 'A74T';", "select * from org_info where `status` = 0 and sapcode = 'A74T'"},
		{"test007", "UPDATE org_info_snapshot ois, (SELECT oi.id, oi.parent_id, oi.org_path, oi.type, oi.sapcode, oi.guidkey, oi.codeitemid, oi.level FROM org_info oi WHERE oi.status = 0 AND oi.org_path LIKE CONCAT('1/3/5285/3682', '%') ) tmp SET ois.org_path = tmp.org_path, ois.parent_id = tmp.parent_id, ois.sapcode = tmp.sapcode, ois.type = tmp.type, ois.guidkey = tmp.guidkey, ois.codeitemid = tmp.codeitemid, ois.level = tmp.level, ois.gmt_update = NOW() WHERE ois.id = tmp.id AND ( ois.parent_id <> tmp.parent_id OR ois.type <> tmp.type OR ois.org_path <> tmp.org_path OR ois.level <> tmp.level ) AND ois.status = 0 AND ois.org_path LIKE CONCAT('1/3/5285/3682', '%');", "select * from org_info_snapshot as ois, (select oi.id, oi.parent_id, oi.org_path, oi.type, oi.sapcode, oi.guidkey, oi.codeitemid, oi.`level` from org_info as oi where oi.`status` = 0 and oi.org_path like CONCAT('1/3/5285/3682', '%')) as tmp where ois.id = tmp.id and (ois.parent_id != tmp.parent_id or ois.type != tmp.type or ois.org_path != tmp.org_path or ois.`level` != tmp.`level`) and ois.`status` = 0 and ois.org_path like CONCAT('1/3/5285/3682', '%')"},
		{"test008", "INSERT INTO students (id, name, age) VALUES (1, 'Tom', 18), (2, 'Jerry', 20), (3, 'Mike', 22), (4, 'Lucy', 19), (5, 'Bob', 21);", "select 5"},
		{"test009", "INSERT INTO students (id, name, age) VALUES (1, 'Tom', 18)", "select 1"},
		{"test010", "INSERT INTO students_above_20 (id, name, age, gender) SELECT id, name, age, gender FROM students WHERE age > 20;", "select id, `name`, age, gender from students where age > 20"},
		{"test011", "update test.student a, test1.student1 b set a.name = 'a', b.name = 'b' WHERE a.phone = '1'", "select * from test.student as a, test1.student1 as b where a.phone = '1'"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			o, err := DML2Select(test.sql)
			if err != nil {
				t.Fatalf("DML2Select(%v) failed, got error: %s", test.sql, err)
			}
			if o != test.newSql {
				t.Fatalf("DML2Select('%v') failed, got: %s, want: %s", test.sql, o, test.newSql)
			}
		})
	}
}

func TestParseRelatedTableName(t *testing.T) {
	tests := []struct {
		name     string
		SQLText  string
		DataBase string
		want     []string
	}{
		{
			name: "test001", want: []string{"d1.t1", "d2.t2"},
			DataBase: "d1",
			SQLText:  "select * from d1.t1 a join d2.t2 b on a.id = b.id;",
		},
		{
			name: "test002", want: []string{"d1.tab1", "d1.tab2", "d1.tab3"},
			DataBase: "d1",
			SQLText:  "SELECT t1.id, t2.name, t3.age FROM tab1 t1 JOIN tab2 t2 ON t1.id = t2.id JOIN tab3 t3 ON t1.id = t3.id;",
		},
		{
			name: "test003", want: []string{"test.student", "test1.student1"},
			DataBase: "d1",
			SQLText:  "update test.student a, test1.student1 b set a.name = 'a', b.name = 'b' WHERE a.phone = '1'",
		},
		{
			name: "test004", want: []string{"d1.t1", "d2.t2"},
			DataBase: "d1",
			SQLText:  "INSERT INTO d2.t2 (column1, column2, column3) SELECT column1, column2, column3 FROM d1.t1 b WHERE b.id=1;",
		},
		{
			name: "test005", want: []string{"d1.t1", "d1.t3"},
			DataBase: "d1",
			SQLText:  "RENAME TABLE t1 TO t2, t3 TO t4",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			o, err := ExtractingRelatedTableName(test.SQLText, test.DataBase)
			if err != nil {
				t.Fatalf("%v", err)
			}
			if !SlicesEqual(o, test.want) {
				t.Fatalf("DML2Select('%v') failed, got:%v, want:%v", test.SQLText, o, test.want)
			}
		})
	}
}

func TestExtractingTableName(t *testing.T) {
	tests := []struct {
		SQLText  string
		DataBase string
		want     []string
	}{
		{
			want: []string{"d1.t1", "d2.t2"},

			DataBase: "d1",
			SQLText:  "select * from d1.t1 a join d2.t2 b on a.id = b.id;",
		},
		{
			want: []string{"d1.new_tbl"},

			DataBase: "d1",
			SQLText:  "CREATE TABLE new_tbl LIKE orig_tbl;",
		},
		{
			want: []string{"d1.table_name"},

			DataBase: "d1",
			SQLText:  "CREATE INDEX idx_name ON table_name (column_name);",
		},
		//{
		//	want: []string{"d1.table_name"},
		//		DataBase: "d1",
		//		SQLText:  "CREATE VIEW view AS SELECT t1.id, t2.name, t3.age FROM tab1 t1 JOIN tab2 t2 ON t1.id = t2.id JOIN tab3 t3 ON t1.id = t3.id;",
		//},
		{
			want:     []string{"d2.table2"},
			DataBase: "d1",
			SQLText:  "ALTER TABLE d2.table2 ADD COLUMN new_column INT;",
		},
		{
			want:     []string{"d2."},
			DataBase: "d1",
			SQLText:  "DROP DATABASE d2;",
		},
		{
			want:     []string{"d1.table1", "d2.table2", "d3.table3"},
			DataBase: "d1",
			SQLText:  "DROP TABLE table1, d2.table2, d3.table3;",
		},
		{
			want:     []string{"d1.table_name"},
			DataBase: "d1",
			SQLText:  "DROP INDEX index1 ON table_name;",
		},
		{
			want:     []string{"d1.table1"},
			DataBase: "d1",
			SQLText:  "TRUNCATE TABLE table1;",
		},
		{
			want:     []string{"d1.table1", "d2.table2", "d3.table3"},
			DataBase: "d1",
			SQLText:  "RENAME TABLE table1 TO new_table1, d2.table2 TO new_table2, d3.table3 TO new_table3;",
		},
		{
			want:     []string{"d1.tbl_name"},
			DataBase: "d1",
			SQLText:  "INSERT INTO tbl_name (col1,col2) VALUES(15,col1*2);",
		},
		{
			want:     []string{"d1.tbl"},
			DataBase: "d1",
			SQLText:  "INSERT INTO tbl SELECT * FROM tb3 WHERE id > 100;",
		},
		{
			want:     []string{"test.student", "test1.student1", "test2.student2"},
			DataBase: "test",
			SQLText:  "update student a, test1.student1 b, test2.student2 c set a.name = 'aaa', b.name = 'bbb' WHERE a.phone = '111'",
		},
		{
			want:     []string{"d1.tab1"},
			DataBase: "d1",
			SQLText:  "DELETE FROM tab1 t1 WHERE t1.id > 100;",
		},
		{
			want:     []string{"d1.tab1", "d2.tab2"},
			DataBase: "d1",
			SQLText:  "DELETE t1, t2 FROM tab1 t1 JOIN d2.tab2 t2 ON t1.num_id = t2.id JOIN d3.tab3 t3 ON t3.num_id = t2.id WHERE t2.id=1;",
		},
		{
			want:     []string{"d1.table1", "d1.table2", "d2.table3"},
			DataBase: "d1",
			SQLText:  "CREATE VIEW view1 AS SELECT t1.customer_name, t2.order_id, t3.product_name, t3.price FROM table1 t1 JOIN table2 t2 ON t1.customer_id = t2.customer_id JOIN d2.table3 t3 ON t2.order_id = t3.order_id",
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			o, err := ExtractingTableName(test.SQLText, test.DataBase)
			if err != nil {
				t.Fatalf("%v", err)
			}
			//fmt.Println(o)
			if !SlicesEqual(o, test.want) {
				t.Fatalf("ExtractingTableName('%v') failed, got:%v, want:%v", test.SQLText, o, test.want)
			}
		})
	}
}

func TestExtractingWhereColumn(t *testing.T) {
	tests := []struct {
		name     string
		SQLText  string
		DataBase string
		want     map[string][]string
	}{
		{
			name: "test001", want: map[string][]string{"": {"a", "b", "c"}},
			DataBase: "d1",
			SQLText:  "SELECT c1, c2 FROM tab1 WHERE a = 10 AND b = 'vb' AND c in (2, 3);",
		},
		{
			name: "test001", want: map[string][]string{"": {"b"}, "d1.tab1": {"a", "c"}},

			DataBase: "d1",
			SQLText:  "SELECT c1, c2 FROM tab1 t1, tab2, tab3 WHERE t1.a = 10 AND b = 'vb' AND t1.c IN (2, 3);",
		},
		{
			name: "test001", want: map[string][]string{"": {"c3"}},

			DataBase: "d1",
			SQLText:  "SELECT c1, c2 FROM tab1 WHERE c3 IN (SELECT c4 FROM t2 WHERE c5 = 1);",
		},
		{
			name: "test001", want: map[string][]string{"d1.tab2": {"c10"}, "": {"c20"}},

			DataBase: "d1",
			SQLText:  "SELECT t1.c1, t2.c2 FROM tab1 t1 JOIN tab2 t2 ON t1.id = t2.id WHERE t2.c10 > 2 AND c20 = 10;",
		},
		{
			name: "test001", want: map[string][]string{"": {"c1", "c2", "c3"}},

			DataBase: "d1",
			SQLText:  "INSERT INTO tab1 (c1, c2, c3) VALUES (v1, v2, v3);",
		},
		{
			name: "test001", want: map[string][]string{"": {"c1", "c2"}},

			DataBase: "d1",
			SQLText:  "INSERT INTO table1 (c1, c2) SELECT c1, c2 FROM t2 WHERE id >200",
		},
		{
			name: "test001", want: map[string][]string{},

			DataBase: "d1",
			SQLText:  "INSERT INTO tab1 VALUES (v1, v2, v3);",
		},
		{
			name: "test001", want: map[string][]string{"": {"id"}},

			DataBase: "d1",
			SQLText:  "UPDATE tab1 SET name = 'a', age = 10, sex = '男' WHERE id = '1'",
		},
		{
			name: "test001", want: map[string][]string{"test.student": {"phone"}},

			DataBase: "d1",
			SQLText:  "UPDATE test.student a, test1.student1 b, test3.student3 c SET a.name = 'a', b.name = 'b', c.name = 'c' WHERE a.phone = '1'",
		},
		{
			name: "test001", want: map[string][]string{"": {"b"}, "d1.tab1": {"a", "c"}},

			DataBase: "d1",
			SQLText:  "DELETE FROM tab1 t1 WHERE t1.a = 10 AND b = 'vb' AND t1.c IN (2, 3)",
		},
		{
			name: "test001", want: map[string][]string{"": {"call_phone", "called_phone", "gmt_create"}},

			DataBase: "d1",
			SQLText:  "update call_record set call_phone = null, called_phone = null WHERE gmt_create >='2023-04-13 00:00:00' and (call_phone is not null and call_phone != '' or  called_phone is not null and called_phone != '')",
		},
		{
			name: "test001", want: map[string][]string{"": {"phone"}},

			DataBase: "d1",
			SQLText:  "update login_account set phone=null where phone is not null;",
		},
		{
			name: "test001", want: map[string][]string{"": {"id"}},

			DataBase: "d1",
			SQLText:  "DELETE from crowd where id in (1458617,1458630,1458632)",
		},
		{
			name: "test001", want: map[string][]string{"": {"trigger_code", "trigger_time"}},

			DataBase: "d1",
			SQLText:  "SELECT * from crowd where trigger_code = 200 AND trigger_time  < DATE_SUB(NOW(), INTERVAL 7 DAY)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			o, err := ExtractingWhereColumn(test.SQLText, test.DataBase)
			if err != nil {
				t.Fatalf("%v", err)
			}
			//fmt.Println(o)
			if !mapsEqual(o, test.want) {
				t.Fatalf("DML2Select('%v') failed, got:%v, want:%v", test.SQLText, o, test.want)
			}
		})
	}
}

func TestExtractingCreateTableInfo(t *testing.T) {
	tests := []struct {
		name    string
		SQLText string
		want    []TableConstraints
	}{
		{
			name: "test001",
			SQLText: `CREATE TABLE t_table (
id BIGINT ( 20 ) UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '主键',
identifier VARCHAR ( 64 ) DEFAULT NULL COMMENT '用户唯一标识',
item_code VARCHAR ( 64 ) DEFAULT NULL COMMENT '条目编码',
switch_state INT ( 4 ) DEFAULT NULL COMMENT '开关状态',
version_num VARCHAR ( 16 ) NOT NULL DEFAULT '0' COMMENT '版本号',
PRIMARY KEY ( id ),
UNIQUE KEY uk_identifer_item ( identifier, item_code ) USING BTREE,
KEY idx_item_code ( item_code, switch_state, version_num ) USING BTREE 
) ENGINE = INNODB DEFAULT CHARSET = utf8mb4`,
			want: []TableConstraints{
				{
					Name:   "",
					Type:   "PRIMARY KEY",
					Column: []string{"id"},
				},
				{
					Name:   "uk_identifer_item",
					Type:   "UNIQUE",
					Column: []string{"identifier", "item_code"},
				},
				{
					Name:   "idx_item_code",
					Type:   "INDEX",
					Column: []string{"item_code", "switch_state", "version_num"},
				},
			},
		},
		{
			name: "test002",
			SQLText: `
CREATE TABLE my_table (
    id INT AUTO_INCREMENT PRIMARY KEY NOT NULL,
    name VARCHAR(255) NOT NULL,
    age INT NOT NULL,
    email VARCHAR(255) NOT NULL   
) ENGINE=INNODB  COMMENT '测试表';
`,
			want: []TableConstraints{
				{
					Name:   "",
					Type:   "PRIMARY KEY",
					Column: []string{"id"},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			o, err := ExtractingTableConstraints(test.SQLText)
			if err != nil {
				t.Fatalf("%v", err)
			}
			o1 := fmt.Sprintf("%v", o)
			want1 := fmt.Sprintf("%v", test.want)
			if o1 != want1 {
				t.Fatalf("ExtractingTableConstraints('%v') failed, got:%v, want:%v", test.SQLText, o1, want1)
			}
		})
	}
}
