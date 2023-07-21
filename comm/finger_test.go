package comm

import (
	"fmt"
	"testing"
)

func TestFingerPrint(t *testing.T) {
	tests := []struct {
		name  string
		sql   string
		print string
	}{
		{"", "SELECT * FROM student WHERE id=2", "select * from student where id=?"},
		{"", "DROP DATABASE IF EXISTS mydatabase;", "drop database if exists mydatabase"},
		{"", "DROP TABLE IF EXISTS mytable;", "drop table if exists mytable"},
		{"", "DROP PROCEDURE IF EXISTS myprocedure;", "drop procedure if exists myprocedure"},
		{"", "DROP VIEW IF EXISTS myview;", "drop view if exists myview"},
		{"", "DROP TRIGGER IF EXISTS mytrigger;", "drop trigger if exists mytrigger"},
		{"", "TRUNCATE TABLE mytable;", "truncate table mytable"},

		{"", "CREATE TABLE students ( id INT PRIMARY KEY, name VARCHAR(50), age INT, gender VARCHAR(10), grade VARCHAR(10) );", "create table students ( id int primary key, name varchar(?), age int, gender varchar(?), grade varchar(?) )"},
		{"", "CREATE TABLE new_table AS SELECT * FROM existing_table;", "create table new_table as select * from existing_table"},
		{"", "CREATE TEMPORARY TABLE students ( id INT PRIMARY KEY, name VARCHAR(50), age INT, gender VARCHAR(10), grade VARCHAR(10) );", "create temporary table students ( id int primary key, name varchar(?), age int, gender varchar(?), grade varchar(?) )"},
		{"", "CREATE INDEX idx_students_name ON students (name);", "create index idx_students_name on students (name)"},
		{"", "CREATE UNIQUE INDEX idx_students_id ON students (id);", "create unique index idx_students_id on students (id)"},
		{"", "CREATE VIEW customer_order_total AS SELECT customer_id, SUM(total_amount) AS order_total FROM orders GROUP BY customer_id;", "create view customer_order_total as select customer_id, sum(total_amount) as order_total from orders group by customer_id"},

		{"", "ALTER TABLE students ADD COLUMN score DECIMAL(5,2);", "alter table students add column score decimal(?,?)"},
		{"", "ALTER TABLE students DROP COLUMN score;", "alter table students drop column score"},
		{"", "ALTER TABLE students MODIFY COLUMN age INT;", "alter table students modify column age int"},
		{"", "ALTER TABLE students RENAME COLUMN student_name TO full_name;", "alter table students rename column student_name to full_name"},
		{"", "ALTER TABLE students CHANGE COLUMN student_name full_name VARCHAR(100);", "alter table students change column student_name full_name varchar(?)"},
		{"", "ALTER TABLE students ADD CONSTRAINT pk_students PRIMARY KEY (id);", "alter table students add constraint pk_students primary key (id)"},
		{"", "ALTER TABLE my_table DROP PRIMARY KEY;", "alter table my_table drop primary key"},
		{"", "ALTER TABLE my_table ADD UNIQUE INDEX idx_name (column_name);", "alter table my_table add unique index idx_name (column_name)"},
		{"", "ALTER TABLE my_table ADD INDEX idx_name (column_name);", "alter table my_table add index idx_name (column_name)"},
		{"", "ALTER TABLE my_table DROP INDEX idx_nam;", "alter table my_table drop index idx_nam"},

		{"", "INSERT INTO table2 (col1, col2) SELECT col1, col2 FROM table1 WHERE id<100;", "insert into table2 (col1, col2) select col1, col2 from table1 where id<?"},
		{"", "INSERT INTO my_table (col1, col2) VALUES ('Value1', 'Value2');", "insert into my_table (col1, col2) values(?+)"},

		{"", "REPLACE INTO my_table (id, name, age) VALUES (1, 'John', 25);", "replace into my_table (id, name, age) values(?+)"},

		{"", "DELETE FROM my_table", "delete from my_table"},
		{"", "DELETE FROM my_table WHERE id > 100;", "delete from my_table where id > ?"},

		{"", "UPDATE my_table SET col1 = v1;", "update my_table set col1 = v1"},
		{"", "UPDATE my_table SET col1 = v1, col2 = v2 WHERE id=123;", "update my_table set col1 = v1, col2 = v2 where id=?"},
		{"", "UPDATE my_table SET col1 = v1   ;  ", "update my_table set col1 = v1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			o := Finger(test.sql)
			fmt.Println(o, FingerID(o))
			if o != test.print {
				t.Fatalf("Finger('%v') failed, got: %s, want: %s", test.sql, o, test.print)
			}
		})
	}
}
