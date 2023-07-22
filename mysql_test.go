package sqlrisk

import (
	"github.com/DATA-DOG/go-sqlmock"
	"github.com/sunkaimr/sql-risk/comm"
	"testing"
)

func mockDBConn(database string) (*Connector, sqlmock.Sqlmock, error) {
	db, mock, err := sqlmock.New()
	if err != nil {
		return nil, nil, err
	}
	conn := &Connector{
		Database: database,
		Conn:     db,
	}
	return conn, mock, nil
}

func TestExplain(t *testing.T) {
	tests := []struct {
		name  string
		table string
		sql   string
		want  []ExplainInfo
	}{
		{
			name:  "Explain",
			table: "student",
			sql:   "",
			want:  []ExplainInfo{},
		},
	}

	conn, mock, err := mockDBConn("test")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer conn.Close()
	mock.ExpectExec("USE `test`").WillReturnResult(sqlmock.NewResult(0, 0))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rows := mock.NewRows([]string{"id", "select_type", "table", "partitions", "type", "possible_keys", "key", "key_len", "ref", "rows", "filtered", "Extra"})

			rows = rows.AddRow(1, "SIMPLE", "student", "NULL", "NULL", "ALL", "NULL", "NULL", "NULL", 123456, 100.00, "NULL")

			mock.ExpectQuery("^explain").WillReturnRows(rows)

			_, err := conn.Explain(test.sql)
			if err != nil {
				t.Fatalf("Explain(%v) failed, got error: %s", test.sql, err)
			}
		})
	}
}

func TestAffectRows(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want int64
	}{
		{
			name: "select",
			sql:  "select * from student",
			want: 20,
		},
		{
			name: "1",
			sql:  "update student set name='zhangsan' where id = 1",
			want: 1,
		},
		{
			name: "1",
			sql:  "delete from student where id > 1",
			want: 100,
		},
		{
			name: "1",
			sql:  "insert into student (id,name)VALUES(1,'zhangsqn'),(2,'lisi')",
			want: 3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			conn, mock, err := mockDBConn("test")
			if err != nil {
				t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
			}
			mock.ExpectExec("USE `test`").WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectQuery("select").WillReturnRows(mock.NewRows([]string{"COUNT(*)"}).AddRow(test.want))
			sql, _ := comm.DML2Select(test.sql)
			o, err := conn.AffectRows(sql)
			conn.Close()
			if err != nil {
				t.Fatalf("AffectRows(%v) failed, got error: %s", test.sql, err)
			}

			if o != test.want {
				t.Fatalf("AffectRows got: %v, want: %v", o, test.want)
			}
		})
	}
}

func TestTableSize(t *testing.T) {
	tests := []struct {
		name  string
		table string
		sql   string
		want  int
	}{
		{
			name:  "table size",
			table: "student",
			want:  20,
		},
	}

	conn, mock, err := mockDBConn("test")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer conn.Close()

	mock.ExpectExec("USE `test`").WillReturnResult(sqlmock.NewResult(0, 0))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mock.ExpectQuery("^SELECT").WillReturnRows(mock.NewRows([]string{"size"}).AddRow(test.want))
			o, err := conn.TableSize(conn.Database, test.table)
			if err != nil {
				t.Fatalf("TableSize(%v) failed, got error: %s", test.table, err)
			}

			if o != test.want {
				t.Fatalf("TableSize got: %v, want: %v", o, test.want)
			}
		})
	}
}

func TestTableRows(t *testing.T) {
	tests := []struct {
		name  string
		table string
		sql   string
		want  int
	}{
		{
			name:  "table rows",
			table: "student",
			want:  20000,
		},
	}

	conn, mock, err := mockDBConn("test")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer conn.Close()

	mock.ExpectExec("USE `test`").WillReturnResult(sqlmock.NewResult(0, 0))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mock.ExpectQuery("^SELECT TABLE_ROWS").WillReturnRows(mock.NewRows([]string{"TABLE_ROWS"}).AddRow(test.want))
			o, err := conn.TableRows(test.table)
			if err != nil {
				t.Fatalf("TableRows(%v) failed, got error: %s", test.table, err)
			}

			if o != test.want {
				t.Fatalf("TableRows got: %v, want: %v", o, test.want)
			}
		})
	}
}

func TestTableConstraints(t *testing.T) {
	tests := []struct {
		name  string
		table string
		sql   string
		want  [][]string
	}{
		{
			name:  "TableConstraints",
			table: "student",
			want:  [][]string{{"id", "PRIMARY KEY"}, {"phone", "UNIQUE"}},
		},
	}

	conn, mock, err := mockDBConn("test")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer conn.Close()

	mock.ExpectExec("USE `test`").WillReturnResult(sqlmock.NewResult(0, 0))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rows := mock.NewRows([]string{"column", "constraint"})
			for _, w := range test.want {
				rows = rows.AddRow(w[0], w[1])
			}
			mock.ExpectQuery("^SELECT").WillReturnRows(rows)

			o, err := conn.TableConstraints(conn.Database, test.table)
			if err != nil {
				t.Fatalf("TableConstraints(%v) failed, got error: %s", test.table, err)
			}

			if o["id"][0] != "PRIMARY KEY" && o["phone"][0] != "UNIQUE" {
				t.Fatalf("TableConstraints got: %v, want: %v", o, test.want)
			}
		})
	}
}

func TestTableTriggers(t *testing.T) {
	tests := []struct {
		name  string
		table string
		sql   string
		want  []TriggerResult
	}{
		{
			name:  "TableTriggers",
			table: "student",
			want: []TriggerResult{
				{
					Name:   "test_trigger",
					Timing: "INSERT",
					Event:  "AFTER",
					Action: "delete from student where id > 1",
				},
			},
		},
	}

	conn, mock, err := mockDBConn("test")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer conn.Close()

	mock.ExpectExec("USE `test`").WillReturnResult(sqlmock.NewResult(0, 0))

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rows := mock.NewRows([]string{"TRIGGER_NAME", "ACTION_TIMING", "EVENT_MANIPULATION", "ACTION_STATEMENT"})
			for _, w := range test.want {
				rows = rows.AddRow(w.Name, w.Timing, w.Event, w.Action)
			}
			mock.ExpectQuery("^SELECT TRIGGER_NAME").WillReturnRows(rows)

			o, err := conn.TableTriggers(conn.Database, test.table)
			if err != nil {
				t.Fatalf("TableTriggers(%v) failed, got error: %s", test.table, err)
			}

			if !comm.SlicesEqual(o, test.want) {
				t.Fatalf("TableTriggers got: %v, want: %v", o, test.want)
			}
		})
	}
}

func TestTableTransaction(t *testing.T) {
	tests := []struct {
		name  string
		table string
		sql   string
		want  []TrxResult
	}{
		{
			name:  "TableIndex",
			table: "student",
			want: []TrxResult{
				{
					ID:             "103230",
					State:          "RUNNING",
					Started:        "2023-07-03 19:13:04",
					OperationState: "",
					MysqlThreadID:  5411,
					Query:          "",
					TablesLocked:   1,
					RowsLocked:     1000,
					RowsModified:   0,
				},
			},
		},
	}

	conn, mock, err := mockDBConn("test")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer conn.Close()
	mock.ExpectExec("USE `test`").WillReturnResult(sqlmock.NewResult(0, 0))

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rows := mock.NewRows([]string{"trx_id", "trx_state", "trx_started", "trx_operation_state", "trx_mysql_thread_id",
				"trx_query", "trx_tables_locked", "trx_rows_locked", "trx_rows_modified"})
			for _, w := range test.want {
				rows = rows.AddRow(w.ID, w.State, w.Started, w.OperationState, w.MysqlThreadID,
					w.Query, w.TablesLocked, w.RowsLocked, w.RowsModified)
			}
			mock.ExpectQuery("^SELECT").WillReturnRows(rows)

			o, err := conn.TableTransaction()
			if err != nil {
				t.Fatalf("TableTransaction(%v) failed, got error: %s", test.table, err)
			}
			// [{ID:103230 State:RUNNING Started:2023-07-03 19:13:04 OperationState: MysqlThreadID:5411 Query: TablesLocked:1 RowsLocked:1 RowsModified:0}]
			if !comm.SlicesEqual(o, test.want) {
				t.Fatalf("TableTriggers got: %v, want: %v", o, test.want)
			}
		})
	}
}

func TestTableIndex(t *testing.T) {
	tests := []struct {
		name  string
		table string
		sql   string
		want  []IndexResult
	}{
		{
			name:  "TableIndex",
			table: "student",
			want: []IndexResult{
				{
					ColumnName: "id",
					IndexType:  "BTREE",
				},
			},
		},
	}

	conn, mock, err := mockDBConn("test")
	if err != nil {
		t.Fatalf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer conn.Close()
	mock.ExpectExec("USE `test`").WillReturnResult(sqlmock.NewResult(0, 0))
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			rows := mock.NewRows([]string{"COLUMN_NAME", "INDEX_NAME", "NON_UNIQUE", "SEQ_IN_INDEX", "NULLABLE", "INDEX_TYPE", "INDEX_COMMENT"})
			for _, w := range test.want {
				rows = rows.AddRow(w.ColumnName, w.IndexName, w.NonUnique, w.SeqInIndex, w.NullAble, w.IndexType, w.IndexComment)
			}
			mock.ExpectQuery("^SELECT").WillReturnRows(rows)
			o, err := conn.TableIndex(conn.Database, test.table)
			if err != nil {
				t.Fatalf("TableIndex(%v) failed, got error: %s", test.table, err)
			}

			if !comm.SlicesEqual(o, test.want) {
				t.Fatalf("TableIndex got: %v, want: %v", o, test.want)
			}
		})
	}
}
