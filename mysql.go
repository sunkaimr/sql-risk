package sqlrisk

import (
	"database/sql"
	"fmt"
	"github.com/go-sql-driver/mysql"
	"github.com/sunkaimr/sql-risk/comm"
	"strconv"
	"strings"
	"time"
)

// Connector 数据库连接基本对象
type Connector struct {
	Addr     string
	User     string
	Pass     string
	Database string
	Charset  string
	Conn     *sql.DB
}

// ExplainInfo 用于存放Explain信息
type ExplainInfo struct {
	SQL         string
	ExplainRows []ExplainRow
	Warnings    []ExplainWarning
	//QueryCost     float64
}

// ExplainRow 单行Explain
type ExplainRow struct {
	ID           int
	SelectType   string
	TableName    string
	Partitions   string // explain partitions
	AccessType   string
	PossibleKeys []string
	Key          string
	KeyLen       string // 索引长度，如果发生了index_merge， KeyLen 格式为 N,N，所以不能定义为整型
	Ref          []string
	Rows         int64
	Filtered     float64 // 5.6 JSON, 5.7+, 5.5 EXTENDED
	Scalability  string  // O(1), O(n), O(log n), O(log n)+
	Extra        string
}

// ExplainWarning explain extended 后 SHOW WARNINGS 输出的结果
type ExplainWarning struct {
	Level   string
	Code    int
	Message string
}

// QueryResult 数据库查询返回值
type QueryResult struct {
	Rows    *sql.Rows
	Error   error
	Warning *sql.Rows
	//QueryCost float64
}

// TriggerResult 触发器返回值
type TriggerResult struct {
	Name   string // 触发器名字
	Timing string // 指定触发器响应的事件，如INSERT、UPDATE、DELETE等。
	Event  string // 指定触发器执行的时间，可以是BEFORE（事件发生之前）或AFTER（事件发生之后）
	Action string // 触发器被触发时执行的SQL语句块
}

// TrxResult 查询事务返回值
type TrxResult struct {
	ID             string // 事务的唯一标识符
	State          string // 事务的状态。常见的状态包括RUNNING（运行中）、LOCK WAIT（等待锁）、ROLLING BACK（回滚中）和COMMITTED（已提交）
	Started        string // 事务启动的时间 5s或10s ()
	OperationState string // 事务所处的操作状态。例如，正在执行一个插入操作或删除操作
	MysqlThreadID  int    // 事务所属的MySQL线程ID
	Query          string // 正在执行的事务所执行的SQL
	TablesLocked   int    // 事务当前已经锁住的表格数量。
	RowsLocked     int    // 事务当前锁住的行数。
	RowsModified   int    // 事务已经修改的行数。
}

// IndexResult 查询索引返回值
type IndexResult struct {
	ColumnName   string // 显示索引涉及的列的名称。
	IndexName    string // 显示索引的名称。
	NonUnique    string // 指示索引是否允许重复值。如果值为 0，则表示索引是唯一的；如果值为 1，则表示索引允许重复值。
	SeqInIndex   int    // 指示索引中的列顺序。例如，如果索引包含多个列，则此列将显示它们的相对位置。
	NullAble     string // 表示索引中的列是否允许NULL值。如果值为"YES"，则表示列允许NULL值；如果值为"NO"，则表示列不允许NULL值。
	IndexType    string // 显示索引的类型，如 BTREE、HASH 等。
	IndexComment string // 提供有关索引的注释或其他附加信息。
}

// ExplainScalability ACCESS TYPE对应的运算复杂度 [AccessType]scalability map
var ExplainScalability = map[string]string{
	"NULL":            "NULL",
	"ALL":             "O(n)",
	"index":           "O(n)",
	"range":           "O(log n)+",
	"index_subquery":  "O(log n)+",
	"unique_subquery": "O(log n)+",
	"index_merge":     "O(log n)+",
	"ref_or_null":     "O(log n)+",
	"fulltext":        "O(log n)+",
	"ref":             "O(log n)",
	"eq_ref":          "O(log n)",
	"const":           "O(1)",
	"system":          "O(1)",
}

func NewDSN(host, port, user, passwd, database string) *mysql.Config {
	dsn := mysql.NewConfig()
	dsn.User = user
	dsn.Passwd = passwd
	dsn.Net = "tcp"
	dsn.Addr = fmt.Sprintf("%s:%s", host, port)
	dsn.DBName = database
	dsn.Timeout = time.Second * 3

	return dsn
}

func NewConnector(dsn *mysql.Config) (*Connector, error) {
	conn, err := sql.Open("mysql", dsn.FormatDSN())
	if err != nil {
		return nil, err
	}
	connector := &Connector{
		Addr:     dsn.Addr,
		User:     dsn.User,
		Pass:     dsn.Passwd,
		Database: dsn.DBName,
		Conn:     conn,
	}
	return connector, err
}

func (db *Connector) Close() error {
	if db.Conn != nil {
		return db.Conn.Close()
	}
	return nil
}

// AffectRows 获取 select 查询行数
// 注意：只支持select语句，如果是 update/delete/insert 语法需要使用 DML2Select 进行转换
func (db *Connector) AffectRows(sql string) (int64, error) {
	var err error
	// 改写select语句为select COUNT(*) ...
	sql, err = comm.Select2SelectCount(sql)
	if err != nil {
		return 0, fmt.Errorf("select to SelectCount failed, %s", err)
	}

	res, err := db.Query(sql)
	if err != nil {
		return 0, fmt.Errorf("exec sql query failed, %s", err)
	}

	var rows int64
	// 解析mysql结果
	for res.Rows.Next() {
		err = res.Rows.Scan(&rows)
		if err != nil {
			return 0, fmt.Errorf("scan rows failed, %s", err)
		}
	}
	err = res.Rows.Close()
	if err != nil {
		return 0, fmt.Errorf("close scan rows failed, %s", err)
	}
	return rows, err
}

// TableExist 表是否存在
func (db *Connector) TableExist(d, table string) (bool, error) {
	sqlQuery := fmt.Sprintf("SELECT "+
		"COUNT(*) "+
		"FROM "+
		"INFORMATION_SCHEMA.TABLES "+
		"WHERE "+
		"TABLE_SCHEMA = '%s' AND TABLE_NAME = '%s';", d, table)

	res, err := db.Query(sqlQuery)
	if err != nil {
		return false, fmt.Errorf("exec sql query failed, %s", err)
	}

	count := 0
	// 解析mysql结果
	for res.Rows.Next() {
		err = res.Rows.Scan(&count)
		if err != nil {
			return false, fmt.Errorf("scan rows failed, %s", err)
		}
	}
	err = res.Rows.Close()
	if err != nil {
		return false, fmt.Errorf("close rows size failed, %s", err)
	}
	return count != 0, err
}

// TableSize 查询表大小
func (db *Connector) TableSize(d, table string) (int, error) {
	var err error
	// DATA_LENGTH: 已分配的数据空间的大小
	// INDEX_LENGTH: 已分配的索引空间的大小
	// DATA_FREE: 表中为数据保留的未使用空间的大小, 当数据被删除或更新后，MySQL存储引擎并不会立即回收相应的空间，而是将其标记为未使用状态
	sqlQuery := fmt.Sprintf("SELECT round(((DATA_LENGTH + INDEX_LENGTH + DATA_FREE) / 1024 / 1024), 0) size "+
		"FROM information_schema.TABLES WHERE table_schema = '%s' AND TABLE_NAME = '%s'", d, table)

	res, err := db.Query(sqlQuery)
	if err != nil {
		return 0, fmt.Errorf("exec sql query failed, %s", err)
	}

	size := 0
	// 解析mysql结果
	for res.Rows.Next() {
		err = res.Rows.Scan(&size)
		if err != nil {
			return 0, fmt.Errorf("scan rows failed, %s", err)
		}
	}
	err = res.Rows.Close()
	if err != nil {
		return 0, fmt.Errorf("close rows size failed, %s", err)
	}
	return size, err
}

// TableRows 查询表行数
func (db *Connector) TableRows(table string) (int, error) {
	var err error
	sqlQuery := fmt.Sprintf("SELECT TABLE_ROWS FROM information_schema.TABLES WHERE TABLE_SCHEMA = '%s' AND TABLE_NAME = '%s';", db.Database, table)

	res, err := db.Query(sqlQuery)
	if err != nil {
		return 0, fmt.Errorf("exec sql query failed, %s", err)
	}

	rows := 0
	// 解析mysql结果
	for res.Rows.Next() {
		err = res.Rows.Scan(&rows)
		if err != nil {
			return 0, fmt.Errorf("scan rows failed, %s", err)
		}
	}
	err = res.Rows.Close()
	if err != nil {
		return 0, fmt.Errorf("close scan rows failed, %s", err)
	}
	return rows, err
}

// TableConstraints 查询表包含哪些约束
func (db *Connector) TableConstraints(d, table string) (map[string][]string, error) {
	var err error
	sqlQuery := fmt.Sprintf("SELECT "+
		"CONSTRAINT_NAME, CONSTRAINT_TYPE "+
		"FROM information_schema.TABLE_CONSTRAINTS "+
		"WHERE "+
		"TABLE_SCHEMA = '%s' AND TABLE_NAME = '%s'", d, table)
	res, err := db.Query(sqlQuery)
	if err != nil {
		return nil, fmt.Errorf("exec sql query failed, %s", err)
	}
	constraint := make(map[string]string, 5)
	constraintName, constraintType := "", ""
	for res.Rows.Next() {
		err = res.Rows.Scan(&constraintName, &constraintType)
		if err != nil {
			return nil, fmt.Errorf("scan rows failed, %s", err)
		}
		constraint[constraintName] = constraintType
	}
	err = res.Rows.Close()
	if err != nil {
		return nil, fmt.Errorf("close scan rows failed, %s", err)
	}

	sqlQuery = fmt.Sprintf("SELECT "+
		"CONSTRAINT_NAME, COLUMN_NAME "+
		"FROM information_schema.KEY_COLUMN_USAGE "+
		"WHERE "+
		"TABLE_SCHEMA = '%s' AND TABLE_NAME = '%s'", d, table)
	res, err = db.Query(sqlQuery)
	if err != nil {
		return nil, fmt.Errorf("exec sql query failed, %s", err)
	}

	columnName := ""
	col := make(map[string][]string, 5)
	for res.Rows.Next() {
		err = res.Rows.Scan(&constraintName, &columnName)
		if err != nil {
			return col, fmt.Errorf("scan rows failed, %s", err)
		}
		if _, ok := col[columnName]; ok {
			col[columnName] = append(col[columnName], constraint[constraintName])
		} else {
			col[columnName] = make([]string, 0, 1)
			col[columnName] = append(col[columnName], constraint[constraintName])
		}
	}
	err = res.Rows.Close()
	if err != nil {
		return col, fmt.Errorf("close scan rows failed, %s", err)
	}

	return col, err
}

// TableTriggers 查询表包含哪些触发器
func (db *Connector) TableTriggers(database, table string) ([]TriggerResult, error) {
	var err error
	sqlQuery := fmt.Sprintf(
		"SELECT TRIGGER_NAME, ACTION_TIMING, EVENT_MANIPULATION, ACTION_STATEMENT "+
			"FROM "+
			"information_schema.TRIGGERS "+
			"WHERE "+
			"EVENT_OBJECT_SCHEMA = '%s' "+
			"AND EVENT_OBJECT_TABLE = '%s'", database, table)

	var triggers []TriggerResult
	res, err := db.Query(sqlQuery)
	if err != nil {
		return triggers, fmt.Errorf("exec sql query failed, %s", err)
	}

	// 解析mysql结果
	for res.Rows.Next() {
		t := TriggerResult{}
		err = res.Rows.Scan(&t.Name, &t.Timing, &t.Event, &t.Action)
		if err != nil {
			return triggers, fmt.Errorf("scan rows failed, %s", err)
		}
		triggers = append(triggers, t)
	}
	err = res.Rows.Close()
	if err != nil {
		return triggers, fmt.Errorf("close scan rows failed, %s", err)
	}
	return triggers, err
}

// TableTransaction 查询所有事务
func (db *Connector) TableTransaction() ([]TrxResult, error) {
	var err error
	sqlQuery := fmt.Sprintf(
		"SELECT " +
			"trx_id, trx_state, trx_started, coalesce(trx_operation_state, ''), trx_mysql_thread_id, " +
			"coalesce(trx_query, ''), trx_tables_locked, trx_rows_locked, trx_rows_modified " +
			"FROM " +
			"information_schema.INNODB_TRX")

	var trxs []TrxResult
	res, err := db.Query(sqlQuery)
	if err != nil {
		return trxs, fmt.Errorf("exec sql query failed, %s", err)
	}

	for res.Rows.Next() {
		t := TrxResult{}
		err = res.Rows.Scan(&t.ID, &t.State, &t.Started, &t.OperationState, &t.MysqlThreadID, &t.Query, &t.TablesLocked,
			&t.RowsLocked, &t.RowsModified)
		if err != nil {
			return trxs, fmt.Errorf("scan rows failed, %s", err)
		}
		trxs = append(trxs, t)
	}
	err = res.Rows.Close()
	if err != nil {
		return trxs, fmt.Errorf("close scan rows failed, %s", err)
	}
	return trxs, err
}

// TableIndex 查询表的索引
func (db *Connector) TableIndex(database, table string) ([]IndexResult, error) {
	var err error
	//sqlQuery := fmt.Sprintf("SHOW INDEX FROM %s.%s", database, table)
	sqlQuery := fmt.Sprintf(
		"SELECT "+
			"COLUMN_NAME,INDEX_NAME,NON_UNIQUE,SEQ_IN_INDEX,NULLABLE,INDEX_TYPE,INDEX_COMMENT "+
			"FROM "+
			"INFORMATION_SCHEMA.STATISTICS "+
			"WHERE TABLE_SCHEMA = '%s' AND TABLE_NAME = '%s'", database, table)

	var idxs []IndexResult
	res, err := db.Query(sqlQuery)
	if err != nil {
		return idxs, fmt.Errorf("exec sql query failed, %s", err)
	}

	for res.Rows.Next() {
		t := IndexResult{}
		err = res.Rows.Scan(&t.ColumnName, &t.IndexName, &t.NonUnique, &t.SeqInIndex, &t.NullAble, &t.IndexType, &t.IndexComment)
		if err != nil {
			return idxs, fmt.Errorf("scan rows failed, %s", err)
		}
		idxs = append(idxs, t)
	}
	err = res.Rows.Close()
	if err != nil {
		return idxs, fmt.Errorf("close scan rows failed, %s", err)
	}
	return idxs, err
}

// Explain 获取 SQL 的 explain 信息
func (db *Connector) Explain(sql string) (exp *ExplainInfo, err error) {
	res, err := db.Query(fmt.Sprintf("explain %s", sql))
	if err != nil {
		return exp, err
	}

	// 解析mysql结果，输出ExplainInfo
	exp, err = parseExplainResult(res)
	if err != nil {
		exp.SQL = sql
	}
	return exp, err
}

// parseExplainResult 分析 mysql 执行 explain 的结果，返回 ExplainInfo 结构化数据
func parseExplainResult(res QueryResult) (exp *ExplainInfo, err error) {
	exp = &ExplainInfo{}

	// Different MySQL version has different columns define
	var selectType, table, partitions, accessType, possibleKeys, key, keyLen, ref, extra, rows, filtered []byte
	expRow := ExplainRow{}
	explainFields := make([]interface{}, 0)
	fields := map[string]interface{}{
		"id":            &expRow.ID,
		"select_type":   &selectType,
		"table":         &table,
		"partitions":    &partitions,
		"type":          &accessType,
		"possible_keys": &possibleKeys,
		"key":           &key,
		"key_len":       &keyLen,
		"ref":           &ref,
		"rows":          &rows,
		"filtered":      &filtered,
		"Extra":         &extra,
	}
	cols, err := res.Rows.Columns()
	var colByPass []byte
	for _, col := range cols {
		if _, ok := fields[col]; ok {
			explainFields = append(explainFields, fields[col])
		} else {
			explainFields = append(explainFields, &colByPass)
		}
	}

	// 补全 ExplainRows
	var explainRows []ExplainRow
	for res.Rows.Next() {
		err = res.Rows.Scan(explainFields...)
		if err != nil {
			return nil, err
		}
		expRow.SelectType = NullString(selectType)
		expRow.TableName = NullString(table)
		expRow.Partitions = NullString(partitions)
		expRow.AccessType = NullString(accessType)
		expRow.PossibleKeys = strings.Split(NullString(possibleKeys), ",")
		expRow.Key = NullString(key)
		expRow.KeyLen = NullString(keyLen)
		expRow.Ref = strings.Split(NullString(ref), ",")
		expRow.Rows = NullInt(rows)
		expRow.Filtered = NullFloat(filtered)
		expRow.Extra = NullString(extra)

		// MySQL bug: https://bugs.mysql.com/bug.php?id=34124
		if expRow.Filtered > 100.00 {
			expRow.Filtered = 100.00
		}

		expRow.Scalability = ExplainScalability[expRow.AccessType]
		explainRows = append(explainRows, expRow)
	}
	err = res.Rows.Close()
	if err != nil {
		return nil, err
	}
	exp.ExplainRows = explainRows

	// check explain warning info
	if res.Warning != nil {
		for res.Warning.Next() {
			var expWarning ExplainWarning
			err = res.Warning.Scan(&expWarning.Level, &expWarning.Code, &expWarning.Message)
			if err != nil {
				break
			}

			// 'EXTENDED' is deprecated and will be removed in a future release.
			if expWarning.Code != 1681 {
				exp.Warnings = append(exp.Warnings, expWarning)
			}
		}
		err = res.Warning.Close()
	}

	return exp, err
}

// Query 执行SQL
func (db *Connector) Query(sql string, params ...interface{}) (QueryResult, error) {
	var res QueryResult
	var err error

	if db.Database == "" {
		db.Database = "information_schema"
	}

	_, err = db.Conn.Exec("USE `" + db.Database + "`")
	if err != nil {
		return res, err
	}
	res.Rows, res.Error = db.Conn.Query(sql, params...)

	// SHOW WARNINGS 并不会影响 last_query_cost
	//res.Warning, err = db.Conn.Query("SHOW WARNINGS")

	//cost, err := db.Conn.Query("SHOW SESSION STATUS LIKE 'last_query_cost'")
	//if err == nil {
	//	var varName string
	//	if cost.Next() {
	//		err = cost.Scan(&varName, &res.QueryCost)
	//		common.LogIfError(err, "")
	//	}
	//	if err := cost.Close(); err != nil {
	//		common.Log.Error(err.Error())
	//	}
	//}

	if res.Error != nil && err == nil {
		err = res.Error
	}
	return res, err
}

// NullString null able string
func NullString(buf []byte) string {
	if buf == nil {
		return "NULL"
	}
	return string(buf)
}

// NullFloat null able float
func NullFloat(buf []byte) float64 {
	if buf == nil {
		return 0
	}
	f, _ := strconv.ParseFloat(string(buf), 64)
	return f
}

// NullInt null able int
func NullInt(buf []byte) int64 {
	if buf == nil {
		return 0
	}
	i, _ := strconv.ParseInt(string(buf), 10, 64)
	return i
}
