package comm

import (
	"encoding/json"
	"fmt"
	"github.com/pingcap/tidb/parser"
	"github.com/pingcap/tidb/parser/ast"
	_ "github.com/pingcap/tidb/types/parser_driver"
	"github.com/tidwall/gjson"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"vitess.io/vitess/go/vt/sqlparser"
)

type Level string

const (
	// Fatal 风险等级：致命
	Fatal Level = "fatal"
	// High 风险等级：高
	High Level = "high"
	// Low 风险等级：低
	Low Level = "low"
	// Info 风险等级：提示建议
	Info Level = "info"
)

var LevelMap = map[Level]int{Fatal: 4, High: 3, Low: 2, Info: 1}

type TableConstraints struct {
	Name   string
	Type   string
	Column []string
}

// SplitStatement 将多个SQL语句进行拆分
func SplitStatement(sqls string) []string {
	sqlList := make([]string, 0, 1)
	for {
		if sqls == "" {
			break
		}

		// 查询请求切分
		orgSQL, sql, bufBytes := SplitOneStatement([]byte(sqls), []byte(";"))
		if len(sqls) == len(bufBytes) {
			// 防止切分死循环，当剩余的内容和原 SQL 相同时直接清空 sqls
			sqls = ""
			orgSQL = string(bufBytes)
			sql = orgSQL
		} else {
			sqls = string(bufBytes)
		}

		// 去除无用的备注和空格
		sql = RemoveSQLComments(sql)
		if sql == "" {
			continue
		}

		sqlList = append(sqlList, sql)
	}

	return sqlList
}

// SplitOneStatement SQL切分
// return 1. original sql, 2. remove comment sql, 3. left over buf
func SplitOneStatement(buf []byte, delimiter []byte) (string, string, []byte) {
	var singleLineComment bool
	var multiLineComment bool
	var quoted bool
	var quoteRune byte
	var sql string

	for i := 0; i < len(buf); i++ {
		b := buf[i]
		// single line comment
		if b == '-' {
			if !quoted && i+2 < len(buf) && buf[i+1] == '-' && buf[i+2] == ' ' {
				singleLineComment = true
				i = i + 2
				continue
			}
			if !quoted && i+2 < len(buf) && i == 0 && buf[i+1] == '-' && (buf[i+2] == '\n' || buf[i+2] == '\r') {
				sql = "--\n"
				break
			}
		}

		if b == '#' {
			if !multiLineComment && !quoted && !singleLineComment {
				singleLineComment = true
				continue
			}
		}

		// new line end single line comment
		if b == '\r' || b == '\n' {
			if singleLineComment {
				sql = string(buf[:i])
				singleLineComment = false
				if strings.HasPrefix(strings.TrimSpace(sql), "--") ||
					strings.HasPrefix(strings.TrimSpace(sql), "#") {
					// just comment, query start with '--', '#'
					break
				}
				// comment in multi-line sql
				continue
			}
			continue
		}

		// multi line comment
		// https://dev.mysql.com/doc/refman/8.0/en/comments.html
		// https://dev.mysql.com/doc/refman/8.0/en/optimizer-hints.html
		if b == '/' && i+1 < len(buf) && buf[i+1] == '*' {
			if !multiLineComment && !singleLineComment && !quoted &&
				(buf[i+2] != '!' && buf[i+2] != '+') {
				i = i + 2
				multiLineComment = true
				continue
			}
		}

		if b == '*' && i+1 < len(buf) && buf[i+1] == '/' {
			if multiLineComment && !quoted && !singleLineComment {
				i = i + 2
				multiLineComment = false
				// '/*comment*/'
				if i == len(buf) {
					sql = string(buf[:i])
				}
				// '/*comment*/;', 'select 1/*comment*/;'
				if string(buf[i:]) == string(delimiter) {
					sql = string(buf)
				}
				continue
			}
		}

		// quoted string
		switch b {
		case '`', '\'', '"':
			if i > 1 && buf[i-1] != '\\' {
				if quoted && b == quoteRune {
					quoted = false
					quoteRune = 0
				} else {
					// check if first time found quote
					if quoteRune == 0 {
						quoted = true
						quoteRune = b
					}
				}
			}
		}

		// delimiter
		if !quoted && !singleLineComment && !multiLineComment {
			eof := true
			for k, c := range delimiter {
				if len(buf) > i+k && buf[i+k] != c {
					eof = false
				}
			}
			if eof {
				i = i + len(delimiter)
				sql = string(buf[:i])
				break
			}
		}

		// ended of buf
		if i == len(buf)-1 {
			sql = string(buf)
		}
	}
	orgSQL := string(buf[:len(sql)])
	buf = buf[len(sql):]
	return orgSQL, strings.TrimSuffix(sql, string(delimiter)), buf
}

// RemoveSQLComments 去除SQL中的注释
func RemoveSQLComments(sql string) string {
	buf := []byte(sql)
	// ("(""|[^"]|(\"))*") 双引号中的内容, "", "\""
	// ('(''|[^']|(\'))*') 单引号中的内容, '', '\''
	// (--[^\n\r]*) 双减号注释
	// (#.*) 井号注释
	// (/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/) 多行注释
	commentRegex := regexp.MustCompile(`("(""|[^"]|(\"))*")|('(''|[^']|(\'))*')|(--[^\n\r]*)|(#.*)|(/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/)`)

	res := commentRegex.ReplaceAllFunc(buf, func(s []byte) []byte {
		if (s[0] == '"' && s[len(s)-1] == '"') ||
			(s[0] == '\'' && s[len(s)-1] == '\'') ||
			(string(s[:3]) == "/*!") {
			return s
		}
		return []byte("")
	})
	return strings.TrimSpace(string(res))
}

// ParseRelatedTableName 提取和SQL语句所有相关的库和表
func ParseRelatedTableName(sql string, defaultDB string) ([]string, error) {
	var tables []string
	node, err := TiParse(sql, "", "")
	if err != nil {
		return tables, err
	}

	b, err := json.MarshalIndent(node, "", "  ")
	if err != nil {
		return tables, err
	}
	jsonString := string(b)

	switch n := node.(type) {
	case *ast.UseStmt:
		tables = append(tables, fmt.Sprintf("%s.", n.DBName))
	// SetOprStmt represents "union/except/intersect statement"
	case *ast.InsertStmt, *ast.SelectStmt, *ast.SetOprStmt, *ast.UpdateStmt, *ast.DeleteStmt:
		// DML/DQL: INSERT, SELECT, UPDATE, DELETE
		for _, tableRef := range JSONFind(jsonString, "TableRefs") {
			for _, source := range JSONFind(tableRef, "Source") {
				database := gjson.Get(source, "Schema.O")
				table := gjson.Get(source, "Name.O")
				if database.String() == "" {
					if table.String() != "" {
						tables = append(tables, fmt.Sprintf("%s.%s", defaultDB, table.String()))
					}
				} else {
					if table.String() != "" {
						tables = append(tables, fmt.Sprintf("%s.%s", database.String(), table.String()))
					} else {
						tables = append(tables, fmt.Sprintf("%s.", database.String()))
					}
				}
			}
		}
	case *ast.DropTableStmt:
		// DDL: DROP TABLE|VIEW
		schemas := JSONFind(jsonString, "Tables")
		for _, tabs := range schemas {
			for _, table := range gjson.Parse(tabs).Array() {
				db := gjson.Get(table.String(), "Schema.O")
				tb := gjson.Get(table.String(), "Name.O")
				if db.String() == "" {
					if tb.String() != "" {
						tables = append(tables, fmt.Sprintf("%s.%s", defaultDB, tb.String()))
					}
				} else {
					if tb.String() != "" {
						tables = append(tables, fmt.Sprintf("%s.%s", db.String(), tb.String()))
					}
				}
			}
		}
	case *ast.DropDatabaseStmt, *ast.CreateDatabaseStmt:
		// DDL: DROP|CREATE DATABASE
		schemas := JSONFind(jsonString, "Name")
		for _, schema := range schemas {
			tables = append(tables, fmt.Sprintf("%s.", schema))
		}
	default:
		// DDL: CREATE TABLE|DATABASE|INDEX|VIEW, DROP INDEX
		schemas := JSONFind(jsonString, "Table")
		for _, table := range schemas {
			db := gjson.Get(table, "Schema.O")
			tb := gjson.Get(table, "Name.O")
			if db.String() == "" {
				if tb.String() != "" {
					tables = append(tables, fmt.Sprintf("%s.%s", defaultDB, tb.String()))
				}
			} else {
				if tb.String() != "" {
					tables = append(tables, fmt.Sprintf("%s.%s", db.String(), tb.String()))
				}
			}
		}
	}

	return RemoveDuplicatesItem(tables), nil
}

// ExtractingTableName 从SQL中提取可能改变的库和表
func ExtractingTableName(sql string, defaultDB string) ([]string, error) {
	var tables []string
	node, err := TiParse(sql, "", "")
	if err != nil {
		return tables, err
	}

	switch n := node.(type) {
	case *ast.UseStmt:
		tables = append(tables, fmt.Sprintf("%s.", n.DBName))
	// select 返回涉及到所有表
	case *ast.SelectStmt:
		return ParseRelatedTableName(sql, defaultDB)
	// create操作
	case *ast.CreateDatabaseStmt:
		tables = append(tables, fmt.Sprintf("%s.", n.Name.O))
	case *ast.CreateTableStmt:
		if n.Table.Schema.L != "" {
			defaultDB = n.Table.Schema.L
		}
		tables = append(tables, fmt.Sprintf("%s.%s", defaultDB, n.Table.Name))
	case *ast.CreateIndexStmt:
		if n.Table.Schema.L != "" {
			defaultDB = n.Table.Schema.L
		}
		tables = append(tables, fmt.Sprintf("%s.%s", defaultDB, n.Table.Name))
	//case *ast.CreateViewStmt:
	// 未实现

	// alter操作
	case *ast.AlterDatabaseStmt:
		tables = append(tables, fmt.Sprintf("%s.", n.Name))
	case *ast.AlterTableStmt:
		if n.Table.Schema.L != "" {
			defaultDB = n.Table.Schema.L
		}
		tables = append(tables, fmt.Sprintf("%s.%s", defaultDB, n.Table.Name))
	// drop操作
	case *ast.DropDatabaseStmt:
		tables = append(tables, fmt.Sprintf("%s.", n.Name))
	case *ast.DropTableStmt:
		for _, table := range n.Tables {
			db := defaultDB
			if table.Schema.L != "" {
				db = table.Schema.L
			}
			tables = append(tables, fmt.Sprintf("%s.%s", db, table.Name))
		}
	case *ast.DropIndexStmt:
		if n.Table.Schema.L != "" {
			defaultDB = n.Table.Schema.L
		}
		tables = append(tables, fmt.Sprintf("%s.%s", defaultDB, n.Table.Name))
	case *ast.TruncateTableStmt:
		if n.Table.Schema.L != "" {
			defaultDB = n.Table.Schema.L
		}
		tables = append(tables, fmt.Sprintf("%s.%s", defaultDB, n.Table.Name))
	case *ast.RenameTableStmt:
		for _, table := range n.TableToTables {
			db := defaultDB
			if table.OldTable.Schema.O != "" {
				db = table.OldTable.Schema.O
			}
			tables = append(tables, fmt.Sprintf("%s.%s", db, table.OldTable.Name))
		}

	case *ast.InsertStmt:
		if v, ok := n.Table.TableRefs.Left.(*ast.TableSource); ok {
			if table, ok := v.Source.(*ast.TableName); ok {
				if table.Schema.O != "" {
					defaultDB = table.Schema.O
				}
				tables = append(tables, fmt.Sprintf("%s.%s", defaultDB, table.Name))
			}
		}
	case *ast.UpdateStmt:
		alias := make(map[string]string, 5)
		extractingTableAlias(defaultDB, alias, n.TableRefs.TableRefs.Left, n.TableRefs.TableRefs.Right)
		s := extractingUpdateStmtList(defaultDB, alias, n)
		tables = append(tables, s...)

	case *ast.DeleteStmt:
		alias := make(map[string]string, 5)
		extractingTableAlias(defaultDB, alias, n.TableRefs.TableRefs.Left, n.TableRefs.TableRefs.Right)
		// 单表表删除
		if n.Tables == nil {
			for _, al := range alias {
				tables = append(tables, al)
			}

			if n.TableRefs == nil || n.TableRefs.TableRefs == nil {
				break
			}
			o := extractingTableName(defaultDB, n.TableRefs.TableRefs)
			tables = append(tables, o...)
			break
		}
		// 多表删除
		s := extractingDeleteStmtList(defaultDB, alias, n)
		tables = append(tables, s...)
	}

	return RemoveDuplicatesItem(tables), nil
}

// ExtractingTableConstraints 从表的创建语句中提取表各列的约束信息
func ExtractingTableConstraints(sql string) ([]TableConstraints, error) {
	constraints := make([]TableConstraints, 0, 1)
	node, err := TiParse(sql, "", "")
	if err != nil {
		return nil, err
	}

	switch n := node.(type) {
	case *ast.CreateTableStmt:
		for _, constraint := range n.Constraints {
			c := TableConstraints{}
			switch constraint.Tp {
			case ast.ConstraintPrimaryKey:
				c.Type = "PRIMARY KEY"

			case ast.ConstraintKey:
				c.Type = "KEY"
			case ast.ConstraintIndex:
				c.Type = "INDEX"
			case ast.ConstraintUniq:
				c.Type = "UNIQUE"
			case ast.ConstraintUniqKey:
				c.Type = "UNIQUE KEY"
			case ast.ConstraintUniqIndex:
				c.Type = "UNIQUE INDEX"
			case ast.ConstraintForeignKey:
				c.Type = "FOREIGN KEY"
			case ast.ConstraintFulltext:
				c.Type = "FULLTEXT"
			case ast.ConstraintCheck:
				c.Type = "CHECK"
			}
			c.Name = constraint.Name

			for _, key := range constraint.Keys {
				c.Column = append(c.Column, key.Column.Name.O)
			}
			constraints = append(constraints, c)
		}
	}
	return constraints, nil
}

// ExtractingWhereColumn 从SQL中提取where后跟的条件列
func ExtractingWhereColumn(sql string, defaultDB string) (map[string][]string, error) {
	columns := make(map[string][]string, 5)
	node, err := TiParse(sql, "", "")
	if err != nil {
		return columns, err
	}

	switch n := node.(type) {
	case *ast.SelectStmt:
		alias := make(map[string]string, 5)
		extractingTableAlias(defaultDB, alias, n.From.TableRefs)
		//fmt.Println(alias)
		switch w := n.Where.(type) {
		case *ast.BinaryOperationExpr, *ast.PatternInExpr:
			extractingWhereColumns(defaultDB, alias, columns, w)
		}
	case *ast.InsertStmt:
		alias := make(map[string]string, 5)
		extractingTableAlias(defaultDB, alias, n.Table.TableRefs)
		extractingInsertIntoColumns(defaultDB, alias, columns, n.Columns...)
	case *ast.UpdateStmt:
		alias := make(map[string]string, 5)
		extractingTableAlias(defaultDB, alias, n.TableRefs.TableRefs)
		//extractingSetColumns(defaultDB, alias, columns, n)
		extractingWhereColumns(defaultDB, alias, columns, n.Where)
	case *ast.DeleteStmt:
		alias := make(map[string]string, 5)
		extractingTableAlias(defaultDB, alias, n.TableRefs.TableRefs)
		//fmt.Println(alias)
		switch w := n.Where.(type) {
		case *ast.BinaryOperationExpr, *ast.PatternInExpr:
			extractingWhereColumns(defaultDB, alias, columns, w)
		}
	}

	for k, v := range columns {
		columns[k] = RemoveDuplicatesItem(v)
	}

	return columns, nil
}

// TiParse TiDB 语法解析
func TiParse(sql, charset, collation string) (ast.StmtNode, error) {
	sql = removeIncompatibleWords(sql)
	stmt, err := parser.New().ParseOneStmt(sql, charset, collation)
	if err != nil {
		// issue: https://github.com/XiaoMi/soar/issues/235
		// TODO: bypass charset error, pingcap/parser not support so much charsets
		if strings.Contains(err.Error(), "Unknown character set") {
			err = nil
		}
	}

	return stmt, err
}

// removeIncompatibleWords remove pingcap/parser not support words from schema
func removeIncompatibleWords(sql string) string {
	fields := strings.Fields(strings.TrimSpace(sql))
	if len(fields) == 0 {
		return sql
	}
	switch strings.ToLower(fields[0]) {
	case "create", "alter":
	default:
		return sql
	}
	// CONSTRAINT col_fk FOREIGN KEY (col) REFERENCES tb (id) ON UPDATE CASCADE
	re := regexp.MustCompile(`(?i) ON UPDATE CASCADE`)
	sql = re.ReplaceAllString(sql, "")

	// FULLTEXT KEY col_fk (col) /*!50100 WITH PARSER `ngram` */
	// /*!50100 PARTITION BY LIST (col)
	re = regexp.MustCompile(`/\*!5`)
	sql = re.ReplaceAllString(sql, "/* 5")

	// col varchar(10) CHARACTER SET gbk DEFAULT NULL
	re = regexp.MustCompile(`(?i)CHARACTER SET [a-z_0-9]* `)
	sql = re.ReplaceAllString(sql, "")

	// CREATE TEMPORARY TABLE IF NOT EXISTS t_film AS (SELECT * FROM film);
	re = regexp.MustCompile(`(?i)CREATE TEMPORARY TABLE`)
	sql = re.ReplaceAllString(sql, "CREATE TABLE")

	return sql
}

func JSONFind(json string, name string) []string {
	var find []string
	next := []string{json}
	for len(next) > 0 {
		var tmpNext []string
		for _, subJSON := range next {
			tmpNext = append(tmpNext, jsonFind(subJSON, name, &find)...)
		}
		next = tmpNext
	}
	return find
}

func jsonFind(json string, name string, find *[]string) (next []string) {
	res := gjson.Parse(json)
	res.ForEach(func(key, value gjson.Result) bool {
		if key.String() == name {
			*find = append(*find, value.String())
		}
		switch value.Type {
		case gjson.Number, gjson.True, gjson.False, gjson.Null:
		default:
			// String, JSON
			next = append(next, value.String())
		}
		return true // keep iterating
	})
	return next
}

func RemoveDuplicatesItem(duplicate []string) []string {
	m := make(map[string]bool)
	for _, item := range duplicate {
		if _, ok := m[item]; !ok {
			m[item] = true
		}
	}

	var unique []string
	for item := range m {
		unique = append(unique, item)
	}
	sort.Strings(unique)
	return unique
}

func SplitDataBaseAndTable(tableName string) (string, string) {
	if len(tableName) == 0 {
		return "", ""
	}

	ss := strings.Split(tableName, ".")
	switch len(ss) {
	case 0:
		return "", ""
	case 1:
		return "", ss[0]
	default:
		return ss[0], ss[1]
	}
}

// DML2Select update/delete/insert 语法转为 select
func DML2Select(sql string) (string, error) {
	stmt, err := sqlparser.Parse(sql)
	if err != nil {
		return sql, fmt.Errorf("parse sql failed, %s", err)
	}

	newSQL := sql
	switch st := stmt.(type) {
	case *sqlparser.Select:
		newSQL = sql
	case *sqlparser.Delete: // Multi DELETE not support yet.
		newSQL = delete2Select(st)
	case *sqlparser.Insert:
		newSQL = insert2Select(st)
	case *sqlparser.Update: // Multi UPDATE not support yet.
		newSQL = update2Select(st)
	}

	// 为防止遗漏，用正则方式再改写一次
	newSQL = RewriteReg2Select(newSQL)

	return newSQL, nil
}

// delete2Select 将 Delete 语句改写成 Select
func delete2Select(stmt *sqlparser.Delete) string {
	newSQL := &sqlparser.Select{
		SelectExprs: []sqlparser.SelectExpr{
			new(sqlparser.StarExpr),
		},
		From:    stmt.TableExprs,
		Where:   stmt.Where,
		OrderBy: stmt.OrderBy,
	}
	return sqlparser.String(newSQL)
}

// insert2Select 将 Insert 语句改写成 Select
func insert2Select(stmt *sqlparser.Insert) string {
	switch row := stmt.Rows.(type) {
	// 如果insert包含子查询，只需要explain该子树
	case *sqlparser.Select, *sqlparser.Union:
		return sqlparser.String(row)
	}
	return fmt.Sprintf("select %d", len(stmt.Columns))
}

// update2Select 将 Update 语句改写成 Select
func update2Select(stmt *sqlparser.Update) string {
	newSQL := &sqlparser.Select{
		SelectExprs: []sqlparser.SelectExpr{
			new(sqlparser.StarExpr),
		},
		From:    stmt.TableExprs,
		Where:   stmt.Where,
		OrderBy: stmt.OrderBy,
		Limit:   stmt.Limit,
	}
	return sqlparser.String(newSQL)
}

func RewriteReg2Select(sql string) string {
	var pre = 9
	if len(sql) < pre {
		// SQL to short no need convert
		return sql
	}
	newSQL := sql
	if strings.HasPrefix(strings.ToLower(sql[:pre]), "select") {
		newSQL = sql
	}
	if strings.HasPrefix(strings.ToLower(sql[:pre]), "update") {
		newSQL = regUpdate2Select(sql)
	}
	if strings.HasPrefix(strings.ToLower(sql[:pre]), "delete") {
		newSQL = regDelete2Select(sql)
	}
	return newSQL
}

// regUpdate2Select convert update to select by regexp
func regUpdate2Select(sql string) string {
	sql = strings.TrimSpace(sql)
	sqlRegexp := regexp.MustCompile(`^(?i)update\s+(.*)\s+set\s+(.*)\s+(where\s+.*)$`)
	params := sqlRegexp.FindStringSubmatch(sql)
	if len(params) > 2 {
		return fmt.Sprintf(`select * from %s %s`, params[1], params[3])
	}
	return sql
}

// regDelete2Select convert delete to select by regexp
func regDelete2Select(sql string) string {
	sql = strings.TrimSpace(sql)
	sqlRegexp := regexp.MustCompile(`^(?i)delete\s+from\s+(.*)$`)
	params := sqlRegexp.FindStringSubmatch(sql)
	if len(params) > 1 {
		return fmt.Sprintf(`select * from %s`, params[1])
	}
	return sql
}

func StrToNum(s, spit string, index int) (int, error) {
	if index <= 0 {
		return 0, fmt.Errorf("index cannot be less than 0")
	}

	if spit == "" {
		spit = " "
	}

	ss := strings.Split(s, spit)
	if len(ss) <= index-1 {
		return 0, fmt.Errorf("the string length is insufficient")
	}

	n, err := strconv.Atoi(ss[index-1])
	if err != nil {
		return 0, err
	}
	return n, nil
}

// Select2SelectCount 改写select语句为select COUNT(*) ...
func Select2SelectCount(sql string) (string, error) {
	stmt, err := sqlparser.Parse(sql)
	if err != nil {
		return "", fmt.Errorf("parser sql failed, %s", err)
	}

	selectStmt, ok := stmt.(*sqlparser.Select)
	if !ok {
		return "", fmt.Errorf("not a select statement")
	}

	selectExprs := sqlparser.SelectExprs{
		&sqlparser.AliasedExpr{
			Expr: &sqlparser.FuncExpr{
				Name: sqlparser.NewColIdent("COUNT"),
				Exprs: sqlparser.SelectExprs{
					&sqlparser.StarExpr{},
				},
			},
			As: sqlparser.NewColIdent("row_count"),
		},
	}
	selectStmt.SelectExprs = selectExprs
	return sqlparser.String(stmt), nil
}

// 解析update ... set后的库和表
func extractingUpdateStmtList(defaultDB string, alias map[string]string, stmt *ast.UpdateStmt) []string {
	var tables []string

	if stmt == nil || stmt.TableRefs.TableRefs == nil {
		return tables
	}

	o := extractingTableName(defaultDB, stmt.TableRefs.TableRefs)
	tables = append(tables, o...)

	for _, col := range stmt.List {
		db, tab := defaultDB, col.Column.Table.O
		if al, ok := alias[tab]; ok {
			tables = append(tables, al)
			continue
		}

		if col.Column.Schema.O != "" {
			db = col.Column.Schema.O
		}

		if tab == "" {
			continue
		}

		tables = append(tables, fmt.Sprintf("%s.%s", db, tab))
	}
	return RemoveDuplicatesItem(tables)
}

// delete的库和表
func extractingDeleteStmtList(defaultDB string, alias map[string]string, stmt *ast.DeleteStmt) []string {
	var tables []string
	if stmt == nil || stmt.Tables == nil {
		return tables
	}

	for _, tab := range stmt.Tables.Tables {
		db, tabName := defaultDB, tab.Name.O
		if al, ok := alias[tabName]; ok {
			tables = append(tables, al)
			continue
		}

		if tab.Schema.O != "" {
			db = tab.Schema.O
		}
		tables = append(tables, fmt.Sprintf("%s.%s", db, tabName))
	}
	return RemoveDuplicatesItem(tables)
}

// 建立表别名和真实表的关系
func extractingTableAlias(defaultDB string, aliasMap map[string]string, sets ...ast.ResultSetNode) {
	//n.TableRefs.TableRefs.Left.(*ast.Join).Left
	//n.TableRefs.TableRefs.Left.(*ast.Join).Left.(*ast.TableSource).AsName
	//n.TableRefs.TableRefs.Left.(*ast.Join).Left.(*ast.TableSource).Source.(*ast.Tables).Schema
	//n.TableRefs.TableRefs.Left.(*ast.Join).Left.(*ast.TableSource).Source.(*ast.Tables).Name

	//n.TableRefs.TableRefs.Right.(*ast.TableSource).Source.(*ast.Tables).Schema
	//n.TableRefs.TableRefs.Right.(*ast.TableSource).Source.(*ast.Tables).Name
	//n.TableRefs.TableRefs.Right.(*ast.TableSource).AsName

	for _, set := range sets {
		switch tab := set.(type) {
		case *ast.Join:
			extractingTableAlias(defaultDB, aliasMap, tab.Left, tab.Right)
		case *ast.TableSource:
			as, db, table := tab.AsName.O, defaultDB, ""
			if as == "" {
				continue
			}
			if tabName, ok := tab.Source.(*ast.TableName); !ok {
				continue
			} else {
				db = tabName.Schema.O
				table = tabName.Name.O
			}

			if db == "" {
				db = defaultDB
			}

			aliasMap[as] = fmt.Sprintf("%s.%s", db, table)
		}
	}
}

func extractingTableName(defaultDB string, sets ...ast.ResultSetNode) []string {
	//n.TableRefs.TableRefs.Left.(*ast.Join).Left
	//n.TableRefs.TableRefs.Left.(*ast.Join).Left.(*ast.TableSource).AsName
	//n.TableRefs.TableRefs.Left.(*ast.Join).Left.(*ast.TableSource).Source.(*ast.Tables).Schema
	//n.TableRefs.TableRefs.Left.(*ast.Join).Left.(*ast.TableSource).Source.(*ast.Tables).Name

	//n.TableRefs.TableRefs.Right.(*ast.TableSource).Source.(*ast.Tables).Schema
	//n.TableRefs.TableRefs.Right.(*ast.TableSource).Source.(*ast.Tables).Name
	//n.TableRefs.TableRefs.Right.(*ast.TableSource).AsName
	var tables []string
	for _, set := range sets {
		switch tab := set.(type) {
		case *ast.Join:
			o := extractingTableName(defaultDB, tab.Left, tab.Right)
			tables = append(tables, o...)
		case *ast.TableSource:
			db, table := defaultDB, ""
			if tabName, ok := tab.Source.(*ast.TableName); !ok {
				continue
			} else {
				db = tabName.Schema.O
				table = tabName.Name.O
			}

			if db == "" {
				db = defaultDB
			}

			tables = append(tables, fmt.Sprintf("%s.%s", db, table))
		}
	}
	return tables
}

// 提取where条件后的列名
func extractingWhereColumns(defaultDB string, aliasMap map[string]string, columns map[string][]string, wheres ...ast.ExprNode) {
	//w.L.(*ast.BinaryOperationExpr).L.(*ast.ColumnNameExpr).Name.Schema.O
	//w.L.(*ast.BinaryOperationExpr).L.(*ast.ColumnNameExpr).Name.Table.O
	//w.L.(*ast.BinaryOperationExpr).L.(*ast.ColumnNameExpr).Name.Name.O
	for _, where := range wheres {
		switch col := where.(type) {
		case *ast.BinaryOperationExpr:
			extractingWhereColumns(defaultDB, aliasMap, columns, col.L, col.R)
		case *ast.PatternInExpr:
			extractingWhereColumns(defaultDB, aliasMap, columns, col.Expr)
		case *ast.ParenthesesExpr:
			extractingWhereColumns(defaultDB, aliasMap, columns, col.Expr)
		case *ast.BetweenExpr:
			extractingWhereColumns(defaultDB, aliasMap, columns, col.Expr)
		case *ast.IsNullExpr:
			extractingWhereColumns(defaultDB, aliasMap, columns, col.Expr)
		case *ast.ColumnNameExpr:
			db, tab, c := defaultDB, col.Name.Table.O, col.Name.Name.O
			key := ""
			if al, ok := aliasMap[tab]; ok {
				key = al
			} else {
				// 如果不确定是那个表,也不用关心是库名
				if tab == "" {
					key = ""
				} else {
					key = fmt.Sprintf("%s.%s", db, tab)
				}
			}

			if _, ok := columns[key]; !ok {
				columns[key] = []string{c}
			} else {
				columns[key] = append(columns[key], c)
			}
		}
	}
}

// 提取insert into条件后的列名
func extractingInsertIntoColumns(defaultDB string, aliasMap map[string]string, columns map[string][]string, columnName ...*ast.ColumnName) {
	for _, col := range columnName {
		db, tab, c := defaultDB, col.Table.O, col.Name.O
		key := ""
		if al, ok := aliasMap[tab]; ok {
			key = al
		} else {
			// 如果不确定是那个表,也不用关心是库名
			if tab == "" {
				key = ""
			} else {
				key = fmt.Sprintf("%s.%s", db, tab)
			}
		}

		if _, ok := columns[key]; !ok {
			columns[key] = []string{c}
		} else {
			columns[key] = append(columns[key], c)
		}
	}
}

// 提取update ... set的列名
func extractingSetColumns(defaultDB string, aliasMap map[string]string, columns map[string][]string, updateStmt *ast.UpdateStmt) {
	for _, col := range updateStmt.List {
		db, tab, c := defaultDB, col.Column.Table.O, col.Column.Name.O
		key := ""
		if al, ok := aliasMap[tab]; ok {
			key = al
		} else {
			// 如果不确定是那个表,也不用关心是库名
			if tab == "" {
				key = ""
			} else {
				key = fmt.Sprintf("%s.%s", db, tab)
			}
		}

		if _, ok := columns[key]; !ok {
			columns[key] = []string{c}
		} else {
			columns[key] = append(columns[key], c)
		}
	}
}

func extractingUpdateWhereColumns(defaultDB string, aliasMap map[string]string, columns map[string][]string, updateStmt *ast.UpdateStmt) {
	for _, col := range updateStmt.List {
		db, tab, c := defaultDB, col.Column.Table.O, col.Column.Name.O
		key := ""
		if al, ok := aliasMap[tab]; ok {
			key = al
		} else {
			// 如果不确定是那个表,也不用关心是库名
			if tab == "" {
				key = ""
			} else {
				key = fmt.Sprintf("%s.%s", db, tab)
			}
		}

		if _, ok := columns[key]; !ok {
			columns[key] = []string{c}
		} else {
			columns[key] = append(columns[key], c)
		}
	}
}
