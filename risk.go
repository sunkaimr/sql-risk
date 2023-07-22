package sqlrisk

import (
	"fmt"
	"github.com/pingcap/tidb/parser"
	"github.com/pingcap/tidb/parser/ast"
	_ "github.com/pingcap/tidb/parser/test_driver"
	"github.com/sunkaimr/sql-risk/comm"
	"github.com/sunkaimr/sql-risk/policy"
	"sort"
	"strings"
	"time"
)

type SQLRisk struct {
	Addr     string
	Port     string
	User     string
	Passwd   string
	DataBase string
	// SQL语句中涉及到所有库、表
	RelevantTableName []string
	// SQL语句中操作的（增、删、改，查）所有库、表
	TableName []string
	SQLText   string

	RiskItems []RiskItem

	MatchBasicPolicy []policy.Policy
	MatchAggPolicy   policy.Policy

	InfoPolicy  []policy.Policy
	LowPolicy   []policy.Policy
	HighPolicy  []policy.Policy
	FatalPolicy []policy.Policy

	PreResult  PreResult
	PostResult PostResult

	Errors []ErrorResult
}

type ErrorResult struct {
	Type  string
	Error error
}

type RiskItem struct {
	Name  string
	ID    string
	Value any
}

type Rule struct {
	Name string
	// 规则表达式
	Expr string
	// 规则优先级
	Priority int
	// 描述
	Description string
	// 风险等级
	Level comm.Level
	// 是否特殊审批
	Special bool
}

type PreResult struct {
	// 风险等级
	Level comm.Level
	// 是否需要走特殊审批
	Special bool
	// 是否跨BU
	CrossBu bool
	//  是否开启跨BU审核
	CrossBuAudit bool
}

type PostResult struct {
	// 风险等级
	Level comm.Level
	// 是否支持自动执行
	Operation int
}

func (c *SQLRisk) IdentifyPreRisk() error {
	var err error

	if len(c.RelevantTableName) == 0 {
		c.RelevantTableName, err = comm.ParseRelatedTableName(c.SQLText, c.DataBase)
		if err != nil {
			return fmt.Errorf("parse related table name failed, %s", err)
		}
	}

	if len(c.TableName) == 0 {
		c.TableName, err = comm.ExtractingTableName(c.SQLText, c.DataBase)
		if err != nil {
			return fmt.Errorf("extracting table name failed, %s", err)
		}
	}

	err = c.CollectPreRiskValues()
	if err != nil {
		return fmt.Errorf("collect preRisk values failed, %s", err)
	}

	env := make(map[string]any, 5)
	for _, v := range c.RiskItems {
		switch v.Value.(type) {
		case policy.OperateType, policy.ActionType, policy.KeyWordType:
			env[v.ID] = fmt.Sprintf("%v", v.Value)
		default:
			env[v.ID] = v.Value
		}
	}

	// 先匹配basic策略
	b, matchBasicPolicy, err := policy.MatchBasicPolicy(env)
	if err != nil {
		return fmt.Errorf("match basic policy failed, %s", err)
	}
	if !b {
		return fmt.Errorf("miss basic policy")
	}

	b, matchAggPolicy, err := policy.MatchAggregatePolicy(matchBasicPolicy)
	if err != nil {
		return fmt.Errorf("match aggregate policy failed, %s", err)
	}
	if !b {
		return fmt.Errorf("miss aggregate policy")
	}

	matchPolicy := policy.Policy{}
	switch matchAggPolicy[0].RuleID {
	case policy.RuleMatch.ID:
		matchPolicy = matchAggPolicy[0]
	case policy.RulePriority.ID:
		sort.Sort(policy.PoliciesListByPriority(matchBasicPolicy))
		switch matchAggPolicy[0].Operator {
		case policy.RuleOperatorHIG:
			matchPolicy = matchBasicPolicy[0]
		case policy.RuleOperatorLOW:
			matchPolicy = matchBasicPolicy[len(matchBasicPolicy)-1]
		}
	case policy.RuleLevel.ID:
		sort.Sort(policy.PoliciesListByLevel(matchBasicPolicy))
		switch matchAggPolicy[0].Operator {
		case policy.RuleOperatorHIG:
			matchPolicy = matchBasicPolicy[0]
		case policy.RuleOperatorLOW:
			matchPolicy = matchBasicPolicy[len(matchBasicPolicy)-1]
		}
	}
	c.MatchBasicPolicy = matchBasicPolicy
	c.MatchAggPolicy = matchAggPolicy[0]
	c.SetMatchPolicies(matchPolicy)
	c.SetPreResult(matchPolicy.Level, matchPolicy.Special)

	return nil
}

func (c *SQLRisk) CollectPreRiskValues() error {
	ope, act, keyword, err := c.CollectAction()
	if err != nil {
		c.SetItemError(policy.Action.Name, err)
	}
	c.SetItemValue(policy.Operate.Name, policy.Operate.ID, ope)
	c.SetItemValue(policy.Action.Name, policy.Action.ID, act)
	c.SetItemValue(policy.KeyWord.Name, policy.KeyWord.ID, keyword)

	if keyword == policy.KeyWord.V.CreateTab || keyword == policy.KeyWord.V.CreateTabAs {
		c.SetItemValue(policy.TabExist.Name, policy.TabExist.ID, false)
	} else {
		exist, err := c.CollectTableExist()
		if err != nil {
			c.SetItemError(policy.TabExist.Name, err)
			return err
		}
		c.SetItemValue(policy.TabExist.Name, policy.TabExist.ID, exist)
	}

	tabSize, err := c.CollectTableSize()
	if err != nil {
		c.SetItemError(policy.TabSize.Name, err)
		return err
	}
	c.SetItemValue(policy.TabSize.Name, policy.TabSize.ID, tabSize)

	tabRows, err := c.CollectTableRows()
	if err != nil {
		c.SetItemError(policy.TabRows.Name, err)
		return err
	}
	c.SetItemValue(policy.TabRows.Name, policy.TabRows.ID, tabRows)

	affectRows, err := c.CollectAffectRows()
	if err != nil {
		c.SetItemError(policy.AffectRows.Name, err)
		return err
	}
	c.SetItemValue(policy.AffectRows.Name, policy.AffectRows.ID, affectRows)

	freeDisk, err := c.CollectFreeDisk()
	if err != nil {
		c.SetItemError(policy.FreeDisk.Name, err)
		return err
	}
	c.SetItemValue(policy.FreeDisk.Name, policy.FreeDisk.ID, freeDisk)

	diskStuff, err := c.CollectDiskSufficient()
	if err != nil {
		c.SetItemError(policy.DiskSufficient.Name, err)
		return err
	}
	c.SetItemValue(policy.DiskSufficient.Name, policy.DiskSufficient.ID, diskStuff)

	primaryKey, err := c.CollectPrimaryKeyExist()
	if err != nil {
		c.SetItemError(policy.PrimaryKeyExist.Name, err)
		return err
	}
	c.SetItemValue(policy.PrimaryKeyExist.Name, policy.PrimaryKeyExist.ID, primaryKey)

	foreignKey, err := c.CollectForeignKeyExist()
	if err != nil {
		c.SetItemError(policy.ForeignKeyExist.Name, err)
		return err
	}
	c.SetItemValue(policy.ForeignKeyExist.Name, policy.ForeignKeyExist.ID, foreignKey)

	trigger, err := c.CollectTriggerExist()
	if err != nil {
		c.SetItemError(policy.TriggerExist.Name, err)
		return err
	}
	c.SetItemValue(policy.TriggerExist.Name, policy.TriggerExist.ID, trigger)

	index, err := c.CollectIndexExistInWhere()
	if err != nil {
		c.SetItemError(policy.IndexExistInWhere.Name, err)
		return err
	}
	c.SetItemValue(policy.IndexExistInWhere.Name, policy.IndexExistInWhere.ID, index)

	return nil
}

// CollectAction 解析SQL的action
// TODO tidb/parser目前还不支持触发器、存储过程、自定义函数、外键
func (c *SQLRisk) CollectAction() (policy.OperateType, policy.ActionType, policy.KeyWordType, error) {
	stmt, err := parser.New().ParseOneStmt(c.SQLText, "", "")
	if err != nil {
		return policy.Operate.V.Unknown, policy.Action.V.Unknown, policy.KeyWord.V.Unknown, fmt.Errorf("parse sql failed, %s", err)
	}

	switch stmt.(type) {
	case *ast.SelectStmt:
		// select
		return policy.Operate.V.DQL, policy.Action.V.Select, policy.KeyWord.V.Select, nil

	/* Drop 相关操作*/
	case *ast.DropTableStmt:
		st := stmt.(*ast.DropTableStmt)
		if st.IsView {
			// 删除视图：DROP VIEW IF EXISTS myview;
			return policy.Operate.V.DDL, policy.Action.V.Drop, policy.KeyWord.V.DropView, nil
		}
		// 删除表：DROP TABLE IF EXISTS mytable;
		return policy.Operate.V.DDL, policy.Action.V.Drop, policy.KeyWord.V.DropTab, nil
	case *ast.DropDatabaseStmt:
		// 删除数据库：DROP DATABASE IF EXISTS mydatabase;
		return policy.Operate.V.DDL, policy.Action.V.Drop, policy.KeyWord.V.DropDB, nil
	case *ast.DropIndexStmt:
		// 删除索引：DROP INDEX IF EXISTS myindex ON mytable;
		return policy.Operate.V.DDL, policy.Action.V.Drop, policy.KeyWord.V.DropIdx, nil
	//case *ast.DropProcedureStmt:
	//	// 删除存储过程：DROP PROCEDURE IF EXISTS myprocedure;
	//	return policy.Operate.V.DDL, policy.Action.V.Drop, policy.KeyWord.V.DropProcedure, nil
	case *ast.TruncateTableStmt:
		// 截断表：TRUNCATE TABLE mytable;
		return policy.Operate.V.DDL, policy.Action.V.Truncate, policy.KeyWord.V.TruncateTab, nil
	case *ast.CreateTableStmt:
		st := stmt.(*ast.CreateTableStmt)
		if st.TemporaryKeyword != ast.TemporaryNone {
			// 创建临时表: CREATE TEMPORARY TABLE students ( id INT PRIMARY KEY, name VARCHAR(50), age INT, gender VARCHAR(10), grade VARCHAR(10) );
			return policy.Operate.V.DDL, policy.Action.V.Create, policy.KeyWord.V.CreateTmpTab, nil
		}
		if st.Select != nil {
			// 从其他表创建: CREATE TABLE new_table AS SELECT * FROM existing_table;
			return policy.Operate.V.DDL, policy.Action.V.Create, policy.KeyWord.V.CreateTabAs, nil
		}
		// 创建表： CREATE TABLE students ( id INT PRIMARY KEY, name VARCHAR(50), age INT, gender VARCHAR(10), grade VARCHAR(10) );
		return policy.Operate.V.DDL, policy.Action.V.Create, policy.KeyWord.V.CreateTab, nil
	case *ast.CreateIndexStmt:
		st := stmt.(*ast.CreateIndexStmt)
		if st.KeyType == ast.IndexKeyTypeUnique {
			// 创建唯一索引：CREATE UNIQUE INDEX idx_students_id ON students (id);
			return policy.Operate.V.DDL, policy.Action.V.Create, policy.KeyWord.V.CreateUniIdx, nil
		}
		// 创建索引：CREATE INDEX idx_students_name ON students (name);
		return policy.Operate.V.DDL, policy.Action.V.Create, policy.KeyWord.V.CreateIdx, nil
	case *ast.CreateViewStmt:
		// 创建视图：CREATE VIEW customer_order_total AS SELECT customer_id, SUM(total_amount) AS order_total FROM orders GROUP BY customer_id;
		return policy.Operate.V.DDL, policy.Action.V.Create, policy.KeyWord.V.CreateView, nil

	/* alert相关操作 */
	case *ast.AlterTableStmt:
		st := stmt.(*ast.AlterTableStmt)
		for _, spec := range st.Specs {
			switch spec.Tp {
			case ast.AlterTableAddColumns:
				// 添加列：ALTER TABLE students ADD COLUMN score DECIMAL(5,2);
				return policy.Operate.V.DDL, policy.Action.V.Alter, policy.KeyWord.V.AlertAddCol, nil
			case ast.AlterTableDropColumn:
				// 删除列：ALTER TABLE students DROP COLUMN score;
				return policy.Operate.V.DDL, policy.Action.V.Alter, policy.KeyWord.V.AlertDropCol, nil
			case ast.AlterTableModifyColumn:
				// 修改列的数据类型或属性：ALTER TABLE students MODIFY COLUMN age INT;
				return policy.Operate.V.DDL, policy.Action.V.Alter, policy.KeyWord.V.AlertModCol, nil
			case ast.AlterTableChangeColumn:
				// 修改表中某个列的名称、数据类型或属性，还可改变列的位置
				// ALTER TABLE table_name CHANGE old_column_name new_column_name column_definition FIRST|AFTER column_name;
				return policy.Operate.V.DDL, policy.Action.V.Alter, policy.KeyWord.V.AlertChgCol, nil
			case ast.AlterTableRenameColumn:
				// 修改表或列的名称: ALTER TABLE students RENAME COLUMN student_name TO full_name;
				return policy.Operate.V.DDL, policy.Action.V.Alter, policy.KeyWord.V.AlertRenameCol, nil
			case ast.AlterTableAddConstraint:
				// 添加约束
				switch spec.Constraint.Tp {
				case ast.ConstraintPrimaryKey:
					// 添加主键约束 ：ALTER TABLE students ADD CONSTRAINT pk_students PRIMARY KEY (id);
					return policy.Operate.V.DDL, policy.Action.V.Alter, policy.KeyWord.V.AlertAddPriKey, nil
				case ast.ConstraintIndex:
					// 添加索引 ALTER TABLE my_table ADD INDEX idx_name (column_name);
					return policy.Operate.V.DDL, policy.Action.V.Alter, policy.KeyWord.V.AlertAddIdx, nil
				case ast.ConstraintUniq, ast.ConstraintUniqIndex:
					// TODO: 添加唯一索引, tidb识别错误会被识别为 ConstraintUniq
					//return Operate.V.DDL, Alter, AlertAddUniIdx, nil
					return policy.Operate.V.DDL, policy.Action.V.Alter, policy.KeyWord.V.AlertAddUni, nil
				}
			case ast.AlterTableDropPrimaryKey:
				// 删除主键：ALTER TABLE my_table DROP PRIMARY KEY;
				return policy.Operate.V.DDL, policy.Action.V.Alter, policy.KeyWord.V.AlertDropPriKey, nil
			case ast.AlterTableDropIndex:
				// 删除索引：ALTER TABLE my_table DROP INDEX idx_nam
				return policy.Operate.V.DDL, policy.Action.V.Alter, policy.KeyWord.V.AlertDropIdx, nil
			}
		}
		// alert的其他操作
		return policy.Operate.V.DDL, policy.Action.V.Alter, policy.KeyWord.V.Alter, nil
	case *ast.InsertStmt:
		st := stmt.(*ast.InsertStmt)
		if st.IsReplace {
			// 替换：REPLACE INTO my_table (id, name, age) VALUES (1, 'John', 25);
			return policy.Operate.V.DML, policy.Action.V.Replace, policy.KeyWord.V.Replace, nil
		}
		if st.Select != nil {
			// 从其他表插入：INSERT INTO table2 (col1, col2) SELECT col1, col2 FROM table1 WHERE id<100;
			return policy.Operate.V.DML, policy.Action.V.Insert, policy.KeyWord.V.InsertSelect, nil
		}
		// 插入：INSERT INTO my_table (col1, col2) VALUES ('Value1', 'Value2');
		return policy.Operate.V.DML, policy.Action.V.Insert, policy.KeyWord.V.Insert, nil
	case *ast.DeleteStmt:
		st := stmt.(*ast.DeleteStmt)
		if st.Where != nil {
			// 带条件删除：delete from my_table where id > 100;
			return policy.Operate.V.DML, policy.Action.V.Delete, policy.KeyWord.V.DeleteWhere, nil
		}
		// 清空表：delete from my_table
		return policy.Operate.V.DML, policy.Action.V.Delete, policy.KeyWord.V.Delete, nil
	case *ast.UpdateStmt:
		st := stmt.(*ast.UpdateStmt)
		if st.Where != nil {
			// 带条件更新：UPDATE my_table SET col1 = v1, col2 = v2 WHERE id=123;
			return policy.Operate.V.DML, policy.Action.V.Update, policy.KeyWord.V.UpdateWhere, nil
		}
		// 全表更新：UPDATE my_table SET col1 = v1;
		return policy.Operate.V.DML, policy.Action.V.Update, policy.KeyWord.V.Update, nil
	}
	return policy.Operate.V.Unknown, policy.Action.V.Unknown, policy.KeyWord.V.Unknown, nil
}

// CollectAffectRows 获取SQL的响应行数，依赖CollectAction先执行
// 1, 非DML操作直接返回0
// 2, delete和update没有where条件的属于全表更新直接返回表行数
// 3, 表行数小于10w&表大小小于2G时使用DML改查询后select count(*)计算影响行数【优点：准确，缺点：影响性能】
// 4, 其他情况使用Explain获取影响行数【优点：速度快，缺点：统计结果不够准确】
func (c *SQLRisk) CollectAffectRows() (int, error) {
	var err error
	value := c.GetItemValue(policy.Operate.ID)
	if value == nil {
		return 0, fmt.Errorf("get %s item value failed, %s is nil", policy.Operate.ID, policy.Operate.ID)
	}
	operate, ok := value.(policy.OperateType)
	if !ok {
		return 0, fmt.Errorf("get %s item value failed, %s(%T) not OperateType", policy.Operate.ID, policy.Operate.ID, value)
	}
	// 只有DML操作才会有影响行数
	if operate != policy.Operate.V.DML {
		return 0, nil
	}

	value = c.GetItemValue(policy.KeyWord.ID)
	if value == nil {
		return 0, fmt.Errorf("get %s item value failed, %s is nil", policy.KeyWord.ID, policy.KeyWord.ID)
	}
	kw, ok := value.(policy.KeyWordType)
	if !ok {
		return 0, fmt.Errorf("get %s item value failed, %s(%T) not KeyWordType", policy.KeyWord.ID, policy.KeyWord.ID, value)
	}

	// 获取表行数
	tabRows := 0
	value = c.GetItemValue(policy.TabRows.ID)
	if value != nil {
		if tabRows, ok = value.(int); !ok {
			return 0, fmt.Errorf("get %s item value failed, %s(%T) not int", policy.TabRows.ID, policy.TabRows.ID, value)
		}
	} else {
		// 查询表行数
		tabRows, err = c.CollectTableRows()
		if err != nil {
			return 0, fmt.Errorf("get table rows failed, %s", err)
		}
	}

	// 获取表大小
	tabSize := 0
	value = c.GetItemValue(policy.TabSize.ID)
	if value != nil {
		if tabSize, ok = value.(int); !ok {
			return 0, fmt.Errorf("get %s item value failed, %s(%T) not int", policy.TabSize.ID, policy.TabSize.ID, value)
		}
	} else {
		// 查询表行数
		tabSize, err = c.CollectTableSize()
		if err != nil {
			return 0, fmt.Errorf("get table size failed, %s", err)
		}
	}

	// 没有where条件相当于全表更新,直接返回表行数
	if kw == policy.KeyWord.V.Delete || kw == policy.KeyWord.V.Update {
		return tabRows, nil
	}

	// DML改查询
	selectSQL, err := comm.DML2Select(c.SQLText)
	if err != nil {
		return 0, fmt.Errorf("get table rows failed, %s", err)
	}

	// 最简单的插入
	if kw == policy.KeyWord.V.Insert {
		rows, _ := comm.StrToNum(selectSQL, " ", 2)
		return rows, nil
	}

	conn, err := NewConnector(NewDSN(c.Addr, c.Port, c.User, c.Passwd, c.DataBase))
	if err != nil {
		return 0, fmt.Errorf("new mysql connect failed, %s", err)
	}
	defer conn.Close()

	var affectRows int64
	if tabRows <= 100000 && tabSize < 2048 {
		// 查询语句的影响行数
		affectRows, err = conn.AffectRows(selectSQL)
		if err != nil {
			return 0, fmt.Errorf("get affect rows failed, %s", err)
		}
	} else {
		explain, err := conn.Explain(c.SQLText)
		if err != nil {
			return 0, fmt.Errorf("explain(%s) failed, %s", c.SQLText, err)
		}

		for _, v := range explain.ExplainRows {
			if v.Rows > affectRows {
				affectRows = v.Rows
			}
		}
	}

	return int(affectRows), nil
}

// CollectTableExist 判断表是否存在
func (c *SQLRisk) CollectTableExist() (bool, error) {
	for _, t := range c.TableName {
		db, tabName := comm.SplitDataBaseAndTable(t)
		if db == "" || tabName == "" {
			continue
		}

		conn, err := NewConnector(NewDSN(c.Addr, c.Port, c.User, c.Passwd, db))
		if err != nil {
			return false, fmt.Errorf("new mysql connect failed, %s", err)
		}

		// 查询表大小
		b, err := conn.TableExist(db, tabName)
		if err != nil {
			return false, err
		}

		if !b {
			return false, fmt.Errorf("table %s.%s not exist", db, tabName)
		}

		if closeErr := conn.Close(); closeErr != nil {
			return false, fmt.Errorf("close connect failed, %s", closeErr)
		}
	}

	return true, nil
}

// CollectTableSize 获取表大小
func (c *SQLRisk) CollectTableSize() (int, error) {
	maxSize := 0

	for _, t := range c.TableName {
		db, tabName := comm.SplitDataBaseAndTable(t)
		if db == "" || tabName == "" {
			continue
		}

		conn, err := NewConnector(NewDSN(c.Addr, c.Port, c.User, c.Passwd, db))
		if err != nil {
			return 0, fmt.Errorf("new mysql connect failed, %s", err)
		}

		// 查询表大小
		size, err := conn.TableSize(db, tabName)

		if closeErr := conn.Close(); closeErr != nil {
			return 0, fmt.Errorf("close connect failed, %s", closeErr)
		}

		if err != nil {
			return 0, fmt.Errorf("get table size failed, %s", err)
		}
		if size > maxSize {
			maxSize = size
		}
	}

	return maxSize, nil
}

// CollectTableRows 获取表的行数
func (c *SQLRisk) CollectTableRows() (int, error) {
	maxRows := 0

	for _, t := range c.TableName {
		db, tabName := comm.SplitDataBaseAndTable(t)
		if db == "" || tabName == "" {
			continue
		}

		conn, err := NewConnector(NewDSN(c.Addr, c.Port, c.User, c.Passwd, db))
		if err != nil {
			return 0, fmt.Errorf("new mysql connect failed, %s", err)
		}

		// 查询表大小
		rows, err := conn.TableRows(tabName)

		if closeErr := conn.Close(); closeErr != nil {
			return 0, fmt.Errorf("close connect failed, %s", closeErr)
		}

		if err != nil {
			return 0, fmt.Errorf("get table rows failed, %s", err)
		}
		if rows > maxRows {
			maxRows = rows
		}
	}

	return maxRows, nil
}

// CollectFreeDisk 剩余磁盘空间
func (c *SQLRisk) CollectFreeDisk() (int, error) {
	disk, err := NewClient(ThanosURL).DiskFree(c.Addr, time.Now())
	if err == nil {
		return int(disk), nil
	}

	if strings.Contains(err.Error(), NoDataPointError.Error()) {
		// 找不到数据，向前提5min再试一次
		disk, err = NewClient(ThanosURL).DiskFree(c.Addr, time.Now().Add(-5*time.Minute))
		if err != nil {
			return 0, err
		}
	}
	return int(disk), nil
}

// CollectDiskSufficient 磁盘是否充足
func (c *SQLRisk) CollectDiskSufficient() (bool, error) {
	var err error
	freeDisk, ok := 0, false
	value := c.GetItemValue(policy.FreeDisk.ID)
	if value != nil {
		if freeDisk, ok = value.(int); !ok {
			return false, fmt.Errorf("get %s item value failed, %s(%T) not int", policy.FreeDisk.ID, policy.FreeDisk.ID, value)
		}
	} else {
		freeDisk, err = c.CollectFreeDisk()
		if err != nil {
			return false, fmt.Errorf("get free disk failed, %s", err)
		}
		c.SetItemValue(policy.FreeDisk.Name, policy.FreeDisk.ID, freeDisk)
	}

	tabSize := 0
	value = c.GetItemValue(policy.TabSize.ID)
	if value != nil {
		if tabSize, ok = value.(int); !ok {
			return false, fmt.Errorf("get %s item value failed, %s(%T) not int", policy.TabSize.ID, policy.TabSize.ID, value)
		}
	} else {
		tabSize, err = c.CollectTableSize()
		if err != nil {
			return false, fmt.Errorf("get table size failed, %s", err)
		}
		c.SetItemValue(policy.TabSize.Name, policy.TabSize.ID, tabSize)
	}

	return freeDisk > tabSize, nil
}

// CollectCpuUsage CPU使用率
func (c *SQLRisk) CollectCpuUsage() (int, error) {
	cpu, err := NewClient(ThanosURL).CpuUsage(c.Addr, time.Now())
	if err == nil {
		return int(cpu), nil
	}

	if strings.Contains(err.Error(), NoDataPointError.Error()) {
		// 找不到数据，向前提5min再试一次
		cpu, err = NewClient(ThanosURL).CpuUsage(c.Addr, time.Now().Add(time.Minute*-5))
		if err != nil {
			return 0, err
		}
	}
	return int(cpu), nil
}

// CollectTranRelated 事务是否与表相关
func (c *SQLRisk) CollectTranRelated() (bool, error) {
	conn, err := NewConnector(NewDSN(c.Addr, c.Port, c.User, c.Passwd, c.DataBase))
	if err != nil {
		return false, fmt.Errorf("new mysql connect failed, %s", err)
	}

	// 查询事务
	trxs, err := conn.TableTransaction()
	if err != nil {
		return false, fmt.Errorf("query table transaction failed, %s", err)
	}

	if closeErr := conn.Close(); closeErr != nil {
		return false, fmt.Errorf("close connect failed, %s", closeErr)
	}

	// risk中SQL涉及的库和表
	var riskTables []string
	// 事务中涉及的库和表
	var trxTables []string

	riskTables, err = comm.ExtractingTableName(c.SQLText, c.DataBase)
	if err != nil {
		return false, fmt.Errorf("extracting SQL(%s) table name failed, %s", c.SQLText, err)
	}

	for _, trx := range trxs {
		// RUNNING, LOCK WAIT, ROLLING BACK, COMMITTING, COMMITTED, ROLLED BACK, PREPARED, ACTIVE
		if trx.State == "" {
			continue
		}
		start, err := time.Parse("2006-01-02 15:04:05", trx.Started)
		if err != nil {
			continue
		}

		// TODO 时间需要可配
		// 判断事务运行的时间
		if time.Now().Sub(start) < time.Second*10 {
			continue
		}

		trxTables, err = comm.ExtractingTableName(trx.Query, c.DataBase)
		if err != nil {
			return false, fmt.Errorf("extracting trx.Query(%s) table name failed, %s", trx.Query, err)
		}

		// 判断riskTables, trxTables是否有交集
		intersect := comm.Intersect(riskTables, trxTables)
		if len(intersect) != 0 {
			// TODO 有交集，返回交集
			return true, fmt.Errorf(
				"The table(%v) is involved in an ongoing transaction, trx.ID:%s, trx.Query(%s) ", intersect, trx.ID, trx.Query)
		}
	}
	return false, nil
}

// CollectPrimaryKeyExist 是否存在主键
func (c *SQLRisk) CollectPrimaryKeyExist() (bool, error) {
	var err error

	// 创建表时解析SQL判断是否指定主键
	tabExist, ok := false, false
	value := c.GetItemValue(policy.TabExist.ID)
	if value != nil {
		if tabExist, ok = value.(bool); !ok {
			return false, fmt.Errorf("get %s item value failed, %s(%T) not int", policy.TabExist.ID, policy.TabExist.ID, value)
		}
	} else {
		// 查询表行数
		tabExist, err = c.CollectTableExist()
		if err != nil {
			return false, fmt.Errorf("get table exist failed, %s", err)
		}
	}

	if !tabExist {
		constraints, err := comm.ExtractingTableConstraints(c.SQLText)
		if err != nil {
			return false, fmt.Errorf("extracting table constraints failed, %s", err)
		}

		for _, c := range constraints {
			if c.Type == "PRIMARY KEY" {
				return true, nil
			}
		}
		return false, nil
	}

	// 表存在时判断连库判断主键
	for _, t := range c.TableName {
		db, tabName := comm.SplitDataBaseAndTable(t)
		if db == "" || tabName == "" {
			continue
		}

		conn, err := NewConnector(NewDSN(c.Addr, c.Port, c.User, c.Passwd, db))
		if err != nil {
			return false, fmt.Errorf("new mysql connect failed, %s", err)
		}

		// 查询表的约束
		columnsConstraints, err := conn.TableConstraints(db, tabName)

		if closeErr := conn.Close(); closeErr != nil {
			return false, fmt.Errorf("close connect failed, %s", closeErr)
		}

		if err != nil {
			return false, fmt.Errorf("get table rows failed, %s", err)
		}

		for _, constraints := range columnsConstraints {
			for _, cc := range constraints {
				if cc == "PRIMARY KEY" {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// CollectForeignKeyExist 是否存在外键
func (c *SQLRisk) CollectForeignKeyExist() (bool, error) {
	for _, t := range c.TableName {
		db, tabName := comm.SplitDataBaseAndTable(t)
		if db == "" || tabName == "" {
			continue
		}

		conn, err := NewConnector(NewDSN(c.Addr, c.Port, c.User, c.Passwd, db))
		if err != nil {
			return false, fmt.Errorf("new mysql connect failed, %s", err)
		}

		// 查询表的约束
		columnsConstraints, err := conn.TableConstraints(db, tabName)

		if closeErr := conn.Close(); closeErr != nil {
			return false, fmt.Errorf("close connect failed, %s", closeErr)
		}

		if err != nil {
			return false, fmt.Errorf("get table rows failed, %s", err)
		}

		for _, constraints := range columnsConstraints {
			for _, cc := range constraints {
				if cc == "FOREIGN KEY" {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// CollectTriggerExist 是否存在触发器
func (c *SQLRisk) CollectTriggerExist() (bool, error) {
	for _, t := range c.TableName {
		db, tabName := comm.SplitDataBaseAndTable(t)
		if db == "" || tabName == "" {
			continue
		}

		conn, err := NewConnector(NewDSN(c.Addr, c.Port, c.User, c.Passwd, db))
		if err != nil {
			return false, fmt.Errorf("new mysql connect failed, %s", err)
		}

		// 查询表的触发器
		triggers, err := conn.TableTriggers(db, tabName)

		if closeErr := conn.Close(); closeErr != nil {
			return false, fmt.Errorf("close connect failed, %s", closeErr)
		}

		if err != nil {
			return false, fmt.Errorf("get table rows failed, %s", err)
		}

		if len(triggers) > 0 {
			return true, nil
		}
	}

	return false, nil
}

// CollectIndexExistInWhere where条件中是否存在索引,只针对delete和update生效
func (c *SQLRisk) CollectIndexExistInWhere() (bool, error) {
	value := c.GetItemValue(policy.Action.ID)
	if value == nil {
		return false, fmt.Errorf("get %s item value failed, %s is nil", policy.Action.ID, policy.Action.ID)
	}
	action, ok := value.(policy.ActionType)
	if !ok {
		return false, fmt.Errorf("get %s item value failed, %s(%T) not KeyWordType", policy.Action.ID, policy.Action.ID, value)
	}

	// 只针对delete和update生效
	if action != policy.Action.V.Delete && action != policy.Action.V.Update {
		return false, nil
	}

	// 查询SQL Where条件后涉及到的所有表的所有列
	columns, err := comm.ExtractingWhereColumn(c.SQLText, c.DataBase)
	if err != nil {
		return false, fmt.Errorf("extracting where column failed, %s", err)
	}

	for _, t := range c.TableName {
		db, tabName := comm.SplitDataBaseAndTable(t)
		if db == "" || tabName == "" {
			continue
		}

		conn, err := NewConnector(NewDSN(c.Addr, c.Port, c.User, c.Passwd, db))
		if err != nil {
			return false, fmt.Errorf("new mysql connect failed, %s", err)
		}

		// 查询表的索引
		indexs, err := conn.TableIndex(db, tabName)

		if closeErr := conn.Close(); closeErr != nil {
			return false, fmt.Errorf("close connect failed, %s", closeErr)
		}

		if err != nil {
			return false, fmt.Errorf("get table index failed, %s", err)
		}

		tabCols, ok := columns[t]
		if !ok {
			if tabCols, ok = columns[""]; !ok {
				continue
			}
		}

		for _, index := range indexs {
			for _, col := range tabCols {
				if index.ColumnName == col {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// GetItemValue 根据风险ID获取对应的结果
func (c *SQLRisk) GetItemValue(id string) any {
	for _, item := range c.RiskItems {
		if item.ID == id {
			return item.Value
		}
	}
	return nil
}

// SetItemValue 设置风险结果，如果存在就更新不存在添加
func (c *SQLRisk) SetItemValue(name, id string, v any) {
	for _, item := range c.RiskItems {
		if item.ID == id {
			item.Value = v
			return
		}
	}
	c.RiskItems = append(c.RiskItems, RiskItem{Name: name, ID: id, Value: v})
}

// SetItemError 记录错误信息
func (c *SQLRisk) SetItemError(name string, e error) {
	c.Errors = append(c.Errors, ErrorResult{Type: name, Error: e})
}

// SetMatchPolicies 记录匹配到的策略
func (c *SQLRisk) SetMatchPolicies(p policy.Policy) {
	switch p.Level {
	case comm.Fatal:
		c.FatalPolicy = append(c.FatalPolicy, p)
	case comm.High:
		c.HighPolicy = append(c.HighPolicy, p)
	case comm.Low:
		c.LowPolicy = append(c.LowPolicy, p)
	case comm.Info:
		c.InfoPolicy = append(c.InfoPolicy, p)
	}
}

// SetPreResult 记录前置风险的风险等级
func (c *SQLRisk) SetPreResult(lev comm.Level, special bool) {
	c.PreResult.Level = lev
	c.PreResult.Special = special
}

type PreResultList []PreResult
type PostResultList []PostResult

func (a PreResultList) Len() int {
	return len(a)
}

// Less 排序，先按风险等级，最后按是否走特殊流程
func (a PreResultList) Less(i, j int) bool {
	if comm.LevelMap[a[i].Level] < comm.LevelMap[a[j].Level] {
		return false
	} else if comm.LevelMap[a[i].Level] > comm.LevelMap[a[j].Level] {
		return true
	}

	if a[i].Special {
		return false
	}
	return true
}

func (a PreResultList) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a PostResultList) Len() int {
	return len(a)
}

// Less 排序，先按风险等级，最后按是否走特殊流程
func (a PostResultList) Less(i, j int) bool {
	if comm.LevelMap[a[i].Level] < comm.LevelMap[a[j].Level] {
		return false
	} else if comm.LevelMap[a[i].Level] > comm.LevelMap[a[j].Level] {
		return true
	}

	return false
}

func (a PostResultList) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
