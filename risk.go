package sqlrisk

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/pingcap/tidb/parser"
	"github.com/pingcap/tidb/parser/ast"
	_ "github.com/pingcap/tidb/parser/test_driver"
	"github.com/sunkaimr/sql-risk/comm"
	"github.com/sunkaimr/sql-risk/policy"
	"reflect"
	"sort"
	"strings"
	"time"
)

type SQLRisk struct {
	ID                 uint            `gorm:"primary_key;AUTO_INCREMENT;" json:"id"`
	WorkID             string          `gorm:"type:varchar(64);index:work_id_idx;column:work_id;comment:工单ID" json:"work_id"`
	Addr               string          `gorm:"type:varchar(64);not null;column:addr;comment:数据源地址" json:"addr"`                        // 此地址对应是集群的vip，自建集群无法根据vip查询到监控信息，所以需要配置读写库的地址
	ReadWriteAddr      string          `gorm:"type:varchar(64);not null;column:read_write_addr;comment:读写库的地址" json:"read_write_addr"` // 此地址对应是集群读写库的地址，主要用来查询监控信息
	Port               string          `gorm:"type:varchar(64);not null;column:port;comment:数据源端口" json:"port"`
	User               string          `gorm:"type:varchar(64);not null;column:user;comment:用户名" json:"user"`
	Passwd             string          `gorm:"-" json:"-"`
	DataBase           string          `gorm:"type:varchar(1024);not null;column:data_base;comment:数据库名称" json:"database"`
	RelevantTables     []string        `gorm:"type:json;column:relevant_tables;comment:SQL语句中涉及到所有库、表" json:"relevant_tables"`
	Tables             []string        `gorm:"type:json;column:tables;comment:SQL语句中操作的（增、删、改，查）所有库、表" json:"tables"`
	SQLText            string          `gorm:"type:longtext;column:sql_text;comment:SQL" json:"sql_text"`
	SQLID              string          `gorm:"type:varchar(64);column:sql_id;comment:MD5" json:"sql_id"`
	Finger             string          `gorm:"type:varchar(1024);column:finger;comment:Finger" json:"finger"`
	FingerID           string          `gorm:"type:varchar(64);column:finger_id;comment:FingerID" json:"finger_id"`
	ItemValues         []ItemValue     `gorm:"type:json;column:item_values;comment:风险评估项结果" json:"item_values"`
	MatchedBasicPolicy []policy.Policy `gorm:"type:json;column:matched_basic_policy;comment:匹配到的基本策略" json:"matched_basic_policy"`
	MatchedAggPolicy   policy.Policy   `gorm:"type:json;column:matched_agg_policy;comment:匹配到的聚合策略" json:"matched_agg_policy"`
	InfoPolicy         []policy.Policy `gorm:"type:json;column:info_policy;comment:最终生效的info级别的策略" json:"info_policy"`
	LowPolicy          []policy.Policy `gorm:"type:json;column:low_policy;comment:最终生效的low级别的策略" json:"low_policy"`
	HighPolicy         []policy.Policy `gorm:"type:json;column:high_policy;comment:最终生效的high级别的策略" json:"high_policy"`
	FatalPolicy        []policy.Policy `gorm:"type:json;column:fatal_policy;comment:最终生效的fatal级别的策略" json:"fatal_policy"`
	PreResult          PreResult       `gorm:"type:json;column:pre_result;comment:前置风险识别结果" json:"pre_result"`
	PostResult         PostResult      `gorm:"type:json;column:post_result;comment:后置风险识别结果" json:"post_result"`
	Errors             []ErrorResult   `gorm:"type:json;column:errors;comment:错误信息" json:"errors"`
	Config             *Config         `gorm:"type:json;column:config;comment:相关配置信息" json:"config"`
	Cost               int             `gorm:"type:int;column:cost;comment:识别SQL风险花费时间" json:"cost"`
	cache              map[string]any
}

type ErrorResult struct {
	Type  string `json:"type"`
	Error string `json:"error"`
}

type ItemValue struct {
	Name  string `json:"name"`
	ID    string `json:"id"`
	Value any    `json:"value"`
	Cost  int    `json:"cost"` // 单位ms
}

type PreResult struct {
	// 风险等级
	Level comm.Level `json:"level"`
	// 是否需要走特殊审批
	Special bool `json:"special"`
	// 是否跨BU
	CrossBu bool `json:"cross_bu"`
	//  是否开启跨BU审核
	CrossBuAudit bool `json:"cross_bu_audit"`
}

type PostResult struct {
	// 风险等级
	Level comm.Level `json:"level"`
	// 是否支持自动执行
	Operation int `json:"operation"`
}

// RiskConfig 风险相关配置
type RiskConfig struct {
	// 事务的持续时间
	TxDuration int `json:"tx_duration"`
	// 表行数小于TabRowsThreshold（默认10w）&&表大小小于TabRSizeThreshold（默认2G）时使用DML改查询后select count(*)计算影响行数
	// 否则使用Explain获取影响行数
	TabRowsThreshold int `json:"tab_rows_threshold"`
	TabSizeThreshold int `json:"tab_size_threshold"`
}

func NewSqlRisk(workID, addr, rwAddr, port, user, passwd, database, sql string, config *Config) *SQLRisk {
	if config == nil {
		config = newDefaultConfig()
	}
	return &SQLRisk{
		WorkID:        workID,
		Addr:          addr,
		ReadWriteAddr: rwAddr,
		Port:          port,
		User:          user,
		Passwd:        passwd,
		DataBase:      database,
		SQLText:       sql,
		Config:        config,
		cache:         make(map[string]any, 1),
	}
}

func (c *SQLRisk) IdentifyPreRisk() error {
	var err error
	start := time.Now()
	defer func() {
		c.Cost = int(time.Now().Sub(start).Milliseconds())
	}()

	err = c.SetSQLBasicInfo()
	if err != nil {
		return err
	}

	err = c.CollectPreRiskValues()
	if err != nil {
		return fmt.Errorf("collect risk values failed, %s", err)
	}

	env := make(map[string]any, 5)
	for _, v := range c.ItemValues {
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
	c.MatchedBasicPolicy = matchBasicPolicy
	c.MatchedAggPolicy = matchAggPolicy[0]
	c.SetMatchPolicies(matchPolicy)
	c.SetPreResult(matchPolicy.Level, matchPolicy.Special)

	return nil
}

// SetSQLBasicInfo 设置SQL的基本信息
func (c *SQLRisk) SetSQLBasicInfo() error {
	var err error

	if len(c.SQLID) == 0 {
		c.SQLID = comm.Hash(c.SQLText)
	}

	if len(c.Finger) == 0 {
		c.Finger = comm.Finger(c.SQLText)
	}

	if len(c.FingerID) == 0 {
		c.FingerID = comm.FingerID(c.Finger)
	}

	if len(c.RelevantTables) == 0 {
		c.RelevantTables, err = comm.ExtractingRelatedTableName(c.SQLText, c.DataBase)
		if err != nil {
			return fmt.Errorf("extracting related table name failed, %s", err)
		}
	}

	if len(c.Tables) == 0 {
		c.Tables, err = comm.ExtractingTableName(c.SQLText, c.DataBase)
		if err != nil {
			return fmt.Errorf("extracting table name failed, %s", err)
		}
	}

	if len(c.ItemValues) == 0 {
		start := time.Now()
		ope, act, keyword, err := c.CollectAction()
		cost := int(time.Now().Sub(start).Milliseconds())
		c.SetItemValue(policy.Operate.Name, policy.Operate.ID, ope, cost)
		c.SetItemValue(policy.Action.Name, policy.Action.ID, act, cost)
		c.SetItemValue(policy.KeyWord.Name, policy.KeyWord.ID, keyword, cost)
		if err != nil {
			c.SetItemError(policy.Action.Name, err)
			return err
		}
	}
	return nil
}

// String 以json格式输出
func (c *SQLRisk) String() string {
	buf := bytes.NewBuffer([]byte{})
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(c)
	if err != nil {
		return err.Error()
	}
	return buf.String()
}

func (c *SQLRisk) CollectValueWithCache(name, id string, keys []string, method string, useCache bool) error {
	var err error

	start := time.Now()
	key := strings.Join([]string{strings.Join(c.Tables, "|"), id, strings.Join(keys, "|")}, "|")

	v, ok := c.cache[key]
	if !ok || !useCache {
		m, ok := reflect.TypeOf(c).MethodByName(method)
		if !ok {
			return fmt.Errorf("method %s undefined in %T", method, c)
		}
		res := m.Func.Call([]reflect.Value{reflect.ValueOf(c)})
		for _, r := range res {
			switch r.Kind() {
			case reflect.String:
				v = r.String()
			case reflect.Int:
				v = int(r.Int())
			case reflect.Bool:
				v = r.Bool()
			case reflect.Interface:
				if e, ok := r.Interface().(error); ok {
					err = e
				}
			default:
				return fmt.Errorf("method %s returned an unsupported return value type(%v)", method, r.Kind())
			}
		}
		if err != nil {
			c.SetItemError(name, err)
			return err
		}

		if useCache {
			c.cache[key] = v
		}
	}
	c.SetItemValue(name, id, v, int(time.Now().Sub(start).Milliseconds()))
	return nil
}

func (c *SQLRisk) CollectPreRiskValues() error {
	var err error
	keyword, err := c.GetItemValueWithKeyWordType(policy.KeyWord.ID)
	if err != nil {
		return err
	}

	if keyword == policy.KeyWord.V.CreateTab || keyword == policy.KeyWord.V.CreateTabAs ||
		keyword == policy.KeyWord.V.CreateTmpTab || keyword == policy.KeyWord.V.DropTabIfExist {
		c.SetItemValue(policy.TabExist.Name, policy.TabExist.ID, false, 0)
	} else {
		err = c.CollectValueWithCache(policy.TabExist.Name, policy.TabExist.ID, nil, "CollectTableExist", true)
		if err != nil {
			return err
		}
	}

	err = c.CollectValueWithCache(policy.TabSize.Name, policy.TabSize.ID, nil, "CollectTableSize", true)
	if err != nil {
		return err
	}

	err = c.CollectValueWithCache(policy.TabRows.Name, policy.TabRows.ID, nil, "CollectTableRows", true)
	if err != nil {
		return err
	}

	err = c.CollectValueWithCache(policy.AffectRows.Name, policy.AffectRows.ID, []string{c.SQLID}, "CollectAffectRows", true)
	if err != nil {
		return err
	}

	err = c.CollectValueWithCache(policy.FreeDisk.Name, policy.FreeDisk.ID, nil, "CollectFreeDisk", true)
	if err != nil {
		return err
	}

	err = c.CollectValueWithCache(policy.DiskSufficient.Name, policy.DiskSufficient.ID, nil, "CollectDiskSufficient", true)
	if err != nil {
		return err
	}

	err = c.CollectValueWithCache(policy.PrimaryKeyExist.Name, policy.PrimaryKeyExist.ID, nil, "CollectPrimaryKeyExist", true)
	if err != nil {
		return err
	}

	err = c.CollectValueWithCache(policy.ForeignKeyExist.Name, policy.ForeignKeyExist.ID, nil, "CollectForeignKeyExist", true)
	if err != nil {
		return err
	}

	err = c.CollectValueWithCache(policy.TriggerExist.Name, policy.TriggerExist.ID, nil, "CollectTriggerExist", true)
	if err != nil {
		return err
	}

	err = c.CollectValueWithCache(policy.IndexExistInWhere.Name, policy.IndexExistInWhere.ID, []string{c.SQLID}, "CollectIndexExistInWhere", true)
	if err != nil {
		return err
	}
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
		if st.IfExists {
			return policy.Operate.V.DDL, policy.Action.V.Drop, policy.KeyWord.V.DropTabIfExist, nil
		}
		// 删除表：DROP TABLE mytable;
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
	case *ast.RenameTableStmt:
		return policy.Operate.V.DDL, policy.Action.V.Rename, policy.KeyWord.V.RenameTable, nil
	}
	return policy.Operate.V.Unknown, policy.Action.V.Unknown, policy.KeyWord.V.Unknown, nil
}

// CollectAffectRows 获取SQL的响应行数，依赖CollectAction先执行
// 1, 非DML操作直接返回0
// 2, delete和update没有where条件的属于全表更新直接返回表行数
// 3, 表行数小于10w && 表大小小于2G时 使用DML改查询后select count(*)计算影响行数【优点：准确，缺点：影响性能】
// 4, 其他情况使用Explain获取影响行数【优点：速度快，缺点：统计结果不够准确】
func (c *SQLRisk) CollectAffectRows() (int, error) {
	operate, err := c.GetItemValueWithOperateType(policy.Operate.ID)
	if err != nil {
		return 0, fmt.Errorf("attempt to query Operate for collecting AffectRows failed, %s", err)
	}
	// 只有DML操作才会有影响行数
	if operate != policy.Operate.V.DML {
		return 0, nil
	}

	// 获取表行数
	tabRows, err := c.GetItemValueWithInt(policy.TabRows.ID)
	if err != nil {
		err = c.CollectValueWithCache(policy.TabRows.Name, policy.TabRows.ID, nil, "CollectTableRows", true)
		if err != nil {
			return 0, fmt.Errorf("attempt to collect TabRows for collecting AffectRows failed, %s", err)
		}

		tabRows, err = c.GetItemValueWithInt(policy.TabRows.ID)
		if err != nil {
			return 0, fmt.Errorf("attempt to query TabRows for collecting AffectRows failed, %s", err)
		}
	}

	// 获取表大小
	tabSize, err := c.GetItemValueWithInt(policy.TabSize.ID)
	if err != nil {
		err = c.CollectValueWithCache(policy.TabSize.Name, policy.TabSize.ID, nil, "CollectTableSize", true)
		if err != nil {
			return 0, fmt.Errorf("attempt to collect TabSize for collecting AffectRows failed, %s", err)
		}

		tabSize, err = c.GetItemValueWithInt(policy.TabSize.ID)
		if err != nil {
			return 0, fmt.Errorf("attempt to query TabSize for collecting AffectRows failed, %s", err)
		}
	}

	kw, err := c.GetItemValueWithKeyWordType(policy.KeyWord.ID)
	if err != nil {
		return 0, fmt.Errorf("attempt to query KeyWord for collecting AffectRows failed, %s", err)
	}
	// 没有where条件相当于全表更新,直接返回表行数
	if kw == policy.KeyWord.V.Delete || kw == policy.KeyWord.V.Update {
		return tabRows, nil
	}

	// DML改查询
	selectSQL, err := comm.DML2Select(c.SQLText)
	if err != nil {
		return 0, fmt.Errorf("attempt to DML2Select for collecting AffectRows failed, %s", err)
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
	if tabRows <= c.Config.RiskConfig.TabRowsThreshold && tabSize < c.Config.RiskConfig.TabSizeThreshold {
		// 查询语句的影响行数
		affectRows, err = conn.AffectRows(selectSQL)
		if err != nil {
			return 0, fmt.Errorf("get affect rows failed, %s", err)
		}
	} else {
		explain, err := conn.Explain(selectSQL)
		if err != nil {
			return 0, fmt.Errorf("explain(%s) failed, %s", selectSQL, err)
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
	for _, t := range c.Tables {
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

	for _, t := range c.Tables {
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

	for _, t := range c.Tables {
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
	addr := c.Addr
	if c.ReadWriteAddr != "" {
		addr = c.ReadWriteAddr
	}

	disk, err := NewClient(c.Config.Runtime.Url).DiskFree(addr, time.Now())
	if err == nil {
		return int(disk), nil
	}

	if strings.Contains(err.Error(), NoDataPointError.Error()) {
		// 找不到数据，向前提5min再试一次
		disk, err = NewClient(c.Config.Runtime.Url).DiskFree(addr, time.Now().Add(-5*time.Minute))
		if err != nil {
			return 0, err
		}
	}
	return int(disk), nil
}

// CollectDiskSufficient 磁盘是否充足
func (c *SQLRisk) CollectDiskSufficient() (bool, error) {
	freeDisk, err := c.GetItemValueWithInt(policy.FreeDisk.ID)
	if err != nil {
		err = c.CollectValueWithCache(policy.FreeDisk.Name, policy.FreeDisk.ID, nil, "CollectFreeDisk", true)
		if err != nil {
			return false, fmt.Errorf("attempt to collect FreeDisk for collecting DiskSufficient failed, %s", err)
		}

		freeDisk, err = c.GetItemValueWithInt(policy.FreeDisk.ID)
		if err != nil {
			return false, fmt.Errorf("attempt to query FreeDisk for collecting DiskSufficient failed, %s", err)
		}
	}

	tabSize, err := c.GetItemValueWithInt(policy.TabSize.ID)
	if err != nil {
		err = c.CollectValueWithCache(policy.TabSize.Name, policy.TabSize.ID, nil, "CollectTableSize", true)
		if err != nil {
			return false, fmt.Errorf("attempt to collect TabSize for collecting DiskSufficient failed, %s", err)
		}

		tabSize, err = c.GetItemValueWithInt(policy.TabSize.ID)
		if err != nil {
			return false, fmt.Errorf("attempt to query TabSize for collecting DiskSufficient failed, %s", err)
		}
	}

	return freeDisk > tabSize, nil
}

// CollectCpuUsage CPU使用率
func (c *SQLRisk) CollectCpuUsage() (int, error) {
	addr := c.Addr
	if c.ReadWriteAddr != "" {
		addr = c.ReadWriteAddr
	}
	cpu, err := NewClient(c.Config.Runtime.Url).CpuUsage(addr, time.Now())
	if err == nil {
		return int(cpu), nil
	}

	if strings.Contains(err.Error(), NoDataPointError.Error()) {
		// 找不到数据，向前提5min再试一次
		cpu, err = NewClient(c.Config.Runtime.Url).CpuUsage(addr, time.Now().Add(time.Minute*-5))
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

		// 判断事务运行的时间
		if time.Now().Sub(start) < time.Second*time.Duration(c.Config.RiskConfig.TxDuration) {
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

	tabExist, err := c.GetItemValueWithBool(policy.TabExist.ID)
	if err != nil {
		err = c.CollectValueWithCache(policy.TabExist.Name, policy.TabExist.ID, nil, "CollectTableExist", true)
		if err != nil {
			return false, fmt.Errorf("attempt to collect TabExist for collecting PrimaryKeyExist failed, %s", err)
		}

		tabExist, err = c.GetItemValueWithBool(policy.TabExist.ID)
		if err != nil {
			return false, fmt.Errorf("attempt to query TabExist for collecting PrimaryKeyExist failed, %s", err)
		}
	}

	// 创建表时解析SQL判断是否指定主键
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
	for _, t := range c.Tables {
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
	for _, t := range c.Tables {
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
	for _, t := range c.Tables {
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
	action, err := c.GetItemValueWithActionType(policy.Action.ID)
	if err != nil {
		return false, fmt.Errorf("attempt to query Action for collecting IndexExistInWhere failed, %s", err)
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

	for _, t := range c.Tables {
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
	for _, item := range c.ItemValues {
		if item.ID == id {
			return item.Value
		}
	}
	return nil
}

func (c *SQLRisk) GetItemValueWithOperateType(id string) (policy.OperateType, error) {
	for _, item := range c.ItemValues {
		if item.ID == id {
			if v, ok := item.Value.(policy.OperateType); ok {
				return v, nil
			}
			return "", fmt.Errorf("%s item value(%T) not OperateType", id, item.Value)
		}
	}
	return "", fmt.Errorf("%s item value not found", id)
}

func (c *SQLRisk) GetItemValueWithActionType(id string) (policy.ActionType, error) {
	for _, item := range c.ItemValues {
		if item.ID == id {
			if v, ok := item.Value.(policy.ActionType); ok {
				return v, nil
			}
			return "", fmt.Errorf("%s item value(%T) not ActionType", id, item.Value)
		}
	}
	return "", fmt.Errorf("%s item value not found", id)
}

func (c *SQLRisk) GetItemValueWithKeyWordType(id string) (policy.KeyWordType, error) {
	for _, item := range c.ItemValues {
		if item.ID == id {
			if v, ok := item.Value.(policy.KeyWordType); ok {
				return v, nil
			}
			return "", fmt.Errorf("%s item value(%T) not KeyWordType", id, item.Value)
		}
	}
	return "", fmt.Errorf("%s item value not found", id)
}

func (c *SQLRisk) GetItemValueWithString(id string) (string, error) {
	for _, item := range c.ItemValues {
		if item.ID == id {
			if v, ok := item.Value.(string); ok {
				return v, nil
			}
			return "", fmt.Errorf("%s item value(%T) not string", id, item.Value)
		}
	}
	return "", fmt.Errorf("%s item value not found", id)
}

func (c *SQLRisk) GetItemValueWithInt(id string) (int, error) {
	for _, item := range c.ItemValues {
		if item.ID == id {
			if v, ok := item.Value.(int); ok {
				return v, nil
			}
			return 0, fmt.Errorf("%s item value(%T) not int", id, item.Value)
		}
	}
	return 0, fmt.Errorf("%s item value not found", id)
}

func (c *SQLRisk) GetItemValueWithBool(id string) (bool, error) {
	for _, item := range c.ItemValues {
		if item.ID == id {
			if v, ok := item.Value.(bool); ok {
				return v, nil
			}
			return false, fmt.Errorf("%s item value(%T) not bool", id, item.Value)
		}
	}
	return false, fmt.Errorf("%s item value not found", id)
}

// JudgeItemValue 判断值是否相等
func (c *SQLRisk) JudgeItemValue(id string, value any) bool {
	for _, item := range c.ItemValues {
		if item.ID == id {
			return reflect.DeepEqual(item.Value, value)
		}
	}
	return false
}

// SetItemValue 设置风险结果，如果存在就更新不存在添加
func (c *SQLRisk) SetItemValue(name, id string, v any, cost int) {
	for _, item := range c.ItemValues {
		if item.ID == id {
			item.Value = v
			item.Cost = cost
			return
		}
	}
	c.ItemValues = append(c.ItemValues, ItemValue{Name: name, ID: id, Value: v, Cost: cost})
}

// SetItemError 记录错误信息
func (c *SQLRisk) SetItemError(name string, e error) {
	for i, _ := range c.Errors {
		if c.Errors[i].Type == name && c.Errors[i].Error == e.Error() {
			return
		}
	}

	c.Errors = append(c.Errors, ErrorResult{Type: name, Error: e.Error()})
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
