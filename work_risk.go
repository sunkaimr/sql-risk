package sqlrisk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sunkaimr/sql-risk/comm"
	"github.com/sunkaimr/sql-risk/policy"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	ParseSQL     = "SQL解析"
	Authority    = "权限检验"
	IdentifyRisk = "风险识别"
)

type WorkRisk struct {
	ID            uint            `gorm:"primary_key;AUTO_INCREMENT;" json:"id"`
	WorkID        string          `gorm:"type:varchar(64);index:work_id_idx;column:work_id;comment:工单ID" json:"work_id"`
	Addr          string          `gorm:"type:varchar(64);not null;column:addr;comment:数据源地址" json:"addr"`                        // 此地址对应是集群的vip，自建集群无法根据vip查询到监控信息，所以需要配置读写库的地址
	ReadWriteAddr string          `gorm:"type:varchar(64);not null;column:read_write_addr;comment:读写库的地址" json:"read_write_addr"` // 此地址对应是集群读写库的地址，主要用来查询监控信息
	Port          string          `gorm:"type:varchar(64);not null;column:port;comment:数据源端口" json:"port"`
	User          string          `gorm:"type:varchar(64);not null;column:user;comment:用户名" json:"user"`
	Passwd        string          `gorm:"-" json:"-"`
	DataBase      string          `gorm:"type:varchar(1024);not null;column:data_base;comment:数据库名称" json:"database"`
	Table         string          `gorm:"type:varchar(1024);column:addr;comment:表名" json:"table"`
	SQLText       string          `gorm:"type:longtext;column:sql_text;comment:SQL" json:"sql_text"`
	SQLRisks      []*SQLRisk      `gorm:"-;comment:各个SQL风险" json:"sql_risks"`
	Summary       Summary         `gorm:"type:json;column:summary;comment:工单概要信息" json:"summary"`
	InfoPolicy    []policy.Policy `gorm:"type:json;column:info_policy;comment:最终生效的info级别的策略" json:"info_policy"`
	LowPolicy     []policy.Policy `gorm:"type:json;column:low_policy;comment:最终生效的low级别的策略" json:"low_policy"`
	HighPolicy    []policy.Policy `gorm:"type:json;column:high_policy;comment:最终生效的high级别的策略" json:"high_policy"`
	FatalPolicy   []policy.Policy `gorm:"type:json;column:fatal_policy;comment:最终生效的fatal级别的策略" json:"fatal_policy"`
	PreResult     PreResult       `gorm:"type:json;column:pre_result;comment:前置风险识别结果" json:"pre_result"`
	PostResult    PostResult      `gorm:"type:json;column:post_result;comment:后置风险识别结果" json:"post_result"`
	Errors        []ErrorResult   `gorm:"type:json;column:errors;comment:错误信息" json:"errors"`
	Config        *Config         `gorm:"type:json;column:config;comment:相关配置信息" json:"config"`
	Cost          int             `gorm:"type:int;column:cost;comment:识别工单风险花费时间" json:"cost"`
	cache         map[string]any
}

type Config struct {
	Runtime    Client     `json:"runtime"`
	RiskConfig RiskConfig `json:"risk_config"`
}

type Summary struct {
	DataBaseNum int `json:"data_base_num"`
	TableNum    int `json:"table_num"`
	SQLCount    int `json:"sql_count"`
	ErrorCount  int `json:"error_count"`
	FatalCount  int `json:"fatal_count"`
	HighCount   int `json:"high_count"`
	LowCount    int `json:"low_count"`
	InfoCount   int `json:"info_count"`
}

func NewWorkRisk(workID, addr, rwAddr, port, user, passwd, database, sql string, config *Config) *WorkRisk {
	if config == nil {
		config = newDefaultConfig()
	}
	return &WorkRisk{
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

func newDefaultConfig() *Config {
	return &Config{
		Runtime: Client{Url: string([]byte{104, 116, 116, 112, 58, 47, 47, 116, 104, 97, 110, 111, 115, 45, 114, 101, 97, 108, 116, 105, 109, 101, 46, 99, 111, 119, 101, 108, 108, 116, 101, 99, 104, 46, 99, 111, 109})},
		RiskConfig: RiskConfig{
			TxDuration:       10,
			TabRowsThreshold: 100000,
			TabSizeThreshold: 2048,
		},
	}
}

// IdentifyWorkRiskPreRisk 对工单进行前置风险识别
func (c *WorkRisk) IdentifyWorkRiskPreRisk() error {
	start := time.Now()
	defer func() {
		c.Cost = int(time.Now().Sub(start).Milliseconds())
		c.CalculateSummary()
	}()

	// 对工单中的sql语句进行拆分
	err := c.SplitStatement()
	if err != nil {
		err = fmt.Errorf("split statement failed, %s", err)
		c.SetPreResult(comm.Fatal, false)
		c.SetItemError(ParseSQL, err)
		return err
	}

	if len(c.SQLRisks) == 0 {
		err = errors.New("no SQL found")
		c.SetPreResult(comm.Fatal, false)
		c.SetItemError(ParseSQL, err)
		return err
	}

	for i, _ := range c.SQLRisks {
		err = c.SQLRisks[i].SetSQLBasicInfo()
		if err != nil {
			c.SetPreResult(comm.Fatal, false)
			c.SetItemError(ParseSQL, err)
			return err
		}
	}

	// 统计信息
	c.CalculateSummary()

	// 校验是否对库进行越权操作
	err = c.ExceedingPermissions()
	if err != nil {
		c.SetPreResult(comm.Fatal, false)
		c.SetItemError(Authority, err)
		return err
	}

	// 抽样检测
	// insert：按SQL指纹进行采样检测
	c.SampDetectForInsert()

	matchedPolicies := make([]policy.Policy, 0, len(c.SQLRisks))
	// 遍历SQL进行前置风险识别
	for i, _ := range c.SQLRisks {
		err = c.SQLRisks[i].IdentifyPreRisk()
		if err != nil {
			err = fmt.Errorf("identify sql risk failed, %s", err)
			c.SetPreResult(comm.Fatal, false)
			c.SetItemError(IdentifyRisk, err)
			return err
		}

		matchedPolicies = append(matchedPolicies, c.SQLRisks[i].InfoPolicy...)
		matchedPolicies = append(matchedPolicies, c.SQLRisks[i].LowPolicy...)
		matchedPolicies = append(matchedPolicies, c.SQLRisks[i].HighPolicy...)
		matchedPolicies = append(matchedPolicies, c.SQLRisks[i].FatalPolicy...)
	}

	// 一个工单只能包含一种操作类型
	//operate := make(map[string]struct{})
	//for i, _ := range c.SQLRisks {
	//	o := fmt.Sprintf("%v", c.SQLRisks[i].GetItemValue(policy.Operate.ID))
	//	operate[o] = struct{}{}
	//}
	//if len(operate) > 1 {
	//	err = errors.New("")
	//	c.SetPreResult(comm.Fatal, false)
	//	c.SetItemError(Authority, err)
	//}

	sort.Sort(policy.PoliciesListByLevel(matchedPolicies))
	if len(matchedPolicies) == 0 {
		err = errors.New("no matched Policies found")
		c.SetPreResult(comm.Fatal, false)
		c.SetItemError(IdentifyRisk, err)
		return err
	}
	c.SetMatchPolicies(matchedPolicies[0])
	c.SetPreResult(matchedPolicies[0].Level, matchedPolicies[0].Special)
	return nil
}

// SplitStatement 将多个SQL语句进行拆分
func (c *WorkRisk) SplitStatement() error {
	idx := strings.Index(c.SQLText, " ")
	if idx != -1 {
		c.SQLText = regexp.MustCompile(` `).ReplaceAllString(c.SQLText, " ")
		c.SetItemError(ParseSQL, fmt.Errorf("column %d near found chinese encoded characters", idx))
	}

	sqlList := comm.SplitStatement(c.SQLText)
	for _, sql := range sqlList {
		sqlRisk := &SQLRisk{
			WorkID:        c.WorkID,
			Addr:          c.Addr,
			ReadWriteAddr: c.ReadWriteAddr,
			Port:          c.Port,
			User:          c.User,
			Passwd:        c.Passwd,
			DataBase:      c.DataBase,
			SQLText:       sql,
			Errors:        nil,
			Config:        c.Config,
			cache:         c.cache,
		}
		c.SQLRisks = append(c.SQLRisks, sqlRisk)
	}

	return nil
}

// ExceedingPermissions 校验是否对库进行越权操作
func (c *WorkRisk) ExceedingPermissions() error {
	for _, sqlRisk := range c.SQLRisks {
		var database []string

		for _, tabName := range sqlRisk.RelevantTables {
			d, _ := comm.SplitDataBaseAndTable(tabName)
			database = append(database, d)
		}

		if !comm.EleExist(sqlRisk.DataBase, database) {
			return fmt.Errorf("check exceeding permissions not pass, database(%s) not in %v", sqlRisk.DataBase, database)
		}
	}

	return nil
}

// SetPreResult 记录前置风险的风险等级
func (c *WorkRisk) SetPreResult(lev comm.Level, special bool) {
	c.PreResult.Level = lev
	c.PreResult.Special = special
}

// SetItemError 记录错误信息
func (c *WorkRisk) SetItemError(name string, e error) {
	c.Errors = append(c.Errors, ErrorResult{Type: name, Error: e.Error()})
}

// SetMatchPolicies 记录匹配到的策略
func (c *WorkRisk) SetMatchPolicies(ps ...policy.Policy) {
	for _, p := range ps {
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
}

// String 以json格式输出
func (c *WorkRisk) String() string {
	buf := bytes.NewBuffer([]byte{})
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(c)
	if err != nil {
		return err.Error()
	}
	return buf.String()
}

// SampDetectForInsert 采样检测insert语句
func (c *WorkRisk) SampDetectForInsert() *WorkRisk {
	m := make(map[string]struct{}, len(c.SQLRisks))
	deleteItem := make([]int, 0, len(c.SQLRisks))
	for i, r := range c.SQLRisks {
		if _, ok := m[r.FingerID]; !ok && r.JudgeItemValue(policy.KeyWord.ID, policy.KeyWord.V.Insert) {
			m[r.FingerID] = struct{}{}
		} else {
			deleteItem = append(deleteItem, i)
		}
	}

	for i := len(deleteItem) - 1; i >= 0; i-- {
		index := deleteItem[i]
		c.SQLRisks = append(c.SQLRisks[:index], c.SQLRisks[index+1:]...)
	}
	return c
}

func (c *WorkRisk) CalculateSummary() *WorkRisk {
	if c.Summary.DataBaseNum == 0 || c.Summary.TableNum == 0 || c.Summary.SQLCount == 0 {
		database := make(map[string]struct{}, len(c.SQLRisks))
		table := make(map[string]struct{}, len(c.SQLRisks))
		for _, r := range c.SQLRisks {
			for _, tab := range r.Tables {
				d, _ := comm.SplitDataBaseAndTable(tab)
				database[d] = struct{}{}
				table[tab] = struct{}{}
			}
			c.Summary.SQLCount++
		}
		c.Summary.DataBaseNum = len(database)
		c.Summary.TableNum = len(table)
		return c
	}

	c.Summary.ErrorCount = len(c.Errors)
	c.Summary.FatalCount = 0
	c.Summary.HighCount = 0
	c.Summary.LowCount = 0
	c.Summary.InfoCount = 0
	for _, r := range c.SQLRisks {
		c.Summary.FatalCount += len(r.FatalPolicy)
		c.Summary.HighCount += len(r.HighPolicy)
		c.Summary.LowCount += len(r.LowPolicy)
		c.Summary.InfoCount += len(r.InfoPolicy)
	}
	return c
}
