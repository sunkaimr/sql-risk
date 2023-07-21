package sqlrisk

import (
	"errors"
	"fmt"
	"github.com/sunkaimr/sql-risk/comm"
	"regexp"
	"sort"
	"strings"
)

const (
	ParseSQL     = "SQL解析"
	Authority    = "权限检验"
	IdentifyRisk = "风险识别"
)

type WorkRisk struct {
	WorkID       string
	SourceID     string
	ServiceUniID string
	Addr         string
	Port         string
	User         string
	Passwd       string
	DataBase     string
	TableName    string

	SQLText string

	SQLRisks []SQLRisk

	PreResult  PreResult
	PostResult PostResult

	Errors []ErrorResult
}

// IdentifyWorkRiskPreRisk 对工单进行前置风险识别
func (c *WorkRisk) IdentifyWorkRiskPreRisk() error {
	// 对工单中的sql语句进行拆分
	err := c.SplitStatement()
	if err != nil {
		c.SetPreResult(comm.Fatal, false)
		c.SetItemError(ParseSQL, err)
		return fmt.Errorf("split statement failed, %s", err)
	}

	if len(c.SQLRisks) == 0 {
		err = errors.New("no SQL found")
		c.SetPreResult(comm.Fatal, false)
		c.SetItemError(ParseSQL, err)
		return err
	}

	// 校验是否对库进行越权操作
	err = c.ExceedingPermissions()
	if err != nil {
		c.SetPreResult(comm.Fatal, false)
		c.SetItemError(Authority, err)
		return err
	}

	preResult := make([]PreResult, 0, len(c.SQLRisks))
	// 遍历SQL进行前置风险识别
	for i, _ := range c.SQLRisks {
		err = c.SQLRisks[i].IdentifyPreRisk()
		if err != nil {
			err = fmt.Errorf("identify sql pre risk failed, %s", err)
			c.SetPreResult(comm.Fatal, false)
			c.SetItemError(IdentifyRisk, err)
			return err
		}
		preResult = append(preResult, c.SQLRisks[i].PreResult)
	}

	sort.Sort(PreResultList(preResult))
	if len(preResult) == 0 {
		err = errors.New("no preResult found")
		c.SetPreResult(comm.Fatal, false)
		c.SetItemError(IdentifyRisk, err)
		return err
	}

	c.SetPreResult(preResult[0].Level, preResult[0].Special)
	return nil
}

// SplitStatement 将多个SQL语句进行拆分
func (c *WorkRisk) SplitStatement() error {
	var err error

	idx := strings.Index(c.SQLText, " ")
	if idx != -1 {
		c.SQLText = regexp.MustCompile(` `).ReplaceAllString(c.SQLText, " ")
		c.SetItemError(ParseSQL, fmt.Errorf("column %d near found chinese encoded characters", idx))
	}

	sqlList := comm.SplitStatement(c.SQLText)
	for i, sql := range sqlList {
		sqlRisk := SQLRisk{
			//ServiceUniID: c.ServiceUniID,
			Addr:     c.Addr,
			Port:     c.Port,
			User:     c.User,
			Passwd:   c.Passwd,
			DataBase: c.DataBase,
			SQLText:  sql,
			Errors:   nil,
		}

		sqlRisk.RelevantTableName, err = comm.ParseRelatedTableName(sql, c.DataBase)
		if err != nil {
			return fmt.Errorf("parse related table name failed, sql index(%d), %s", i, err)
		}

		sqlRisk.TableName, err = comm.ExtractingTableName(sql, c.DataBase)
		if err != nil {
			return fmt.Errorf("extracting table name failed,  sql index(%d), %s", i, err)
		}

		c.SQLRisks = append(c.SQLRisks, sqlRisk)
	}

	return nil
}

// ExceedingPermissions 校验是否对库进行越权操作
func (c *WorkRisk) ExceedingPermissions() error {
	for _, sqlRisk := range c.SQLRisks {
		var database []string

		for _, tabName := range sqlRisk.RelevantTableName {
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
	c.Errors = append(c.Errors, ErrorResult{Type: name, Error: e})
}
