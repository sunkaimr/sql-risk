package sqlrisk

//
//import (
//	"sql-risk/comm"
//	"sql-risk/policy"
//	"fmt"
//	"sort"
//)
//
//var riskMap = map[comm.Level]int{comm.Fatal: 4, comm.High: 3, comm.Low: 2, comm.Info: 1}
//
//var BasicStrategies []Rule
//var SpecialStrategies []Rule
//var PostRiskStrategies []Rule
//var DefaultStrategy = Rule{Expr: "DEFAULT", Level: comm.High, Special: false}
//
//func init() {
//	RefreshStrategies()
//	if err := VerifyStrategies(); err != nil {
//		panic(err)
//	}
//}
//
//func VerifyStrategies() error {
//	env := make(map[string]any, 5)
//	env[policy.Operate.ID] = string(policy.Operate.V.DQL)
//	env[policy.Action.ID] = string(policy.Action.V.Select)
//	env[policy.KeyWord.ID] = string(policy.KeyWord.V.Select)
//	env[policy.TabSize.ID] = 1024
//	env[policy.TabRows.ID] = 20000
//	env[policy.AffectRows.ID] = 3000
//	env[policy.FreeDisk.ID] = 1240
//	env[policy.PrimaryKeyExist.ID] = true
//	env[policy.ForeignKeyExist.ID] = false
//	env[policy.TriggerExist.ID] = false
//	env[policy.IndexExistInWhere.ID] = true
//	env[policy.CpuUsage.ID] = 10
//	env[policy.BigTransaction.ID] = false
//
//	// 定制策略
//	for _, strategy := range SpecialStrategies {
//		if _, err := policy.Eval(strategy.Expr, env); err != nil {
//			return fmt.Errorf("verify SpecialStrategies:%s failed, %s", strategy.Name, err)
//		}
//	}
//
//	// 基本风险策略
//	for _, strategy := range BasicStrategies {
//		if _, err := policy.Eval(strategy.Expr, env); err != nil {
//			return fmt.Errorf("verify BasicStrategies:%s failed, %s", strategy.Name, err)
//		}
//	}
//
//	// 运行前风险策略
//	for _, strategy := range PostRiskStrategies {
//		if _, err := policy.Eval(strategy.Expr, env); err != nil {
//			return fmt.Errorf("verify PostRiskStrategies:%s failed, %s", strategy.Name, err)
//		}
//	}
//
//	return nil
//}
//
//// RefreshStrategies 更新风险策略
//func RefreshStrategies() {
//	BasicStrategies = []Rule{
//		{Expr: `KeyWord == "unknown"`, Level: comm.Fatal, Special: false, Priority: 999},
//		{Expr: `KeyWord == "select"`, Level: comm.Low, Special: false, Priority: 1},
//		{Expr: `KeyWord == "drop table"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "drop index"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "drop procedure"`, Level: comm.Fatal, Special: false, Priority: 1},
//		{Expr: `KeyWord == "drop function"`, Level: comm.Fatal, Special: false, Priority: 1},
//		{Expr: `KeyWord == "drop view"`, Level: comm.Fatal, Special: false, Priority: 1},
//		{Expr: `KeyWord == "drop trigger"`, Level: comm.Fatal, Special: false, Priority: 1},
//		{Expr: `KeyWord == "truncate table"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "create table"`, Level: comm.Low, Special: false, Priority: 1},
//		{Expr: `KeyWord == "create table as"`, Level: comm.Fatal, Special: false, Priority: 1},
//		{Expr: `KeyWord == "create temporary table"`, Level: comm.Fatal, Special: false, Priority: 1},
//		{Expr: `KeyWord == "create index"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "create unique index"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "create procedure"`, Level: comm.Fatal, Special: false, Priority: 1},
//		{Expr: `KeyWord == "create function"`, Level: comm.Fatal, Special: false, Priority: 1},
//		{Expr: `KeyWord == "create view"`, Level: comm.Fatal, Special: false, Priority: 1},
//		{Expr: `KeyWord == "create trigger"`, Level: comm.Fatal, Special: false, Priority: 1},
//		{Expr: `KeyWord == "add column"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "drop column"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "modify column"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "rename column"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "change column"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "add primary key"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "drop primary key"`, Level: comm.Fatal, Special: false, Priority: 1},
//		{Expr: `KeyWord == "add index"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "add unique index"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "drop index"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "alert"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "insert into select"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "insert"`, Level: comm.Low, Special: false, Priority: 1},
//		{Expr: `KeyWord == "replace into"`, Level: comm.Low, Special: false, Priority: 1},
//		{Expr: `KeyWord == "delete from where"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "delete from"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "update set where"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `KeyWord == "update set"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `TableSize > 2048"`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `TableSize <= 2048`, Level: comm.Low, Special: false, Priority: 1},
//		{Expr: `AffectRows > 20000`, Level: comm.High, Special: true, Priority: 1},
//		{Expr: `AffectRows <= 20000`, Level: comm.Low, Special: false, Priority: 1},
//		{Expr: `FreeDisk <= TableSize`, Level: comm.Fatal, Special: false, Priority: 2},
//		{Expr: `FreeDisk > TableSize`, Level: comm.Low, Special: false, Priority: 0},
//	}
//	sort.Sort(StrategyList(BasicStrategies))
//
//	SpecialStrategies = []Rule{
//		{Expr: `KeyWord == "insert"`, Priority: 50, Level: comm.Low, Special: false},
//
//		{Expr: `Action == "alter" && TableSize <= 2048`, Priority: 50, Level: comm.Low, Special: false},
//		{Expr: `Action == "alter" && TableSize > 2048`, Priority: 50, Level: comm.High, Special: false},
//
//		{Expr: `KeyWord == "delete from" && AffectRows > 100000`, Priority: 50, Level: comm.High, Special: true},
//		{Expr: `KeyWord == "delete from" && AffectRows > 20000 && AffectRows <= 100000`, Priority: 50, Level: comm.Low, Special: true},
//		{Expr: `KeyWord == "delete from" && AffectRows <= 20000`, Priority: 50, Level: comm.Low, Special: false},
//
//		{Expr: `KeyWord == "delete from where" && TableRows <= 100000`, Priority: 51, Level: comm.Low, Special: false},
//		{Expr: `KeyWord == "delete from where" && !IndexExistInWhere && AffectRows > 20000`, Priority: 50, Level: comm.High, Special: true},
//		{Expr: `KeyWord == "delete from where" && !IndexExistInWhere && AffectRows <= 20000`, Priority: 50, Level: comm.High, Special: false},
//		{Expr: `KeyWord == "delete from where" && IndexExistInWhere && AffectRows > 20000`, Priority: 50, Level: comm.High, Special: true},
//		{Expr: `KeyWord == "delete from where" && IndexExistInWhere && AffectRows <= 20000`, Priority: 50, Level: comm.Low, Special: false},
//
//		{Expr: `KeyWord == "update set" && AffectRows > 100000`, Priority: 50, Level: comm.High, Special: true},
//		{Expr: `KeyWord == "update set" && AffectRows > 20000 && AffectRows < 100000`, Priority: 50, Level: comm.Low, Special: true},
//		{Expr: `KeyWord == "update set" && AffectRows <= 20000`, Priority: 50, Level: comm.Low, Special: false},
//
//		{Expr: `KeyWord == "update set where" && TableRows <= 100000`, Priority: 51, Level: comm.Low, Special: false},
//		{Expr: `KeyWord == "update set where" && !IndexExistInWhere && AffectRows > 20000`, Priority: 50, Level: comm.High, Special: true},
//		{Expr: `KeyWord == "update set where" && !IndexExistInWhere && AffectRows <= 20000`, Priority: 50, Level: comm.High, Special: false},
//		{Expr: `KeyWord == "update set where" && IndexExistInWhere && AffectRows > 20000`, Priority: 50, Level: comm.High, Special: true},
//		{Expr: `KeyWord == "update set where" && IndexExistInWhere && AffectRows <= 20000`, Priority: 50, Level: comm.Low, Special: false},
//	}
//	sort.Sort(StrategyList(SpecialStrategies))
//
//	PostRiskStrategies = []Rule{
//		{Expr: `CpuUsage > 70`, Level: comm.Fatal, Special: false, Priority: 1},
//		{Expr: `40 <= CpuUsage && CpuUsage <= 70`, Level: comm.High, Special: false, Priority: 1},
//		{Expr: `CpuUsage < 40`, Level: comm.Low, Special: false, Priority: 1},
//		{Expr: `BigTransaction`, Level: comm.Fatal, Special: false, Priority: 1},
//		{Expr: `!BigTransaction`, Level: comm.Low, Special: false, Priority: 1},
//		{Expr: `PrimaryKeyExist`, Level: comm.Low, Special: false, Priority: 1},
//		{Expr: `!PrimaryKeyExist`, Level: comm.Low, Special: false, Priority: 1},
//		{Expr: `ForeignKeyExist`, Level: comm.Low, Special: false, Priority: 1},
//		{Expr: `!ForeignKeyExist`, Level: comm.Low, Special: false, Priority: 1},
//		{Expr: `TriggerExist`, Level: comm.Low, Special: false, Priority: 1},
//		{Expr: `!TriggerExist`, Level: comm.Low, Special: false, Priority: 1},
//	}
//	sort.Sort(StrategyList(PostRiskStrategies))
//}
//
//type StrategyList []Rule
//
//func (a StrategyList) Len() int {
//	return len(a)
//}
//
//// Less 排序，先按优先级（数字越大优先级越高）, 再按风险等级，最后按是否走特殊流程
//func (a StrategyList) Less(i, j int) bool {
//	if a[i].Priority < a[j].Priority {
//		return false
//	} else if a[i].Priority > a[j].Priority {
//		return true
//	}
//
//	if riskMap[a[i].Level] < riskMap[a[j].Level] {
//		return false
//	} else if riskMap[a[i].Level] > riskMap[a[j].Level] {
//		return true
//	}
//
//	if a[i].Special {
//		return false
//	}
//	return true
//}
//
//func (a StrategyList) Swap(i, j int) {
//	a[i], a[j] = a[j], a[i]
//}
//
//func MatchBasicStrategies(env map[string]any) (bool, []Rule, error) {
//	matched := false
//	matchRules := make([]Rule, 0, 1)
//	for _, strategy := range BasicStrategies {
//		b, err := policy.Eval(strategy.Expr, env)
//		if err != nil {
//			return matched, matchRules, fmt.Errorf("eval BasicStrategies:%s failed, %s", strategy.Name, err)
//		}
//
//		if !b {
//			continue
//		}
//		matched = true
//		matchRules = append(matchRules, strategy)
//	}
//	return matched, matchRules, nil
//}
//
//func MatchSpecialStrategies(env map[string]any) (bool, []Rule, error) {
//	matched := false
//	matchRules := make([]Rule, 0, 1)
//	for _, strategy := range SpecialStrategies {
//		b, err := policy.Eval(strategy.Expr, env)
//		if err != nil {
//			return matched, matchRules, fmt.Errorf("eval SpecialStrategies:%s failed, %s", strategy.Name, err)
//		}
//
//		if !b {
//			continue
//		}
//		matched = true
//		matchRules = append(matchRules, strategy)
//	}
//	return matched, matchRules, nil
//}
//
//func MatchPostRiskStrategies(env map[string]any) (bool, []Rule, error) {
//	matched := false
//	matchRules := make([]Rule, 0, 1)
//	for _, strategy := range PostRiskStrategies {
//		b, err := policy.Eval(strategy.Expr, env)
//		if err != nil {
//			return matched, matchRules, fmt.Errorf("eval PostRiskStrategies:%s failed, %s", strategy.Name, err)
//		}
//
//		if !b {
//			continue
//		}
//		matched = true
//		matchRules = append(matchRules, strategy)
//	}
//	return matched, matchRules, nil
//}
