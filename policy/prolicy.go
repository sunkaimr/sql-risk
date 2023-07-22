package policy

import (
	"encoding/json"
	"fmt"
	"github.com/sunkaimr/sql-risk/comm"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var operateTypeMeta []OperateTypeMeta
var actionTypeMeta []ActionTypeMeta
var keyWordTypeMeta []KeyWordTypeMeta
var ruleMeta []RuleMeta
var policyMeta []Policy

const matchBasicPolicies = "matchBasicPolicies"

func init() {
	operateTypeMeta = generateOperateTypeMeta()
	actionTypeMeta = generateActionTypeMeta()
	keyWordTypeMeta = generateKeyWordTypeMeta()
	ruleMeta = generateRuleMeta()
}

func GetOperateTypeMeta() []OperateTypeMeta {
	return operateTypeMeta
}

func GetActionTypeMeta() []ActionTypeMeta {
	return actionTypeMeta
}

func GetKeyWordTypeMeta() []KeyWordTypeMeta {
	return keyWordTypeMeta
}

func GetRuleMeta() []RuleMeta {
	return ruleMeta
}

func GetPolicy() []Policy {
	return policyMeta
}

func generateOperateTypeMeta() []OperateTypeMeta {
	pValue := reflect.ValueOf(Operate.V)
	pType := pValue.Type()
	mates := make([]OperateTypeMeta, 0, pValue.NumField())

	for i := 0; i < pValue.NumField(); i++ {
		if pValue.Field(i).String() == "" {
			continue
		}
		mates = append(mates, OperateTypeMeta{
			ID:    pType.Field(i).Name,
			Value: pValue.Field(i).String(),
		})
	}
	return mates
}

func generateActionTypeMeta() []ActionTypeMeta {
	pValue := reflect.ValueOf(Action.V)
	pType := pValue.Type()
	mates := make([]ActionTypeMeta, 0, pValue.NumField())

	for i := 0; i < pValue.NumField(); i++ {
		if pValue.Field(i).String() == "" {
			continue
		}

		mates = append(mates, ActionTypeMeta{
			ID:    pType.Field(i).Name,
			Value: pValue.Field(i).String(),
		})
	}
	return mates
}

func generateKeyWordTypeMeta() []KeyWordTypeMeta {
	pValue := reflect.ValueOf(KeyWord.V)
	pType := pValue.Type()
	mates := make([]KeyWordTypeMeta, 0, pValue.NumField())

	for i := 0; i < pValue.NumField(); i++ {
		if pValue.Field(i).String() == "" {
			continue
		}

		mates = append(mates, KeyWordTypeMeta{
			ID:    pType.Field(i).Name,
			Value: pValue.Field(i).String(),
		})
	}
	return mates
}

func generateRuleMeta() []RuleMeta {
	rules := []RuleMeta{
		// Operate	BASIC	OperateType	!=,==
		{
			ID:          Operate.ID,
			Name:        Operate.Name,
			Type:        BasicRule,
			ValueType:   RuleValueTypeOperate,
			Operator:    []OperatorType{RuleOperatorEQ, RuleOperatorNE},
			Description: "SQL的操作类型",
		},
		// Action	BASIC	ActionType	!=,==
		{
			ID:          Action.ID,
			Name:        Action.Name,
			Type:        BasicRule,
			ValueType:   RuleValueTypeAction,
			Operator:    []OperatorType{RuleOperatorEQ, RuleOperatorNE},
			Description: "SQL的动作类型",
		},
		// KeyWord	BASIC	KeyWordType	!=,==
		{
			ID:          KeyWord.ID,
			Name:        KeyWord.Name,
			Type:        BasicRule,
			ValueType:   RuleValueTypeKeyWord,
			Operator:    []OperatorType{RuleOperatorEQ, RuleOperatorNE},
			Description: "SQL的关键字",
		},
		// TableSize	BASIC	int	<,<=,==,>,>=,between
		{
			ID:          TabSize.ID,
			Name:        TabSize.Name,
			Type:        BasicRule,
			ValueType:   RuleValueTypeInt,
			Operator:    []OperatorType{RuleOperatorLT, RuleOperatorLE, RuleOperatorGT, RuleOperatorGE, RuleOperatorBETWEEN},
			Description: "表大小",
		},
		// TableRows	BASIC	int	<,<=,==,>,>=,between
		{
			ID:          TabRows.ID,
			Name:        TabRows.Name,
			Type:        BasicRule,
			ValueType:   RuleValueTypeInt,
			Operator:    []OperatorType{RuleOperatorLT, RuleOperatorLE, RuleOperatorGT, RuleOperatorGE, RuleOperatorBETWEEN},
			Description: "表行数",
		},
		// AffectRows	BASIC	int	<,<=,==,>,>=,between
		{
			ID:          AffectRows.ID,
			Name:        AffectRows.Name,
			Type:        BasicRule,
			ValueType:   RuleValueTypeInt,
			Operator:    []OperatorType{RuleOperatorLT, RuleOperatorLE, RuleOperatorGT, RuleOperatorGE, RuleOperatorBETWEEN},
			Description: "评估delete和update操作的影响行数",
		},
		// DiskSufficient	BASIC	bool	!=,==
		{
			ID:          DiskSufficient.ID,
			Name:        DiskSufficient.Name,
			Type:        BasicRule,
			ValueType:   RuleValueTypeBool,
			Operator:    []OperatorType{RuleOperatorEQ, RuleOperatorNE},
			Description: "判断磁盘剩余空间是否大于表大小，评估磁盘剩余空间是否支持DDL操作",
		},
		// PrimaryKeyExist	BASIC	bool	!=,==
		{
			ID:          PrimaryKeyExist.ID,
			Name:        PrimaryKeyExist.Name,
			Type:        BasicRule,
			ValueType:   RuleValueTypeBool,
			Operator:    []OperatorType{RuleOperatorEQ, RuleOperatorNE},
			Description: "判断表是否存在主键",
		},
		// PrimaryKeyExist	BASIC	bool	!=,==
		{
			ID:          ForeignKeyExist.ID,
			Name:        ForeignKeyExist.Name,
			Type:        BasicRule,
			ValueType:   RuleValueTypeBool,
			Operator:    []OperatorType{RuleOperatorEQ, RuleOperatorNE},
			Description: "判断表是否存在外键",
		},
		// TriggerExist	BASIC	bool	!=,==
		{
			ID:          TriggerExist.ID,
			Name:        TriggerExist.Name,
			Type:        BasicRule,
			ValueType:   RuleValueTypeBool,
			Operator:    []OperatorType{RuleOperatorEQ, RuleOperatorNE},
			Description: "判断表是否存在触发器",
		},
		// IndexExistInWhere	BASIC	bool	!=,==
		{
			ID:          IndexExistInWhere.ID,
			Name:        IndexExistInWhere.Name,
			Type:        BasicRule,
			ValueType:   RuleValueTypeBool,
			Operator:    []OperatorType{RuleOperatorEQ, RuleOperatorNE},
			Description: "判断delete和update操作时where条件后边的列是否是索引",
		},
		// BigTransaction	BASIC	bool	!=,==
		{
			ID:          BigTransaction.ID,
			Name:        BigTransaction.Name,
			Type:        BasicRule,
			ValueType:   RuleValueTypeBool,
			Operator:    []OperatorType{RuleOperatorEQ, RuleOperatorNE},
			Description: "判断操作的表是否有正在运行的事务",
		},
		// CpuUsage	BASIC	int	<,<=,==,>,>=,between
		{
			ID:          CpuUsage.ID,
			Name:        CpuUsage.Name,
			Type:        BasicRule,
			ValueType:   RuleValueTypeInt,
			Operator:    []OperatorType{RuleOperatorLT, RuleOperatorLE, RuleOperatorGT, RuleOperatorGE, RuleOperatorBETWEEN},
			Description: "获取当前集群最近5分钟内CPU的使用率",
		},
		// RuleMatch	AGG	BASIC	ALL,ANY
		{
			ID:          RuleMatch.ID,
			Name:        RuleMatch.Name,
			Type:        AggRule,
			ValueType:   RuleValueTypeBasic,
			Operator:    []OperatorType{RuleOperatorALL, RuleOperatorANY},
			Description: "判断匹配到的BASIC规则名称",
		},
		// RulePriority	AGG	BASIC	HIGHEST，LOWEST
		{
			ID:          RulePriority.ID,
			Name:        RulePriority.Name,
			Type:        AggRule,
			ValueType:   RuleValueTypeBasic,
			Operator:    []OperatorType{RuleOperatorHIG, RuleOperatorLOW},
			Description: "按优先级取匹配到的BASIC规则",
		},
		// RuleLevel	AGG	BASIC	HIGHEST，LOWEST
		{
			ID:          RuleLevel.ID,
			Name:        RuleLevel.Name,
			Type:        AggRule,
			ValueType:   RuleValueTypeBasic,
			Operator:    []OperatorType{RuleOperatorHIG, RuleOperatorLOW},
			Description: "按风险等级取匹配到的BASIC规则",
		},
	}
	return rules
}

func generateDefaultPolicy() []Policy {
	policies := []Policy{
		// 基本策略
		// Action
		{
			ID:          "OPE.UNKNOWN.000",
			Name:        "未知的动作类型",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      Action.ID,
			Operator:    RuleOperatorEQ,
			Value:       Action.V.Unknown,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.SELECT.000",
			Name:        "SELECT动作类型",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      Action.ID,
			Operator:    RuleOperatorEQ,
			Value:       Action.V.Select,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.DROP.000",
			Name:        "DROP动作类型",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      Action.ID,
			Operator:    RuleOperatorEQ,
			Value:       Action.V.Drop,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.TRUNCATE.000",
			Name:        "TRUNCATE动作类型",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      Action.ID,
			Operator:    RuleOperatorEQ,
			Value:       Action.V.Truncate,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.CREATE.000",
			Name:        "CREATE动作类型",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      Action.ID,
			Operator:    RuleOperatorEQ,
			Value:       Action.V.Create,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.ALTER.000",
			Name:        "ALTER动作类型",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      Action.ID,
			Operator:    RuleOperatorEQ,
			Value:       Action.V.Alter,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.INSERT.000",
			Name:        "INSERT动作类型",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      Action.ID,
			Operator:    RuleOperatorEQ,
			Value:       Action.V.Insert,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.REPLACE.000",
			Name:        "REPLACE动作类型",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      Action.ID,
			Operator:    RuleOperatorEQ,
			Value:       Action.V.Replace,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.DELETE.000",
			Name:        "DELETE动作类型",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      Action.ID,
			Operator:    RuleOperatorEQ,
			Value:       Action.V.Delete,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.UPDATE.000",
			Name:        "UPDATE动作类型",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      Action.ID,
			Operator:    RuleOperatorEQ,
			Value:       Action.V.Update,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		// KeyWord
		{
			ID:          "OPE.UNKNOWN.001",
			Name:        "未知的关键字",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.Unknown,
			Level:       comm.Low,
			Special:     false,
			Priority:    999,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.SELECT.001",
			Name:        "查询",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.Select,
			Level:       comm.Low,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.DROP.001",
			Name:        "删除表",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.DropTab,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.DROP.002",
			Name:        "删除数据库",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.DropDB,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.DROP.003",
			Name:        "删除索引",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.DropIdx,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.DROP.004",
			Name:        "删除存储过程",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.DropProcedure,
			Level:       comm.Fatal,
			Special:     false,
			Priority:    999,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.DROP.005",
			Name:        "删除函数",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.DropFun,
			Level:       comm.Fatal,
			Special:     false,
			Priority:    999,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.DROP.006",
			Name:        "删除视图",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.DropView,
			Level:       comm.Fatal,
			Special:     false,
			Priority:    999,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.DROP.007",
			Name:        "删除触发器",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.DropTrig,
			Level:       comm.Fatal,
			Special:     false,
			Priority:    999,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.TRUNCATE.001",
			Name:        "截断表",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.TruncateTab,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.CREATE.001",
			Name:        "创建表",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.CreateTab,
			Level:       comm.Low,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.CREATE.002",
			Name:        "复制表",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.CreateTabAs,
			Level:       comm.Fatal,
			Special:     false,
			Priority:    999,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.CREATE.003",
			Name:        "创建临时表",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.CreateTmpTab,
			Level:       comm.Fatal,
			Special:     false,
			Priority:    999,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.CREATE.004",
			Name:        "创建索引",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.CreateIdx,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.CREATE.005",
			Name:        "创建唯一索引",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.CreateUniIdx,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.CREATE.006",
			Name:        "创建存储过程",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.CreateProcedure,
			Level:       comm.Fatal,
			Special:     false,
			Priority:    999,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.CREATE.007",
			Name:        "创建函数",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.CreateFunc,
			Level:       comm.Fatal,
			Special:     false,
			Priority:    999,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.CREATE.008",
			Name:        "创建视图",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.CreateView,
			Level:       comm.Fatal,
			Special:     false,
			Priority:    999,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.CREATE.009",
			Name:        "创建触发器",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.CreateTrig,
			Level:       comm.Fatal,
			Special:     false,
			Priority:    999,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.ALTER.001",
			Name:        "alter操作",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.Alter,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.ALTER.002",
			Name:        "添加列",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.AlertAddCol,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.ALTER.003",
			Name:        "删除列",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.AlertDropCol,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.ALTER.004",
			Name:        "更新列",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.AlertModCol,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.ALTER.005",
			Name:        "列重命名",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.AlertRenameCol,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.ALTER.006",
			Name:        "修改列",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.AlertChgCol,
			Level:       comm.High,
			Special:     false,
			Priority:    50,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.ALTER.007",
			Name:        "添加主键",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.AlertAddPriKey,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.ALTER.008",
			Name:        "删除主键",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.AlertDropPriKey,
			Level:       comm.Fatal,
			Special:     false,
			Priority:    999,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.ALTER.009",
			Name:        "添加索引",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.AlertAddIdx,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.ALTER.010",
			Name:        "添加唯一约束",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.AlertAddUni,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.ALTER.011",
			Name:        "添加唯一索引",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.AlertAddUniIdx,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.ALTER.012",
			Name:        "删除索引",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.DropIdx,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.INSERT.001",
			Name:        "插入数据",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.Insert,
			Level:       comm.Low,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.INSERT.002",
			Name:        "插入查询数据",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.InsertSelect,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.REPLACE.003",
			Name:        "替换数据",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.Replace,
			Level:       comm.Low,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.DELETE.001",
			Name:        "删除全表数据",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.DeleteWhere,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.DELETE.002",
			Name:        "删除部分数据",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.Delete,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.UPDATE.001",
			Name:        "更新部分数据",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.UpdateWhere,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.UPDATE.002",
			Name:        "更新全表数据",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      KeyWord.ID,
			Operator:    RuleOperatorEQ,
			Value:       KeyWord.V.Update,
			Level:       comm.High,
			Special:     false,
			Priority:    60,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.AFFECTROWS.001",
			Name:        "影响行数大于等于10w",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      AffectRows.ID,
			Operator:    RuleOperatorGE,
			Value:       100000,
			Level:       comm.High,
			Special:     true,
			Priority:    70,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.AFFECTROWS.002",
			Name:        "影响行数在2w和10w之间",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      AffectRows.ID,
			Operator:    RuleOperatorBETWEEN,
			Value:       []int{20000, 100000},
			Level:       comm.High,
			Special:     true,
			Priority:    70,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "OPE.AFFECTROWS.003",
			Name:        "影响行数小于等于2w",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      AffectRows.ID,
			Operator:    RuleOperatorLE,
			Value:       20000,
			Level:       comm.Low,
			Special:     false,
			Priority:    70,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "RUN.CAPACITY.001",
			Name:        "表大小大于2G",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      TabSize.ID,
			Operator:    RuleOperatorGT,
			Value:       2048,
			Level:       comm.High,
			Special:     false,
			Priority:    50,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "RUN.CAPACITY.002",
			Name:        "表大小小于等于2G",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      TabSize.ID,
			Operator:    RuleOperatorLE,
			Value:       2048,
			Level:       comm.Low,
			Special:     false,
			Priority:    50,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "RUN.CAPACITY.003",
			Name:        "表行数小于等于10w",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      TabRows.ID,
			Operator:    RuleOperatorLE,
			Value:       100000,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "RUN.CAPACITY.004",
			Name:        "表行数大于2w",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      TabRows.ID,
			Operator:    RuleOperatorGT,
			Value:       20000,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "RUN.CAPACITY.005",
			Name:        "表行数小于等于2w",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      TabRows.ID,
			Operator:    RuleOperatorLE,
			Value:       20000,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "RUN.CAPACITY.006",
			Name:        "磁盘容量充足",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      DiskSufficient.ID,
			Operator:    RuleOperatorEQ,
			Value:       true,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "磁盘可用空间大于表大小，磁盘容量充足可以进行DDL操作",
			Suggestion:  "",
		},
		{
			ID:          "RUN.CAPACITY.007",
			Name:        "磁盘容量不充足",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      DiskSufficient.ID,
			Operator:    RuleOperatorEQ,
			Value:       false,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "磁盘可用空间小于表大小，此时磁盘容量不足以支持DDL操作",
			Suggestion:  "",
		},
		{
			ID:          "RUN.TABINFO.001",
			Name:        "表存在主键",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      PrimaryKeyExist.ID,
			Operator:    RuleOperatorEQ,
			Value:       true,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "RUN.TABINFO.002",
			Name:        "表不存在主键",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      PrimaryKeyExist.ID,
			Operator:    RuleOperatorEQ,
			Value:       false,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "RUN.TABINFO.003",
			Name:        "表存在外键",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      ForeignKeyExist.ID,
			Operator:    RuleOperatorEQ,
			Value:       true,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "RUN.TABINFO.004",
			Name:        "表不存在外键",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      ForeignKeyExist.ID,
			Operator:    RuleOperatorEQ,
			Value:       false,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "RUN.TABINFO.005",
			Name:        "表存在触发器",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      TriggerExist.ID,
			Operator:    RuleOperatorEQ,
			Value:       true,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "RUN.TABINFO.006",
			Name:        "表不存在触发器",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      TriggerExist.ID,
			Operator:    RuleOperatorEQ,
			Value:       false,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "RUN.TABINFO.007",
			Name:        "where条件中存在索引列",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      IndexExistInWhere.ID,
			Operator:    RuleOperatorEQ,
			Value:       true,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "RUN.TABINFO.008",
			Name:        "where条件中不存在索引列",
			Enable:      true,
			Type:        BasicRule,
			RuleID:      IndexExistInWhere.ID,
			Operator:    RuleOperatorEQ,
			Value:       false,
			Level:       comm.Low,
			Special:     false,
			Priority:    10,
			Description: "",
			Suggestion:  "",
		},
		// 聚合策略 - 按优先级
		{
			ID:          "AGG.RULEPRIORITY.001",
			Name:        "优先级最高的基本策略",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RulePriority.ID,
			Operator:    RuleOperatorHIG,
			Value:       []string{"*"},
			Level:       comm.Low,
			Special:     true,
			Priority:    150,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEPRIORITY.002",
			Name:        "优先级最低的基本策略",
			Enable:      false,
			Type:        AggRule,
			RuleID:      RulePriority.ID,
			Operator:    RuleOperatorLOW,
			Value:       []string{"*"},
			Level:       comm.Low,
			Special:     false,
			Priority:    140,
			Description: "",
			Suggestion:  "",
		},
		// 聚合策略 - 按风险等级
		{
			ID:          "AGG.RULELEVEL.001",
			Name:        "风险等级最高的基本策略",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RulePriority.ID,
			Operator:    RuleOperatorHIG,
			Value:       []string{"*"},
			Level:       comm.Low,
			Special:     false,
			Priority:    130,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULELEVEL.002",
			Name:        "风险等级最低的基本策略",
			Enable:      false,
			Type:        AggRule,
			RuleID:      RulePriority.ID,
			Operator:    RuleOperatorLOW,
			Value:       []string{"*"},
			Level:       comm.Low,
			Special:     false,
			Priority:    120,
			Description: "",
			Suggestion:  "",
		},
		// 聚合策略 - 按匹配结果
		{
			ID:          "AGG.RULEMATCH.001",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorANY,
			Value:       []string{"OPE.INSERT.000"},
			Level:       comm.Low,
			Special:     false,
			Priority:    150,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.002",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.ALTER.000", "RUN.CAPACITY.002"},
			Level:       comm.Low,
			Special:     false,
			Priority:    200,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.003",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.ALTER.000", "RUN.CAPACITY.001"},
			Level:       comm.High,
			Special:     false,
			Priority:    200,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.004",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.DELETE.002", "OPE.AFFECTROWS.001"},
			Level:       comm.High,
			Special:     true,
			Priority:    200,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.005",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.DELETE.002", "OPE.AFFECTROWS.002"},
			Level:       comm.Low,
			Special:     true,
			Priority:    200,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.006",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.DELETE.002", "OPE.AFFECTROWS.003"},
			Level:       comm.Low,
			Special:     true,
			Priority:    200,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.007",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.DELETE.001", "RUN.CAPACITY.003"},
			Level:       comm.Low,
			Special:     true,
			Priority:    210,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.008",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.DELETE.001", "RUN.TABINFO.008", "RUN.CAPACITY.004"},
			Level:       comm.High,
			Special:     true,
			Priority:    200,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.009",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.DELETE.001", "RUN.TABINFO.008", "OPE.AFFECTROWS.003"},
			Level:       comm.High,
			Special:     false,
			Priority:    200,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.010",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.DELETE.001", "RUN.TABINFO.007", "RUN.CAPACITY.004"},
			Level:       comm.High,
			Special:     true,
			Priority:    200,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.011",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.DELETE.001", "RUN.TABINFO.007", "OPE.AFFECTROWS.003"},
			Level:       comm.Low,
			Special:     false,
			Priority:    200,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.012",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.UPDATE.002", "OPE.AFFECTROWS.001"},
			Level:       comm.High,
			Special:     true,
			Priority:    200,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.013",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.UPDATE.002", "OPE.AFFECTROWS.002"},
			Level:       comm.Low,
			Special:     true,
			Priority:    200,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.014",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.UPDATE.002", "OPE.AFFECTROWS.003"},
			Level:       comm.Low,
			Special:     false,
			Priority:    200,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.015",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.UPDATE.001", "RUN.CAPACITY.003"},
			Level:       comm.Low,
			Special:     false,
			Priority:    210,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.016",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.UPDATE.001", "RUN.TABINFO.008", "RUN.CAPACITY.004"},
			Level:       comm.High,
			Special:     true,
			Priority:    200,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.017",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.UPDATE.001", "RUN.TABINFO.008", "OPE.AFFECTROWS.003"},
			Level:       comm.High,
			Special:     false,
			Priority:    200,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.018",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.UPDATE.001", "RUN.TABINFO.007", "RUN.CAPACITY.004"},
			Level:       comm.High,
			Special:     true,
			Priority:    200,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.019",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.UPDATE.001", "RUN.TABINFO.007", "OPE.AFFECTROWS.003"},
			Level:       comm.Low,
			Special:     false,
			Priority:    200,
			Description: "",
			Suggestion:  "",
		},
		{
			ID:          "AGG.RULEMATCH.020",
			Name:        "",
			Enable:      true,
			Type:        AggRule,
			RuleID:      RuleMatch.ID,
			Operator:    RuleOperatorALL,
			Value:       []string{"OPE.ALTER.000", "RUN.CAPACITY.007"},
			Level:       comm.Fatal,
			Special:     false,
			Priority:    200,
			Description: "",
			Suggestion:  "",
		},
	}

	for i, p := range policies {
		if p.Type != AggRule || p.RuleID != RuleMatch.ID || p.Name != "" {
			continue
		}

		policies[i].Name = generatePolicyName(p, policies)
	}
	return policies
}

func generatePolicyName(p Policy, policies []Policy) string {
	basicName := make([]string, 0, 3)
	if ids, ok := p.Value.([]string); ok {
		for _, id := range ids {
			if name := queryPolicyNameByPolicyID(id, policies); name != "" {
				basicName = append(basicName, name)
			}
		}
	}

	switch p.Operator {
	case RuleOperatorALL:
		return strings.Join(basicName, "&&")
	case RuleOperatorANY:
		return strings.Join(basicName, "||")
	}
	return ""
}

func queryPolicyNameByPolicyID(id string, policies []Policy) string {
	for _, policy := range policies {
		if policy.ID == id {
			return policy.Name
		}
	}
	return ""
}

func MatchBasicPolicy(env map[string]any) (bool, []Policy, error) {
	matched := false
	matchPolicies := make([]Policy, 0, 1)
	for _, p := range GetPolicy() {
		if p.Type != BasicRule {
			continue
		}

		b, err := Eval(p.Expr, env)
		if err != nil {
			return matched, matchPolicies, fmt.Errorf("eval BasicPolicy:%s failed, %s", p.ID, err)
		}

		if !b {
			continue
		}
		matched = true
		matchPolicies = append(matchPolicies, p)
	}
	return matched, matchPolicies, nil
}

func MatchAggregatePolicy(basicPolicy []Policy) (bool, []Policy, error) {
	matched := false
	matchPolicies := make([]Policy, 0, 1)

	env := make(map[string]any, 5)
	env[matchBasicPolicies] = fetchPolicyID(basicPolicy)
	env[strings.ToUpper(string(RuleOperatorALL))] = RuleMatchAll
	env[strings.ToUpper(string(RuleOperatorANY))] = RuleMatchANY
	env[strings.ToUpper(RulePriority.ID+string(RuleOperatorHIG))] = RulePriorityHIG
	env[strings.ToUpper(RulePriority.ID+string(RuleOperatorLOW))] = RulePriorityLOW
	env[strings.ToUpper(RuleLevel.ID+string(RuleOperatorHIG))] = RuleLevelHIG
	env[strings.ToUpper(RuleLevel.ID+string(RuleOperatorLOW))] = RuleLevelLOW

	for _, p := range GetPolicy() {
		if p.Type != AggRule {
			continue
		}

		b, err := Eval(p.Expr, env)
		if err != nil {
			return matched, matchPolicies, fmt.Errorf("eval AggregatePolicy:%s failed, %s", p.ID, err)
		}

		if !b {
			continue
		}
		matched = true
		matchPolicies = append(matchPolicies, p)
	}
	sort.Sort(PoliciesListByPriority(matchPolicies))
	return matched, matchPolicies, nil
}

func RuleMatchAll(matchBasic []string, value ...string) bool {
	return comm.IsSubsetSlice(value, matchBasic)
}

func RuleMatchANY(matchBasic []string, value ...string) bool {
	r := comm.Intersect(matchBasic, value)
	return len(r) > 0
}

func RulePriorityHIG(matchBasic []string, value ...string) bool {
	return true
}

func RulePriorityLOW(matchBasic []string, value ...string) bool {
	return true
}

func RuleLevelHIG(matchBasic []string, value ...string) bool {
	return true
}

func RuleLevelLOW(matchBasic []string, value ...string) bool {
	return true
}

func generateDefaultBasicPolicy() map[string]any {
	mm := make(map[string]any, 20)
	mm[Operate.ID] = string(Operate.V.DML)
	mm[Action.ID] = string(Action.V.Select)
	mm[KeyWord.ID] = string(KeyWord.V.Select)
	mm[TabExist.ID] = true
	mm[TabSize.ID] = 100
	mm[TabRows.ID] = 100
	mm[AffectRows.ID] = 100
	mm[FreeDisk.ID] = 102400
	mm[DiskSufficient.ID] = true
	mm[PrimaryKeyExist.ID] = true
	mm[ForeignKeyExist.ID] = false
	mm[TriggerExist.ID] = false
	mm[IndexExistInWhere.ID] = true
	mm[CpuUsage.ID] = 10
	mm[BigTransaction.ID] = false
	return mm
}

func parseRuleValue(c *Policy) error {
	// c.Value可能的几种形式
	// 纯数字：		2048
	// 布尔：  		true false
	// 字符串：		update set
	// 字符串切片：	["*"], ["OPE.INSERT.000"]
	// 整型切片：	[20000,100000]
	value := ""
	if value1, ok := (c.Value).(*any); ok {
		if value2, ok := (*value1).([]uint8); ok {
			value = string(value2)
		}
	}

	// 判断是否是数字
	if IsNumber(value) {
		c.Value, _ = strconv.Atoi(value)
		return nil
	}

	// 判断是否是bool
	if v, err := strconv.ParseBool(value); err == nil {
		c.Value = v
		return nil
	}

	// 判断是否是切片类型
	if IsSliceString(value) {
		var o any
		if err := json.Unmarshal([]byte(value), &o); err != nil {
			return fmt.Errorf("failed to marshal(%s), policy id:%s, %s", value, c.ID, err)
		}

		oType := reflect.TypeOf(o)
		oValue := reflect.ValueOf(o)
		if oType.Kind() != reflect.Slice {
			return fmt.Errorf("the type of rule value looks like a slice, but it is %s, policy id:%s",
				oType.String(), c.ID)
		}

		if oValue.Len() == 0 {
			c.Value = []string{}
			return nil
		}

		elemType := reflect.TypeOf(oValue.Index(0).Interface()).Kind()
		switch elemType {
		case reflect.String:
			ss := make([]string, 0, oValue.Len())
			for i := 0; i < oValue.Len(); i++ {
				ss = append(ss, oValue.Index(i).Interface().(string))
			}
			c.Value = ss
			return nil
		case reflect.Int:
			ss := make([]int, 0, oValue.Len())
			for i := 0; i < oValue.Len(); i++ {
				ss = append(ss, oValue.Index(i).Interface().(int))
			}
			c.Value = ss
			return nil
		case reflect.Float64:
			ss := make([]int, 0, oValue.Len())
			for i := 0; i < oValue.Len(); i++ {
				ss = append(ss, int(oValue.Index(i).Interface().(float64)))
			}
			c.Value = ss
			return nil
		default:
			return fmt.Errorf("the type of slice for rule value is not supported(%s), policy id:%s",
				reflect.TypeOf(oValue.Index(0).Interface()).String(), c.ID)
		}
	}

	// 字符串
	switch c.RuleID {
	case Operate.ID:
		c.Value = OperateType(value)
	case Action.ID:
		c.Value = ActionType(value)
	case KeyWord.ID:
		c.Value = KeyWordType(value)
	default:
		c.Value = value
		return fmt.Errorf("unknown rule value type, policy id: %s", c.ID)
	}
	return nil
}

func IsNumber(input string) bool {
	return regexp.MustCompile(`^[0-9]+$`).MatchString(input)
}

func IsSliceString(str string) bool {
	return regexp.MustCompile(`^\[.*\]$`).MatchString(strings.TrimSpace(str))
}

// GeneratePolicyExpr 生成BASIC类型的expr表达式，修改结果存放到新的策略中，不会影响原始策略
func GeneratePolicyExpr(polices []Policy) ([]Policy, error) {
	newPolices := make([]Policy, len(polices))
	copy(newPolices, polices)

	var expr string
	var err error
	for i, p := range newPolices {
		switch p.Type {
		case BasicRule:
			expr, err = GenerateOneBasicPolicyExpr(p)
		case AggRule:
			expr, err = GenerateOneAggregatePolicyExpr(p)
		default:
			return nil, fmt.Errorf("unknown policy type(%s), policy id:%s", p.Type, p.ID)
		}

		if err != nil {
			return nil, fmt.Errorf("generate policy expr failed, policy id:%s, %s", p.ID, err)
		}
		newPolices[i].Expr = expr
	}
	return newPolices, nil
}

func GenerateOneBasicPolicyExpr(p Policy) (string, error) {
	expr := ""
	switch p.Operator {
	case RuleOperatorEQ, RuleOperatorNE, RuleOperatorLT, RuleOperatorLE, RuleOperatorGT, RuleOperatorGE:
		switch p.Value.(type) {
		case []int, []string:
			return "", fmt.Errorf("not support operator:%s on rule value type:%T", p.Operator, p.Value)
		case string, OperatorType, ActionType, KeyWordType:
			expr = fmt.Sprintf("%s %s \"%v\"", p.RuleID, p.Operator, p.Value)
		default:
			expr = fmt.Sprintf("%s %s %v", p.RuleID, p.Operator, p.Value)
		}

	case RuleOperatorBETWEEN:
		v, ok := p.Value.([]int)
		if !ok {
			return "", fmt.Errorf("OperatorType:%s only support rule value type: []int, but it is %T",
				RuleOperatorBETWEEN, p.Value)
		}
		if len(v) != 2 {
			return "", fmt.Errorf("OperatorType:%s rule value []int lenth must be 2, but it is %d",
				RuleOperatorBETWEEN, len(v))
		}

		expr = fmt.Sprintf("%v <= %s && %s >= %v", v[0], p.RuleID, p.RuleID, v[1])
	default:
		return "", fmt.Errorf("not support operator:%s on rule type:%s", p.Operator, BasicRule)
	}
	return expr, nil
}

// GenerateOneAggregatePolicyExpr 生成聚合的expr表达式
func GenerateOneAggregatePolicyExpr(p Policy) (string, error) {
	value, ok := p.Value.([]string)
	if !ok {
		return "", fmt.Errorf("rule value type must be []string, but it is:%T", p.Value)
	}

	if len(value) <= 0 {
		return "", fmt.Errorf("rule value type must be []string and lenght greate 0")
	}

	expr := ""
	switch p.RuleID {
	case RuleMatch.ID:
		switch p.Operator {
		case RuleOperatorALL, RuleOperatorANY:
			expr = fmt.Sprintf("%s(%s, %s)",
				strings.ToUpper(string(p.Operator)), matchBasicPolicies, comm.Slice2String(value))
		default:
			return "", fmt.Errorf("not support operator:%s on rule type:%s", p.Operator, AggRule)
		}
	case RulePriority.ID, RuleLevel.ID:
		switch p.Operator {
		case RuleOperatorHIG, RuleOperatorLOW:
			expr = fmt.Sprintf("%s(%s, %s)",
				strings.ToUpper(p.RuleID+string(p.Operator)), matchBasicPolicies, comm.Slice2String(value))
		default:
			return "", fmt.Errorf("not support operator:%s on rule type:%s", p.Operator, AggRule)
		}
	default:
		return "", fmt.Errorf("not support operator:%s on rule type:%s", p.Operator, BasicRule)
	}
	return expr, nil
}

func ValidatePolicy(p Policy) error {
	// 判断策略ID是否合法
	if !regexp.MustCompile(`^[A-Z]{3,}\.[A-Z]{3,}\.\d{3}$`).MatchString(p.ID) {
		return fmt.Errorf("policy id must comply with regular expressions '^[A-Z]{3,}\\.[A-Z]{3,}\\.\\d{3}$'")
	}

	// 判断名字是否合法
	if p.Name == "" {
		return fmt.Errorf("policy name cannot null")
	}

	// 判断规则类型是否合法
	if p.Type != BasicRule && p.Type != AggRule {
		return fmt.Errorf("policy type must in (%s,%s), policy id(%s) ", BasicRule, AggRule, p.ID)
	}

	// 判断规则ID是否在支持列表中
	match, rule := false, RuleMeta{}
	for _, rule = range GetRuleMeta() {
		if p.RuleID == rule.ID {
			match = true
			break
		}
	}
	if !match {
		return fmt.Errorf("policy rule_id invalid")
	}

	// 判断规则是否支持对应的操作
	if !comm.EleExist(p.Operator, rule.Operator) {
		return fmt.Errorf("rule_id(%s) not support operator(%s), support operator %v", rule.ID, p.Operator, rule.Operator)
	}

	// 判断风险等级是否合法
	switch p.Level {
	case comm.Fatal, comm.High, comm.Low, comm.Info:
	default:
		return fmt.Errorf("policy level not support(%s)", p.Level)
	}

	return nil
}

func fetchPolicyID(policies []Policy) []string {
	s := make([]string, 0, len(policies))
	for _, policy := range policies {
		s = append(s, policy.ID)
	}
	return s
}
