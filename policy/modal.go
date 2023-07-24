package policy

import (
	"github.com/sunkaimr/sql-risk/comm"
)

type OperateTypeMeta struct {
	ID    string `gorm:"type:varchar(64);primary_key;column:id" yaml:"id"`
	Value string `gorm:"type:varchar(64);not null;column:value;" yaml:"value"`
}

type ActionTypeMeta struct {
	ID    string `gorm:"type:varchar(64);primary_key;column:id" yaml:"id"`
	Value string `gorm:"type:varchar(64);not null;column:value;" yaml:"value"`
}

type KeyWordTypeMeta struct {
	ID    string `gorm:"type:varchar(64);primary_key;column:id;" yaml:"id"`
	Value string `gorm:"type:varchar(64);not null;column:value;" yaml:"value"`
}

type RuleMeta struct {
	ID          string            `gorm:"type:varchar(64);primary_key;column:id;comment:规则ID" yaml:"id"`
	Name        string            `gorm:"type:varchar(64);not null;column:name;comment:规则名称" yaml:"name"`
	Type        RuleType          `gorm:"type:varchar(64);not null;column:type;comment:规则类型" yaml:"type"`
	ValueType   RuleValueType     `gorm:"type:varchar(64);not null;column:value_type;comment:值类型" yaml:"value_type"`
	Operator    OperatorTypeSlice `gorm:"type:varchar(128);not null;column:operator;comment:支持的运算符" yaml:"operator"`
	Description string            `gorm:"type:varchar(2048);not null;column:description;comment:描述" yaml:"description"`
}

// 建议优先级使用范围
// Basic: 0 - 300
// AGG:   300 - 500
// Fatal: 999
type Policy struct {
	ID          int          `gorm:"type:int;column:id;comment:ID" yaml:"id"`
	PolicyID    string       `gorm:"type:varchar(64);primary_key;column:policy_id;comment:策略ID"  yaml:"policy_id"`
	Name        string       `gorm:"type:varchar(1024);not null;column:name;comment:策略名称" yaml:"name"`
	Type        RuleType     `gorm:"type:varchar(64);not null;column:type;comment:策略类型" yaml:"type"`
	Enable      bool         `gorm:"type:tinyint(1) ;not null;column:enable;comment:是否启用策略" yaml:"enable"`
	RuleID      string       `gorm:"type:varchar(64);not null;column:rule_id;comment:使用的规则ID" yaml:"rule_id"`
	Operator    OperatorType `gorm:"type:varchar(64);not null;column:operator;comment:操作符" yaml:"operator"`
	Value       any          `gorm:"type:varchar(2048);not null;column:value;comment:规则对应的值" yaml:"value"`
	Level       comm.Level   `gorm:"type:varchar(64);not null;column:level;comment:风险等级" yaml:"level"`
	Special     bool         `gorm:"type:tinyint(1) ;not null;column:special;comment:是否走特殊流程" yaml:"special"`
	Priority    int          `gorm:"type:int;column:priority;comment:优先级" yaml:"priority"`
	Description string       `gorm:"type:varchar(2048);not null;column:description;comment:策略描述" yaml:"description"`
	Suggestion  string       `gorm:"type:varchar(2048);not null;column:suggestion;comment:建议" yaml:"suggestion"`
	Expr        string       `gorm:"type:varchar(1024);column:expr;comment:策略表达式" yaml:"expr"`
}

type PoliciesListByPriority []Policy

func (a PoliciesListByPriority) Len() int {
	return len(a)
}

// Less 排序，先按优先级（数字越大优先级越高）, 再按风险等级，最后按是否走特殊流程
func (a PoliciesListByPriority) Less(i, j int) bool {
	if a[i].Priority < a[j].Priority {
		return false
	} else if a[i].Priority > a[j].Priority {
		return true
	}

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

func (a PoliciesListByPriority) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

type PoliciesListByLevel []Policy

func (a PoliciesListByLevel) Len() int {
	return len(a)
}

// Less 排序，先按风险等级，最后按是否走特殊流程
func (a PoliciesListByLevel) Less(i, j int) bool {
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

func (a PoliciesListByLevel) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
