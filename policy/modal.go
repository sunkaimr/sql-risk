package policy

import (
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"github.com/sunkaimr/sql-risk/comm"
	"gorm.io/gorm"
)

type OperatorTypeSlice []OperatorType

func (c *OperatorTypeSlice) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to unmarshal value: %s", value)
	}

	result := OperatorTypeSlice{}
	err := json.Unmarshal(bytes, &result)
	*c = result
	return err
}

func (c OperatorTypeSlice) Value() (driver.Value, error) {
	if len(c) == 0 {
		return nil, nil
	}

	buf := bytes.NewBuffer([]byte{})
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(c)
	return buf.String(), err
}

type OperateTypeMeta struct {
	ID    string `gorm:"type:varchar(64);primary_key;column:id"`
	Value string `gorm:"type:varchar(64);not null;column:value;"`
}

type ActionTypeMeta struct {
	ID    string `gorm:"type:varchar(64);primary_key;column:id"`
	Value string `gorm:"type:varchar(64);not null;column:value;"`
}

type KeyWordTypeMeta struct {
	ID    string `gorm:"type:varchar(64);primary_key;column:id;"`
	Value string `gorm:"type:varchar(64);not null;column:value;"`
}

type RuleMeta struct {
	ID          string            `gorm:"type:varchar(64);primary_key;column:id;comment:规则ID"`
	Name        string            `gorm:"type:varchar(64);not null;column:name;comment:规则名称"`
	Type        RuleType          `gorm:"type:varchar(64);not null;column:type;comment:规则类型"`
	ValueType   RuleValueType     `gorm:"type:varchar(64);not null;column:value_type;comment:值类型"`
	Operator    OperatorTypeSlice `gorm:"type:varchar(128);not null;column:operator;comment:支持的运算符"`
	Description string            `gorm:"type:varchar(2048);not null;column:description;comment:描述"`
}

// 建议优先级使用范围
// Basic: 0 - 300
// AGG:   300 - 500
// Fatal: 999
type Policy struct {
	ID          string       `gorm:"type:varchar(64);primary_key;column:id;comment:策略ID"`
	Name        string       `gorm:"type:varchar(1024);not null;column:name;comment:策略名称"`
	Type        RuleType     `gorm:"type:varchar(64);not null;column:type;comment:策略类型"`
	Enable      bool         `gorm:"type:tinyint(1) ;not null;column:enable;comment:是否启用策略"`
	RuleID      string       `gorm:"type:varchar(64);not null;column:rule_id;comment:使用的规则ID"`
	Operator    OperatorType `gorm:"type:varchar(64);not null;column:operator;comment:操作符"`
	Value       any          `gorm:"type:varchar(2048);not null;column:value;comment:规则对应的值"`
	Level       comm.Level   `gorm:"type:varchar(64);not null;column:level;comment:风险等级"`
	Special     bool         `gorm:"type:tinyint(1) ;not null;column:special;comment:是否走特殊流程"`
	Priority    int          `gorm:"type:int;column:priority;comment:优先级"`
	Description string       `gorm:"type:varchar(2048);not null;column:description;comment:策略描述"`
	Suggestion  string       `gorm:"type:varchar(2048);not null;column:suggestion;comment:建议"`
	Expr        string       `gorm:"-"`
}

func (c *Policy) BeforeSave(tx *gorm.DB) error {
	var err error
	switch c.Value.(type) {
	case int:
		c.Value = fmt.Sprintf("%d", c.Value)
	case string, ActionType, OperatorType, KeyWordType:
		c.Value = fmt.Sprintf("%s", c.Value)
	case bool:
		c.Value = fmt.Sprintf("%v", c.Value)
	case []int, []string:
		c.Value, err = json.Marshal(c.Value)
		if err != nil {
			return fmt.Errorf("failed to marshal %v, policy id:%s, %s", c.Value, c.ID, err)
		}
	default:
		return fmt.Errorf("failed to marshal(%s), not support type:%T, policy id:%s", err, c.Value, c.ID)
	}
	return nil
}

func (c *Policy) AfterFind(tx *gorm.DB) error {
	return parseRuleValue(c)
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

// Less 排序，先按优先级（数字越大优先级越高）, 再按风险等级，最后按是否走特殊流程
func (a PoliciesListByLevel) Less(i, j int) bool {
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

func (a PoliciesListByLevel) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
