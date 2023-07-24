package policy

import (
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"gorm.io/gorm"
)

type MysqlStore struct {
	*gorm.DB
}

type OperatorTypeSlice []OperatorType

func (c *OperatorTypeSlice) Scan(value interface{}) error {
	b, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to unmarshal value: %s", value)
	}

	result := OperatorTypeSlice{}
	err := json.Unmarshal(b, &result)
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
			return fmt.Errorf("failed to marshal %v, policy id:%s, %s", c.Value, c.PolicyID, err)
		}
	default:
		return fmt.Errorf("failed to marshal(%s), not support type:%T, policy id:%s", err, c.Value, c.PolicyID)
	}
	return nil
}

func (c *Policy) AfterFind(tx *gorm.DB) error {
	return parseRuleValue(c)
}

func (c *MysqlStore) Init() error {
	err := c.AutoMigrate(&OperateTypeMeta{}, &ActionTypeMeta{}, &KeyWordTypeMeta{}, &RuleMeta{}, &Policy{})
	if err != nil {
		return fmt.Errorf("AutoMigrate Policy failed, %s", err)
	}

	var count int64
	err = c.Model(&Policy{}).Count(&count).Error
	if err != nil {
		return fmt.Errorf("count ploicy failed, %s", err)
	}

	if count == 0 {
		err = c.PolicyWriter(GenerateDefaultPolicy())
		if err != nil {
			return fmt.Errorf("write default ploicy failed, %s", err)
		}
		return nil
	}

	err = c.Transaction(func(tx *gorm.DB) error {
		// OperateTypeMeta
		operate := GenerateOperateTypeMeta()
		if err = tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&OperateTypeMeta{}).Error; err != nil {
			return err
		}
		if err = tx.Create(&operate).Error; err != nil {
			return err
		}
		// ActionTypeMeta
		action := GenerateActionTypeMeta()
		if err = tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&ActionTypeMeta{}).Error; err != nil {
			return err
		}
		if err = tx.Create(&action).Error; err != nil {
			return err
		}

		// KeyWordTypeMeta
		keyword := GenerateKeyWordTypeMeta()
		if err = tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&KeyWordTypeMeta{}).Error; err != nil {
			return err
		}
		if err = tx.Create(&keyword).Error; err != nil {
			return err
		}

		// RuleMeta
		rule := GenerateRuleMeta()
		if err = tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&RuleMeta{}).Error; err != nil {
			return err
		}
		if err = tx.Create(&rule).Error; err != nil {
			return err
		}

		operateTypeMeta = operate
		actionTypeMeta = action
		keyWordTypeMeta = keyword
		ruleMeta = rule
		return nil
	})

	return err
}

func (c *MysqlStore) PolicyReader() ([]Policy, error) {
	policies := make([]Policy, 0, 100)
	// 从数据库加载策略
	err := c.Find(&policies).Error
	if err != nil {
		return nil, err
	}

	// 生成策略名字
	for i, p := range policies {
		if p.Type != AggRule || p.RuleID != RuleMatch.ID || p.Name != "" {
			continue
		}

		policies[i].Name = generatePolicyName(p, policies)
	}

	// 校验策略
	for _, p := range policies {
		err = ValidatePolicy(p)
		if err != nil {
			return nil, fmt.Errorf("policy(%s) validate failed, %s", p.PolicyID, err)
		}
	}

	// 生成expr表达式
	policies, err = GeneratePolicyExpr(policies)
	if err != nil {
		return nil, fmt.Errorf("generate policy expr failed, %s", err)
	}

	policyMeta = policies
	return policies, nil
}

func (c *MysqlStore) PolicyWriter(policies []Policy) error {
	var err error
	// 生成策略名字
	for i, p := range policies {
		policies[i].ID = i
		if p.Type != AggRule || p.RuleID != RuleMatch.ID || p.Name != "" {
			continue
		}

		policies[i].Name = generatePolicyName(p, policies)
	}

	// 校验策略
	for _, p := range policies {
		err = ValidatePolicy(p)
		if err != nil {
			return fmt.Errorf("policy(%s) validate failed, %s", p.PolicyID, err)
		}
	}

	// 生成expr表达式
	policies, err = GeneratePolicyExpr(policies)
	if err != nil {
		return fmt.Errorf("generate policy expr failed, %s", err)
	}

	err = c.Transaction(func(tx *gorm.DB) error {
		// OperateTypeMeta
		operate := GenerateOperateTypeMeta()
		if err = tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&OperateTypeMeta{}).Error; err != nil {
			return err
		}
		if err = tx.Create(&operate).Error; err != nil {
			return err
		}
		// ActionTypeMeta
		action := GenerateActionTypeMeta()
		if err = tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&ActionTypeMeta{}).Error; err != nil {
			return err
		}
		if err = tx.Create(&action).Error; err != nil {
			return err
		}

		// KeyWordTypeMeta
		keyword := GenerateKeyWordTypeMeta()
		if err = tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&KeyWordTypeMeta{}).Error; err != nil {
			return err
		}
		if err = tx.Create(&keyword).Error; err != nil {
			return err
		}

		rule := GenerateRuleMeta()
		if err = tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&RuleMeta{}).Error; err != nil {
			return err
		}
		if err = tx.Create(&rule).Error; err != nil {
			return err
		}

		if err = tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&Policy{}).Error; err != nil {
			return err
		}
		if err = tx.Create(&policies).Error; err != nil {
			return err
		}

		operateTypeMeta = operate
		actionTypeMeta = action
		keyWordTypeMeta = keyword
		ruleMeta = rule
		policyMeta = policies
		return nil
	})
	return err
}
