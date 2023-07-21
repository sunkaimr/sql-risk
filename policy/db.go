package policy

import (
	"fmt"
	"gorm.io/gorm"
)

func RefreshOperateTypeMetaToDB(db *gorm.DB) error {
	var err error
	//err = db.AutoMigrate(&OperateTypeMeta{})
	//if err != nil {
	//	return fmt.Errorf("AutoMigrate OperateTypeMeta failed, %s", err)
	//}

	metas := generateOperateTypeMeta()
	err = db.Transaction(func(tx *gorm.DB) error {
		if err = tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&OperateTypeMeta{}).Error; err != nil {
			return err
		}
		if err = tx.Create(&metas).Error; err != nil {
			return err
		}
		return nil
	})
	operateTypeMeta = metas
	return err
}

func RefreshActionTypeMetaToDB(db *gorm.DB) error {
	var err error
	//err = db.AutoMigrate(&ActionTypeMeta{})
	//if err != nil {
	//	return fmt.Errorf("AutoMigrate ActionTypeMeta failed, %s", err)
	//}

	metas := generateActionTypeMeta()
	err = db.Transaction(func(tx *gorm.DB) error {
		if err = tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&ActionTypeMeta{}).Error; err != nil {
			return err
		}
		if err = tx.Create(&metas).Error; err != nil {
			return err
		}
		return nil
	})
	actionTypeMeta = metas
	return err
}

func RefreshKeyWordTypeMateToDB(db *gorm.DB) error {
	var err error
	//err = db.AutoMigrate(&KeyWordTypeMeta{})
	//if err != nil {
	//	return fmt.Errorf("AutoMigrate KeyWordTypeMeta failed, %s", err)
	//}

	metas := generateKeyWordTypeMeta()
	err = db.Transaction(func(tx *gorm.DB) error {
		if err = tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&KeyWordTypeMeta{}).Error; err != nil {
			return err
		}
		if err = tx.Create(&metas).Error; err != nil {
			return err
		}
		return nil
	})
	keyWordTypeMeta = metas
	return err
}

func RefreshRuleMetasToDB(db *gorm.DB) error {
	var err error
	//err = db.AutoMigrate(&RuleMeta{})
	//if err != nil {
	//	return fmt.Errorf("AutoMigrate RuleMeta failed, %s", err)
	//}

	metas := generateRuleMeta()
	err = db.Transaction(func(tx *gorm.DB) error {
		if err = tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&RuleMeta{}).Error; err != nil {
			return err
		}
		if err = tx.Create(&metas).Error; err != nil {
			return err
		}
		return nil
	})

	ruleMeta = metas
	return err
}

func RefreshDefaultPolicyToDB(db *gorm.DB) error {
	var err error
	//err = db.AutoMigrate(&Policy{})
	//if err != nil {
	//	return fmt.Errorf("AutoMigrate Policy failed, %s", err)
	//}

	policies := generateDefaultPolicy()

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
			return fmt.Errorf("policy(%s) validate failed, %s", p.ID, err)
		}
	}

	// 生成expr表达式
	policies, err = GeneratePolicyExpr(policies)
	if err != nil {
		return fmt.Errorf("generate basic policy expr failed, %s", err)
	}

	err = db.Transaction(func(tx *gorm.DB) error {
		if err = tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&Policy{}).Error; err != nil {
			return err
		}
		if err = tx.Create(&policies).Error; err != nil {
			return err
		}
		return nil
	})

	policyMeta = policies
	return err
}

func RefreshPolicyFromDB(db *gorm.DB) error {
	policies := make([]Policy, 0, 100)
	// 从数据库加载策略
	err := db.Find(&policies).Error
	if err != nil {
		return err
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
			return fmt.Errorf("policy(%s) validate failed, %s", p.ID, err)
		}
	}

	// 生成expr表达式
	policies, err = GeneratePolicyExpr(policies)
	if err != nil {
		return fmt.Errorf("generate basic policy expr failed, %s", err)
	}

	policyMeta = policies
	return nil
}
