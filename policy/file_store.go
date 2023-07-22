package policy

import (
	"fmt"
	"github.com/sunkaimr/sql-risk/comm"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
)

type FileStorage struct {
	FilePath string
}

type PolicyYaml struct {
	OperateTypeMeta []OperateTypeMeta
	ActionTypeMeta  []ActionTypeMeta
	KeyWordTypeMeta []KeyWordTypeMeta
	RuleMeta        []RuleMeta
	Policy          []Policy
}

func (c *FileStorage) Init() error {
	path := filepath.Dir(c.FilePath)
	if !comm.PathExist(path) {
		err := os.MkdirAll(path, 0755)
		if err != nil {
			return fmt.Errorf("create dir %s failed, %v", path, err)
		}
	}

	operateTypeMeta = GenerateOperateTypeMeta()
	actionTypeMeta = GenerateActionTypeMeta()
	keyWordTypeMeta = GenerateKeyWordTypeMeta()
	ruleMeta = GenerateRuleMeta()
	return nil
}

func (c *FileStorage) PolicyReader() ([]Policy, error) {
	data, err := os.ReadFile(c.FilePath)
	if err != nil {
		return nil, err
	}

	policyYaml := PolicyYaml{}
	err = yaml.Unmarshal(data, &policyYaml)
	if err != nil {
		return nil, err
	}
	policies := policyYaml.Policy

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
			return nil, fmt.Errorf("policy(%s) validate failed, %s", p.ID, err)
		}
	}

	// 生成expr表达式
	policies, err = GeneratePolicyExpr(policies)
	if err != nil {
		return nil, fmt.Errorf("generate basic policy expr failed, %s", err)
	}

	policyMeta = policies
	return policies, nil
}

func (c *FileStorage) PolicyWriter(policies []Policy) error {
	var err error
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

	file, err := os.Create(c.FilePath)
	if err != nil {
		return err
	}
	defer file.Close()

	policyYaml := PolicyYaml{
		OperateTypeMeta: GenerateOperateTypeMeta(),
		ActionTypeMeta:  GetActionTypeMeta(),
		KeyWordTypeMeta: GenerateKeyWordTypeMeta(),
		RuleMeta:        GenerateRuleMeta(),
		Policy:          GetPolicy(),
	}
	yamlData, err := yaml.Marshal(&policyYaml)
	if err != nil {
		return err
	}
	_, err = file.Write(yamlData)
	return err
}
