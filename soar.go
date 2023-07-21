package risk

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

const soarBin = "D:\\User\\sunkai\\Desktop\\soar.windows-amd64.exe"

type SQLRiskResult struct {
	ID             string      `json:"ID"`
	Fingerprint    string      `json:"Finger"`
	Score          int         `json:"Score"`
	Sample         string      `json:"Sample"`
	Explain        interface{} `json:"Explain"`
	HeuristicRules []struct {
		Item     string `json:"Item"`
		Severity string `json:"Severity"`
		Summary  string `json:"Summary"`
		Content  string `json:"Content"`
		Case     string `json:"Case"`
		Position int    `json:"Position"`
	} `json:"HeuristicRules"`
	IndexRules interface{} `json:"IndexRules"`
	Tables     []string    `json:"Tables"`
}

func SoarVersion() (string, error) {
	stdout, err := exec.Command(soarBin, "-version").CombinedOutput()
	return string(stdout), err
}

func SoarRun(sql string) ([]SQLRiskResult, error) {
	result := make([]SQLRiskResult, 0, 1)

	arg := fmt.Sprintf("-query=%s", sql)
	stdout, err := exec.Command(soarBin, "-report-type=json", arg).CombinedOutput()
	if err != nil {
		return result, fmt.Errorf("soar exec '%s', %s ", sql, err)
	}

	err = json.Unmarshal(stdout, &result)
	if err != nil {
		return result, fmt.Errorf("fail to unmarshal '%s', %s ", string(stdout), err)
	}
	return result, err
}
