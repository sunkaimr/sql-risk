package policy

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestGenerateOperateTypeMates(t *testing.T) {
	t.Run("generateOperateTypeMeta", func(t *testing.T) {
		o := generateOperateTypeMeta()
		fmt.Printf("%+v\n", o)
	})
}

func TestGenerateActionTypeMates(t *testing.T) {
	t.Run("generateActionTypeMeta", func(t *testing.T) {
		o := generateActionTypeMeta()
		fmt.Printf("%+v\n", o)
	})
}

func TestGenerateKeyWordTypeMates(t *testing.T) {
	t.Run("generateKeyWordTypeMeta", func(t *testing.T) {
		o := generateKeyWordTypeMeta()
		b, err := json.MarshalIndent(o, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(string(b))
	})
}

func TestGenerateRuleMates(t *testing.T) {
	t.Run("generateRuleMeta", func(t *testing.T) {
		o := generateRuleMeta()
		b, err := json.MarshalIndent(o, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(string(b))
	})
}

func TestGenerateDefaultPolicy(t *testing.T) {
	t.Run("generateDefaultPolicy", func(t *testing.T) {
		o := generateDefaultPolicy()
		b, err := json.MarshalIndent(o, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(string(b))
		//fmt.Fprintln(os.Stdout, string(b))
	})

}

func TestMatchBasicPolicy(t *testing.T) {
	initDB()
	err := RefreshDefaultPolicyToDB(db)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("MatchBasicPolicy", func(t *testing.T) {
		env := generateDefaultBasicPolicy()
		b, policy, err := MatchBasicPolicy(env)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("%v\n%+v", b, policy)
	})
}
