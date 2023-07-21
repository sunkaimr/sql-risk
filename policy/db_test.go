package policy

import (
	"fmt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"testing"
)

func newDB() (db *gorm.DB, err error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local", "root", "123456", "192.168.198.128", "30336", "test")
	return gorm.Open(mysql.Open(dsn), &gorm.Config{})
}

func TestRefreshOperateTypeMetaToDB(t *testing.T) {
	db, err := newDB()
	if err != nil {
		t.Fatal(err)
	}
	err = RefreshOperateTypeMetaToDB(db)
	if err != nil {
		t.Fatal(err)
	}
}
func TestRefreshActionTypeMetaToDB(t *testing.T) {
	db, err := newDB()
	if err != nil {
		t.Fatal(err)
	}

	err = RefreshActionTypeMetaToDB(db)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRefreshKeyWordTypeMateToDB(t *testing.T) {
	db, err := newDB()
	if err != nil {
		t.Fatal(err)
	}

	err = RefreshKeyWordTypeMateToDB(db)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRefreshRuleMetaToDB(t *testing.T) {
	db, err := newDB()
	if err != nil {
		t.Fatal(err)
	}

	err = RefreshRuleMetasToDB(db)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRefreshDefaultPolicyToDB(t *testing.T) {
	db, err := newDB()
	if err != nil {
		t.Fatal(err)
	}

	err = RefreshDefaultPolicyToDB(db)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRefreshPolicyFromDB(t *testing.T) {
	db, err := newDB()
	if err != nil {
		t.Fatal(err)
	}

	err = RefreshPolicyFromDB(db)
	if err != nil {
		t.Fatal(err)
	}
}
