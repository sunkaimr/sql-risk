package policy

import (
	"fmt"
	"github.com/DATA-DOG/go-sqlmock"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"testing"
)

var db *gorm.DB
var fakeDB = true

func initDB() {
	if fakeDB {
		dbMock, mock, _ := sqlmock.New()
		rows := sqlmock.NewRows([]string{"VERSION()"}).AddRow("8.0.0")
		mock.ExpectQuery("SELECT VERSION()").WillReturnRows(rows)
		mock.ExpectBegin()
		mock.ExpectExec("DELETE").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("INSERT").WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectCommit()
		db, _ = gorm.Open(mysql.New(mysql.Config{Conn: dbMock}), &gorm.Config{})
	} else {
		var err error
		db, err = newDB()
		if err != nil {
			panic(err)
		}
		db.AutoMigrate(&OperateTypeMeta{})
		db.AutoMigrate(&ActionTypeMeta{})
		db.AutoMigrate(&KeyWordTypeMeta{})
		db.AutoMigrate(&RuleMeta{})
		db.AutoMigrate(&Policy{})
	}
}

func newDB() (*gorm.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local", "root", "123456", "127.0.0.1", "3306", "test")
	return gorm.Open(mysql.Open(dsn), &gorm.Config{})
}

func TestRefreshOperateTypeMetaToDB(t *testing.T) {
	initDB()
	err := RefreshOperateTypeMetaToDB(db)
	if err != nil {
		t.Fatal(err)
	}
}
func TestRefreshActionTypeMetaToDB(t *testing.T) {
	initDB()
	err := RefreshActionTypeMetaToDB(db)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRefreshKeyWordTypeMateToDB(t *testing.T) {
	initDB()
	err := RefreshKeyWordTypeMateToDB(db)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRefreshRuleMetaToDB(t *testing.T) {
	initDB()
	err := RefreshRuleMetasToDB(db)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRefreshDefaultPolicyToDB(t *testing.T) {
	initDB()
	err := RefreshDefaultPolicyToDB(db)
	if err != nil {
		t.Fatal(err)
	}
}

func TestRefreshPolicyFromDB(t *testing.T) {
	if fakeDB {
		dbMock, mock, _ := sqlmock.New()
		rows := sqlmock.NewRows([]string{"VERSION()"}).AddRow("8.0.0")
		mock.ExpectQuery("SELECT VERSION()").WillReturnRows(rows)
		rows1 := sqlmock.NewRows([]string{"id", "name", "enable", "type", "rule_id", "operator", "value", "level", "special", "priority"}).
			AddRow("OPE.SELECT.001", "查询", 1, "BASIC", "KeyWord", "==", any("select"), "low", 0, 60) /*.
		AddRow("AGG.RULEPRIORITY.001", "优先级最高的基本策略", 1, "AGG", "RulePriority", "highest", any("[\"*\"]"), "low", 1, 150)*/
		mock.ExpectQuery("SELECT ").WillReturnRows(rows1)
		db, _ = gorm.Open(mysql.New(mysql.Config{Conn: dbMock}), &gorm.Config{})
	} else {
		var err error
		db, err = newDB()
		if err != nil {
			panic(err)
		}
	}

	err := RefreshPolicyFromDB(db)
	if err != nil {
		t.Fatal(err)
	}
}
