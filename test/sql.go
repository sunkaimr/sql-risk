package test

import (
	"fmt"
	"github.com/sunkaimr/sql-risk/comm"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"net"
	"strconv"
	"strings"
)

type CoreDataSource struct {
	ID               uint   `gorm:"primary_key;AUTO_INCREMENT" json:"id"`
	IDC              string `gorm:"type:varchar(50);not null" json:"idc"`
	Source           string `gorm:"type:varchar(50);not null" json:"source"`
	IP               string `gorm:"type:varchar(200);not null" json:"ip"`
	Port             int    `gorm:"type:int(10);not null" json:"port"`
	Username         string `gorm:"type:varchar(50);not null" json:"username"`
	Password         string `gorm:"type:varchar(150);not null" json:"password"`
	IsQuery          int    `gorm:"type:tinyint(2);not null" json:"is_query"` // 0写 1读 2读写
	FlowID           int    `gorm:"type:int(100);not null" json:"flow_id"`
	SourceId         string `gorm:"type:varchar(200);not null;index:source_idx"  json:"source_id"`
	ServiceUniID     string `gorm:"type:varchar(200);not null;"  json:"service_uni_id"`
	DatabaseName     string `gorm:"type:varchar(4096);"  json:"database_name"`
	ExcludeDbList    string `gorm:"type:varchar(200);not null" json:"exclude_db_list"`
	InsulateWordList string `gorm:"type:varchar(200);not null" json:"insulate_word_list"`
	Principal        string `gorm:"type:varchar(150);not null" json:"principal"`
	CAFile           string `gorm:"type:longtext;default ''" json:"ca_file"`
	Cert             string `gorm:"type:longtext;default ''" json:"cert"`
	KeyFile          string `gorm:"type:longtext;default ''" json:"key_file"`
	ReadWriteHost    string `gorm:"type:varchar(200);not null" json:"read_write_host"`
	ReadWritePort    int    `gorm:"type:varchar(200);not null" json:"read_write_port"`
	ReadOnlyHost     string `gorm:"type:varchar(200);not null" json:"read_only_host"`
	ReadOnlyPort     int    `gorm:"type:varchar(200);not null" json:"read_only_port"`
	ReadOnlyUser     string `gorm:"type:varchar(50);not null" json:"readonly_user"`
	ReadOnlyPasswd   string `gorm:"type:varchar(150);not null" json:"readonly_passwd"`
}

func newDB() (db *gorm.DB, err error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local", "root", "123456", "192.168.198.128", "30336", "Yearning")
	return gorm.Open(mysql.Open(dsn), &gorm.Config{})
}

func QueryDataSourceByDBName(db *gorm.DB, dbName string) ([]CoreDataSource, error) {
	var sources []CoreDataSource
	err := db.Model(CoreDataSource{}).Where("database_name LIKE ?", "%"+dbName+"%").Find(&sources).Error
	if err != nil {
		return nil, err
	}

	var matchedSources []CoreDataSource
	for _, source := range sources {
		ss := strings.Split(source.DatabaseName, ",")
		for _, s := range ss {
			if s == dbName {
				matchedSources = append(matchedSources, source)
				break
			}
		}
	}

	return matchedSources, nil
}

func FilterDataSourceByEnv(dataSources []CoreDataSource, env string) []CoreDataSource {
	var matchedSources []CoreDataSource
	for _, v := range dataSources {
		if v.IDC == env {
			matchedSources = append(matchedSources, v)
		}
	}
	return matchedSources
}

func FilterDataSourceByRole(dataSources []CoreDataSource, roles []string) []CoreDataSource {
	var matchedSources []CoreDataSource
	for _, v := range dataSources {
		for _, role := range roles {
			switch role {
			case "ro", "s":
				if v.ReadOnlyHost != "" && v.ReadOnlyPort != 0 {
					matchedSources = append(matchedSources, v)
				}
			case "ms", "m":
				if v.ReadWriteHost != "" && v.ReadWritePort != 0 {
					matchedSources = append(matchedSources, v)
				}
			}
		}
	}
	return matchedSources
}

func GetDBAddrByDBName(dbName string) (addr, port, database, user, passwd string, err error) {
	if dbName == "" {
		return "", "", "", "", "", fmt.Errorf("dbName is null")
	}

	db, err := newDB()
	if err != nil {
		return "", "", "", "", "", err
	}
	dss, err := QueryDataSourceByDBName(db, dbName)
	if err != nil {
		return "", "", "", "", "", err
	}

	if len(dss) == 0 {
		return "", "", "", "", "", fmt.Errorf("not found database %s", dbName)
	}

	dssRole := FilterDataSourceByRole(dss, []string{"ro", "s"})
	dss = FilterDataSourceByEnv(dssRole, "Prod")
	if len(dss) == 0 {
		dss = dssRole
	}

	if len(dss) == 0 {
		return "", "", "", "", "", fmt.Errorf("not found readonly database %s", dbName)
	}

	if dss[0].ReadOnlyHost == "" || dss[0].ReadOnlyPort == 0 {
		return "", "", "", "", "", fmt.Errorf("readonly host or port is null")
	}

	addr, err = LookupIP(dss[0].ReadOnlyHost)
	if err != nil {
		return "", "", "", "", "", fmt.Errorf("lookup %s failed, %s", dss[0].ReadOnlyHost, err)
	}

	pw := comm.Decrypt(dss[0].ReadOnlyPasswd)

	if dss[0].ReadOnlyUser == "" || pw == "" {
		return "", "", "", "", "", fmt.Errorf("readonly user or passwd is null")
	}

	return addr, strconv.Itoa(dss[0].ReadOnlyPort), dbName, dss[0].ReadOnlyUser, pw, nil
}

func LookupIP(host string) (string, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("lookup %s to ip failed, %s", host, err)
	} else if len(ips) == 0 {
		return "", fmt.Errorf("lookup %s to ip failed, ip is null", host)

	}
	return ips[0].String(), err
}
