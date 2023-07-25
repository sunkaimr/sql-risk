package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/sunkaimr/sql-risk"
	"github.com/sunkaimr/sql-risk/comm"
	"github.com/sunkaimr/sql-risk/policy"
	"github.com/xuri/excelize/v2"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var (
	actionFileName = "action.xlsx"
)

// ReadSQLFromFile 从excel读取SQL转换为工单结构
func ReadSQLFromFile(file, sheetName string) ([]sqlrisk.WorkRisk, error) {
	// 动作	来源	编号	地址	端口	库名	表名	表大小	表行数	SQL
	Header := map[string]int{
		"动作":  0, //"A",
		"来源":  1, //"B",
		"编号":  2, //"C",
		"地址":  3, //"D",
		"端口":  4, //"E",
		"库名":  5, //"F",
		"表名":  6, //"G",
		"表大小": 7, //"H",
		"表行数": 8, //"I",
		"SQL": 9, //  "J",
	}

	f, err := excelize.OpenFile(file)
	if err != nil {
		return nil, fmt.Errorf("open file %s failed, %s", actionFileName, err)
	}
	defer f.Close()

	rows, err := f.GetRows(sheetName)
	if err != nil {
		return nil, fmt.Errorf("get rows failed, %s", err)
	}

	workRiskMap := make(map[string][]sqlrisk.SQLRisk, 100)
	for i, row := range rows {
		if i == 0 {
			continue
		}
		r := sqlrisk.SQLRisk{
			Addr:     row[Header["地址"]],
			Port:     row[Header["端口"]],
			DataBase: row[Header["库名"]],
			Tables:   []string{row[Header["表名"]]},
			SQLText:  row[Header["SQL"]],
			Errors:   nil,
		}

		if r.Addr == "" || r.Port == "" || r.DataBase == "" || r.SQLText == "" {
			continue
		}

		if _, ok := workRiskMap[row[Header["编号"]]]; !ok {
			workRiskMap[row[Header["编号"]]] = []sqlrisk.SQLRisk{r}
		} else {
			workRiskMap[row[Header["编号"]]] = append(workRiskMap[row[Header["编号"]]], r)
		}
	}

	wkSQL := make([]sqlrisk.WorkRisk, 0, len(workRiskMap))
	for k, risks := range workRiskMap {
		addr, port, db, sqlText := "", "", "", ""
		for _, r := range risks {
			addr = r.Addr
			port = r.Port
			db = r.DataBase
			r.SQLText = strings.TrimRight(r.SQLText, "\r\n")
			if r.SQLText[len(r.SQLText)-1] == ';' {
				sqlText = sqlText + r.SQLText
			} else {
				sqlText = sqlText + r.SQLText + ";"
			}
		}

		wk := sqlrisk.WorkRisk{
			WorkID:   k,
			Addr:     addr,
			Port:     port,
			User:     "*",
			Passwd:   "*",
			DataBase: db,
			SQLText:  sqlText,
			Errors:   nil,
		}

		wkSQL = append(wkSQL, wk)
	}

	return wkSQL, nil
}

// TestIdentifySQLFinger 识别excel中SQL的指纹
func TestIdentifySQLFinger(t *testing.T) {
	// 动作	来源	编号	地址	端口	库名	表名	表大小	表行数	SQL
	header := map[string]int{
		"动作":  0, //"A",
		"来源":  1, //"B",
		"编号":  2, //"C",
		"地址":  3, //"D",
		"端口":  4, //"E",
		"库名":  5, //"F",
		"表名":  6, //"G",
		"表大小": 7, //"H",
		"表行数": 8, //"I",
		"SQL": 9, //  "J",
	}

	fileName, sheet1, sheet2 := "D:/User/sunkai/Desktop/sql-test/sql-test-0724.xlsx", "筛选", "结果"
	f, err := excelize.OpenFile(fileName)
	if err != nil {
		t.Fatalf("open file %s failed, %s", actionFileName, err)
	}
	defer f.Close()

	rows, err := f.GetRows(sheet1)
	if err != nil {
		t.Fatalf("get rows failed, %s", err)
	}

	if sheet, _ := f.GetSheetIndex(sheet2); sheet != -1 {
		_ = f.DeleteSheet(sheet2)
	}
	_, _ = f.NewSheet(sheet2)
	_ = f.SetCellValue(sheet2, fmt.Sprintf("A1"), "来源")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("B1"), "地址")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("C1"), "端口")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("D1"), "库名")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("E1"), "SQL")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("F1"), "指纹")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("G1"), "指纹ID")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("H1"), "操作类型")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("I1"), "动作类型")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("J1"), "关键字")
	rowNum := 2
	for i, row := range rows {
		if i == 0 {
			continue
		}

		db := row[header["库名"]]
		sql := row[header["SQL"]]
		idx := strings.Index(sql, " ")
		if idx != -1 {
			sql = regexp.MustCompile(` `).ReplaceAllString(sql, " ")
		}

		sqlFinger := comm.Finger(sql)
		//c := &sqlrisk.SQLRisk{SQLText: sql}
		c := sqlrisk.NewSqlRisk("", "", "", "", "", "", sql, nil)
		ope, act, keyword, err := c.CollectAction()
		if err != nil {
			fmt.Printf("collect action failed, %s\n", err)
			_ = f.SetCellValue(sheet2, "D"+strconv.Itoa(rowNum), sql)
			rowNum++
			continue
		}

		_ = f.SetCellValue(sheet2, "A"+strconv.Itoa(rowNum), "邮件")
		_ = f.SetCellValue(sheet2, "D"+strconv.Itoa(rowNum), db)
		_ = f.SetCellValue(sheet2, "E"+strconv.Itoa(rowNum), sql)
		_ = f.SetCellValue(sheet2, "F"+strconv.Itoa(rowNum), sqlFinger)
		_ = f.SetCellValue(sheet2, "G"+strconv.Itoa(rowNum), comm.FingerID(sqlFinger))
		_ = f.SetCellValue(sheet2, "H"+strconv.Itoa(rowNum), ope)
		_ = f.SetCellValue(sheet2, "I"+strconv.Itoa(rowNum), act)
		_ = f.SetCellValue(sheet2, "J"+strconv.Itoa(rowNum), keyword)
		rowNum++
	}

	// 从SQLReview中查询SQL
	dmlSQLs, err := QuerySQL()
	if err != nil {
		t.Fatalf("get rows failed, %s", err)
	}
	for _, dmlSQL := range dmlSQLs {
		db := dmlSQL.DB
		sql := dmlSQL.SQL
		idx := strings.Index(sql, " ")
		if idx != -1 {
			sql = regexp.MustCompile(` `).ReplaceAllString(sql, " ")
		}

		sqlFinger := comm.Finger(sql)
		c := sqlrisk.NewSqlRisk("", "", "", "", "", "", sql, nil)
		ope, act, keyword, err := c.CollectAction()
		if err != nil {
			fmt.Printf("collect action failed, %s\n", err)
			_ = f.SetCellValue(sheet2, "A"+strconv.Itoa(rowNum), "sqlreview")
			_ = f.SetCellValue(sheet2, "D"+strconv.Itoa(rowNum), sql)
			rowNum++
			continue
		}

		_ = f.SetCellValue(sheet2, "A"+strconv.Itoa(rowNum), "sqlreview")
		_ = f.SetCellValue(sheet2, "D"+strconv.Itoa(rowNum), db)
		_ = f.SetCellValue(sheet2, "E"+strconv.Itoa(rowNum), sql)
		_ = f.SetCellValue(sheet2, "F"+strconv.Itoa(rowNum), sqlFinger)
		_ = f.SetCellValue(sheet2, "G"+strconv.Itoa(rowNum), comm.FingerID(sqlFinger))
		_ = f.SetCellValue(sheet2, "H"+strconv.Itoa(rowNum), ope)
		_ = f.SetCellValue(sheet2, "I"+strconv.Itoa(rowNum), act)
		_ = f.SetCellValue(sheet2, "J"+strconv.Itoa(rowNum), keyword)
		rowNum++
	}

	// 设置excel格式
	style, _ := f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Horizontal: "center",
			Vertical:   "center",
		},
	})
	_ = f.SetCellStyle(sheet2, "A1", "J"+strconv.Itoa(rowNum), style)

	style, _ = f.NewStyle(&excelize.Style{
		Alignment: &excelize.Alignment{
			Vertical: "left",
		},
	})
	_ = f.SetCellStyle(sheet2, "D2", "H"+strconv.Itoa(rowNum), style)
	_ = f.SetCellStyle(sheet2, "E2", "H"+strconv.Itoa(rowNum), style)

	style, _ = f.NewStyle(&excelize.Style{
		Fill: excelize.Fill{
			Type:    "pattern",
			Color:   []string{"00B0F0"},
			Pattern: 1,
		},
		Alignment: &excelize.Alignment{
			Horizontal: "center",
			Vertical:   "center",
		},
	})
	_ = f.SetCellStyle(sheet2, "A1", "J1", style)

	_ = f.AutoFilter(sheet2, "A1:"+"I"+strconv.Itoa(rowNum), []excelize.AutoFilterOptions{})
	_ = f.SetPanes(sheet2,
		&excelize.Panes{
			Freeze:      true,
			Split:       false,
			XSplit:      0,
			YSplit:      1,
			TopLeftCell: "A2",
			ActivePane:  "",
		},
	)
	_ = f.SetColWidth(sheet2, "A", "I", 15)
	_ = f.SetColWidth(sheet2, "D", "D", 50)
	_ = f.SetColWidth(sheet2, "E", "E", 50)
	_ = f.SetColWidth(sheet2, "F", "F", 20)

	_ = f.Save()
	return
}

type DmlSQL struct {
	IP   string
	Port string
	DB   string
	SQL  string
}

func QuerySQL() ([]DmlSQL, error) {
	conn, err := sqlrisk.NewConnector(sqlrisk.NewDSN("192.168.198.128", "3306", "root", "123456", "yearning"))
	if err != nil {
		return nil, fmt.Errorf("new mysql connect failed, %s", err)
	}

	var sqls []DmlSQL
	res, err := conn.Query(`SELECT c.ip, c.Port, a.data_base AS 'DB', b.sql AS 'SQL' FROM core_sql_orders a, core_sql_records b, core_data_sources c WHERE a.work_id = b.work_id AND a.source = c.source AND a.time BETWEEN '2023-05-01' AND '2023-05-31';`)
	if err != nil {
		return sqls, fmt.Errorf("exec sql query failed, %s", err)
	}

	for res.Rows.Next() {
		t := DmlSQL{}
		err = res.Rows.Scan(&t.IP, &t.Port, &t.DB, &t.SQL)
		if err != nil {
			return sqls, fmt.Errorf("scan rows failed, %s", err)
		}
		sqls = append(sqls, t)
	}
	err = res.Rows.Close()
	if err != nil {
		return sqls, fmt.Errorf("close scan rows failed, %s", err)
	}
	return sqls, err
}

func TestRunSQLRisk(t *testing.T) {
	// 动作	来源	编号	地址	端口	库名	表名	表大小	表行数	SQL
	inputHeader := map[string]int{
		"来源":   0, //"A",
		"地址":   1, //"B",
		"端口":   2, //"C",
		"库名":   3, //"D",
		"SQL":  4, //"E",
		"指纹":   5, //"F",
		"指纹ID": 6, //"G",
		"操作类型": 7, //"H",
		"动作类型": 8, //"I",
		"关键字":  9, //  "J",
	}

	// 来源	地址	端口	库名	SQL	指纹	指纹ID	风险等级	特殊流程	操作类型	动作类型	关键字	表大小	表行数	影响行数	磁盘可用空间	存在主键	存在外键	否存在触发器	where条件中是否存在索引列	错误	详情
	//outputHeader := map[string]int{
	//	"来源":              0,  //"A",
	//	"地址":              1,  //"B",
	//	"端口":              2,  //"C",
	//	"库名":              3,  //"D",
	//	"SQL":             4,  //"E",
	//	"指纹":              5,  //"F",
	//	"指纹ID":            6,  //"G",
	//	"风险等级":            7,  //"H",
	//	"特殊流程":            8,  //"I",
	//	"操作类型":            9,  //  "J",
	//	"动作类型":            10, //  "K",
	//	"关键字":             11, //  "L",
	//	"表大小":             12, //  "M",
	//	"表行数":             13, //  "N",
	//	"影响行数":            14, //  "O",
	//	"磁盘可用空间":          15, //  "P",
	//	"存在主键":            16, //  "Q",
	//	"存在外键":            17, //  "R",
	//	"否存在触发器":          18, //  "S",
	//	"where条件中是否存在索引列": 19, //  "T",
	//	"错误":              20, //  "U",
	//	"详情":              21, //  "V",
	//}
	store := policy.GetStore(policy.FileStoreType, ".policy.yaml")
	err := store.Init()
	if err != nil {
		t.Fatal(err)
	}

	fileName, sheet1, sheet2 := "D:/User/sunkai/Desktop/sql-test/sql-test-0724.xlsx", "筛选", "结果"

	f, err := excelize.OpenFile(fileName)
	if err != nil {
		t.Fatalf("open file %s failed, %s", fileName, err)
	}
	defer func() {
		_ = f.Save()
		_ = f.Close()
	}()

	rows, err := f.GetRows(sheet1)
	if err != nil {
		t.Fatalf("get rows failed, %s", err)
	}

	if sheet, _ := f.GetSheetIndex(sheet2); sheet != -1 {
		_ = f.DeleteSheet(sheet2)
	}
	_, _ = f.NewSheet(sheet2)
	_ = f.SetCellValue(sheet2, fmt.Sprintf("A1"), "来源")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("B1"), "地址")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("C1"), "端口")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("D1"), "库名")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("E1"), "SQL")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("F1"), "指纹")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("G1"), "指纹ID")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("H1"), "风险等级")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("I1"), "特殊流程")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("J1"), "操作类型")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("K1"), "动作类型")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("L1"), "关键字")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("M1"), "表大小")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("N1"), "表行数")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("O1"), "影响行数")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("P1"), "磁盘可用空间")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("Q1"), "存在主键")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("R1"), "存在外键")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("S1"), "否存在触发器")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("T1"), "where条件中是否存在索引列")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("U1"), "错误")
	_ = f.SetCellValue(sheet2, fmt.Sprintf("V1"), "详情")

	rowNum := 0
	for i, row := range rows {
		fmt.Printf("row %d\n", i+1)
		rowNum++
		if i == 0 {
			continue
		}

		source := row[inputHeader["来源"]]
		finger := row[inputHeader["指纹"]]
		fingerID := row[inputHeader["指纹ID"]]
		sql := row[inputHeader["SQL"]]
		dbname := row[inputHeader["库名"]]
		_ = f.SetCellValue(sheet2, "A"+strconv.Itoa(rowNum), source)
		_ = f.SetCellValue(sheet2, "E"+strconv.Itoa(rowNum), sql)
		_ = f.SetCellValue(sheet2, "F"+strconv.Itoa(rowNum), finger)
		_ = f.SetCellValue(sheet2, "G"+strconv.Itoa(rowNum), fingerID)

		addr, port, database, user, passwd, err := GetDBAddrByDBName(dbname)
		if err != nil {
			_ = f.SetCellValue(sheet2, "U"+strconv.Itoa(rowNum), err)
			fmt.Printf("GetDBAddrByDBName err: %s\n", err)
			continue
		}
		r := sqlrisk.NewSqlRisk("", addr, port, user, passwd, database, sql, nil)
		err = r.IdentifyPreRisk()
		if err != nil {
			r.SetItemError(sqlrisk.IdentifyRisk, err)
			_ = f.SetCellValue(sheet2, "U"+strconv.Itoa(rowNum), r.Errors)
			b, _ := json.MarshalIndent(r, "", " ")
			_ = f.SetCellValue(sheet2, "V"+strconv.Itoa(rowNum), string(b))

			fmt.Printf("IdentifyPreRisk err: %s\n", err)
			continue
		}

		// 来源	地址	端口	库名	SQL	指纹	指纹ID	风险等级	特殊流程	操作类型	动作类型	关键字	表大小	表行数	影响行数	磁盘可用空间	存在主键	存在外键	否存在触发器	where条件中是否存在索引列	错误	详情
		_ = f.SetCellValue(sheet2, "A"+strconv.Itoa(rowNum), source)
		_ = f.SetCellValue(sheet2, "B"+strconv.Itoa(rowNum), addr)
		_ = f.SetCellValue(sheet2, "C"+strconv.Itoa(rowNum), port)
		_ = f.SetCellValue(sheet2, "D"+strconv.Itoa(rowNum), database)
		_ = f.SetCellValue(sheet2, "E"+strconv.Itoa(rowNum), sql)
		_ = f.SetCellValue(sheet2, "F"+strconv.Itoa(rowNum), finger)
		_ = f.SetCellValue(sheet2, "G"+strconv.Itoa(rowNum), fingerID)
		_ = f.SetCellValue(sheet2, "H"+strconv.Itoa(rowNum), r.PreResult.Level)
		_ = f.SetCellValue(sheet2, "I"+strconv.Itoa(rowNum), r.PreResult.Special)
		_ = f.SetCellValue(sheet2, "J"+strconv.Itoa(rowNum), r.GetItemValue(policy.Operate.ID))
		_ = f.SetCellValue(sheet2, "K"+strconv.Itoa(rowNum), r.GetItemValue(policy.Action.ID))
		_ = f.SetCellValue(sheet2, "L"+strconv.Itoa(rowNum), r.GetItemValue(policy.KeyWord.ID))
		_ = f.SetCellValue(sheet2, "M"+strconv.Itoa(rowNum), r.GetItemValue(policy.TabSize.ID))
		_ = f.SetCellValue(sheet2, "N"+strconv.Itoa(rowNum), r.GetItemValue(policy.TabRows.ID))
		_ = f.SetCellValue(sheet2, "O"+strconv.Itoa(rowNum), r.GetItemValue(policy.AffectRows.ID))
		_ = f.SetCellValue(sheet2, "P"+strconv.Itoa(rowNum), r.GetItemValue(policy.FreeDisk.ID))
		_ = f.SetCellValue(sheet2, "Q"+strconv.Itoa(rowNum), r.GetItemValue(policy.PrimaryKeyExist.ID))
		_ = f.SetCellValue(sheet2, "R"+strconv.Itoa(rowNum), r.GetItemValue(policy.ForeignKeyExist.ID))
		_ = f.SetCellValue(sheet2, "S"+strconv.Itoa(rowNum), r.GetItemValue(policy.TriggerExist.ID))
		_ = f.SetCellValue(sheet2, "T"+strconv.Itoa(rowNum), r.GetItemValue(policy.IndexExistInWhere.ID))
		_ = f.SetCellValue(sheet2, "U"+strconv.Itoa(rowNum), r.Errors)
		buf := bytes.NewBuffer([]byte{})
		encoder := json.NewEncoder(buf)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(r)
		if err != nil {
			panic(err)
		}
		s := buf.String()
		_ = f.SetCellValue(sheet2, "V"+strconv.Itoa(rowNum), s)
	}

	style, _ := f.NewStyle(&excelize.Style{
		Fill: excelize.Fill{
			Type:    "pattern",
			Color:   []string{"00B0F0"},
			Pattern: 1,
		},
		Alignment: &excelize.Alignment{
			Horizontal: "center",
			Vertical:   "center",
		},
	})
	_ = f.SetCellStyle(sheet2, "A1", "V1", style)

	_ = f.AutoFilter(sheet2, "A1:"+"V"+strconv.Itoa(rowNum), []excelize.AutoFilterOptions{})
	_ = f.SetPanes(sheet2, &excelize.Panes{
		Freeze:      true,
		Split:       false,
		XSplit:      0,
		YSplit:      1,
		TopLeftCell: "A2",
		ActivePane:  "",
	})
}

func TestRunOneSQLRisk(t *testing.T) {
	store := policy.GetStore(policy.FileStoreType, ".policy.yaml")
	err := store.Init()
	if err != nil {
		t.Fatal(err)
	}

	addr := "1.2.3.4"
	port := "3306"
	database := "db"
	sql := `delete from bundling_task_store_detail;`

	user := "root"
	passwd := "123456"

	//dbname := `test1`
	//sql := "CREATE TABLE auth;"
	//addr, port, database, user, passwd, err := GetDBAddrByDBName(dbname)
	//if err != nil {
	//	t.Fatalf("GetDBAddrByDBName err: %s", err)
	//}

	r := sqlrisk.NewSqlRisk("", addr, port, user, passwd, database, sql, nil)
	err = r.IdentifyPreRisk()
	if err != nil {
		t.Fatalf("IdentifyPreRisk err: %s", err)
	}

	fmt.Printf("地址: %v\n", addr)
	fmt.Printf("端口: %v\n", port)
	fmt.Printf("库名: %v\n", database)
	fmt.Printf("SQL: %v\n", sql)
	fmt.Printf("风险等级: %v\n", r.PreResult.Level)
	fmt.Printf("特殊流程: %v\n", r.PreResult.Special)
	fmt.Printf("操作类型: %v\n", r.GetItemValue(policy.Operate.ID))
	fmt.Printf("动作类型: %v\n", r.GetItemValue(policy.Action.ID))
	fmt.Printf("关键字: %v\n", r.GetItemValue(policy.KeyWord.ID))
	fmt.Printf("表大小: %v\n", r.GetItemValue(policy.TabSize.ID))
	fmt.Printf("表行数: %v\n", r.GetItemValue(policy.TabRows.ID))
	fmt.Printf("影响行数: %v\n", r.GetItemValue(policy.AffectRows.ID))
	fmt.Printf("磁盘可用空间: %v\n", r.GetItemValue(policy.FreeDisk.ID))
	fmt.Printf("存在主键: %v\n", r.GetItemValue(policy.PrimaryKeyExist.ID))
	fmt.Printf("存在外键: %v\n", r.GetItemValue(policy.ForeignKeyExist.ID))
	fmt.Printf("否存在触发器: %v\n", r.GetItemValue(policy.TriggerExist.ID))
	fmt.Printf("where条件中是否存在索引列: %v\n", r.GetItemValue(policy.IndexExistInWhere.ID))

	buf := bytes.NewBuffer([]byte{})
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(r)
	if err != nil {
		panic(err)
	}
	s := buf.String()
	fmt.Printf("详情: %s\n", s)
}
