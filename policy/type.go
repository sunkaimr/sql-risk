package policy

type RuleType string

const (
	BasicRule RuleType = "BASIC"
	AggRule   RuleType = "AGG"
)

type RuleValueType string

const (
	RuleValueTypeOperate RuleValueType = "OperateType"
	RuleValueTypeAction  RuleValueType = "ActionType"
	RuleValueTypeKeyWord RuleValueType = "KeyWordType"
	RuleValueTypeInt     RuleValueType = "INT"
	RuleValueTypeBool    RuleValueType = "BOOL"
	RuleValueTypeBasic   RuleValueType = "BASIC"
)

type OperatorType string

const (
	RuleOperatorEQ      OperatorType = "=="
	RuleOperatorNE      OperatorType = "!="
	RuleOperatorLT      OperatorType = "<"
	RuleOperatorLE      OperatorType = "<="
	RuleOperatorGT      OperatorType = ">"
	RuleOperatorGE      OperatorType = ">="
	RuleOperatorBETWEEN OperatorType = "between"
	RuleOperatorALL     OperatorType = "all"
	RuleOperatorANY     OperatorType = "any"
	RuleOperatorHIG     OperatorType = "highest"
	RuleOperatorLOW     OperatorType = "lowest"
)

type Item struct {
	Name string
	ID   string
}

type OperateStruct struct {
	Item
	V OperateValues
}

type OperateType string

type OperateValues struct {
	Unknown OperateType
	DQL     OperateType
	DDL     OperateType
	DML     OperateType
	DCL     OperateType
}

var Operate = OperateStruct{
	Item: Item{
		Name: "操作类型",
		ID:   "Operate",
	},

	V: OperateValues{
		Unknown: "UNKNOWN",
		DQL:     "DQL",
		DDL:     "DDL",
		DML:     "DML",
		DCL:     "DCL",
	},
}

type ActionStruct struct {
	Item
	V ActionValues
}

type ActionType string

type ActionValues struct {
	Unknown  ActionType
	Select   ActionType
	Drop     ActionType
	Truncate ActionType
	Create   ActionType
	Alter    ActionType
	Insert   ActionType
	Replace  ActionType
	Delete   ActionType
	Update   ActionType
}

var Action = ActionStruct{
	Item: Item{
		Name: "动作类型",
		ID:   "Action",
	},
	V: ActionValues{
		Unknown:  "unknown",
		Select:   "select",
		Drop:     "drop",
		Truncate: "truncate",
		Create:   "create",
		Alter:    "alter",
		Insert:   "insert",
		Replace:  "replace",
		Delete:   "delete",
		Update:   "update",
	},
}

type KeyWordStruct struct {
	Item
	V KeyWordValues
}
type KeyWordType string

type KeyWordValues struct {
	Unknown         KeyWordType
	Select          KeyWordType
	DropTab         KeyWordType
	DropDB          KeyWordType
	DropIdx         KeyWordType
	DropProcedure   KeyWordType
	DropFun         KeyWordType // 暂时不支持
	DropView        KeyWordType
	DropTrig        KeyWordType // 暂时不支持
	TruncateTab     KeyWordType
	CreateTab       KeyWordType
	CreateTabAs     KeyWordType
	CreateTmpTab    KeyWordType
	CreateIdx       KeyWordType
	CreateUniIdx    KeyWordType
	CreateProcedure KeyWordType
	CreateFunc      KeyWordType
	CreateView      KeyWordType
	CreateTrig      KeyWordType
	AlertAddCol     KeyWordType
	AlertDropCol    KeyWordType
	AlertModCol     KeyWordType
	AlertRenameCol  KeyWordType
	AlertChgCol     KeyWordType
	AlertAddPriKey  KeyWordType
	AlertDropPriKey KeyWordType
	AlertAddIdx     KeyWordType
	AlertAddUni     KeyWordType
	AlertAddUniIdx  KeyWordType
	AlertDropIdx    KeyWordType
	Alter           KeyWordType
	InsertSelect    KeyWordType
	Insert          KeyWordType
	Replace         KeyWordType
	DeleteWhere     KeyWordType
	Delete          KeyWordType
	UpdateWhere     KeyWordType
	Update          KeyWordType
}

var KeyWord = KeyWordStruct{
	Item: Item{
		Name: "关键字",
		ID:   "KeyWord",
	},

	V: KeyWordValues{
		Unknown:         "unknown",
		Select:          "select",
		DropTab:         "drop table",
		DropDB:          "drop database",
		DropIdx:         "drop index",
		DropProcedure:   "drop procedure",
		DropFun:         "drop function", // 暂时不支持
		DropView:        "drop view",
		DropTrig:        "drop trigger", // 暂时不支持
		TruncateTab:     "truncate table",
		CreateTab:       "create table",
		CreateTabAs:     "create table as",
		CreateTmpTab:    "create temporary table",
		CreateIdx:       "create index",
		CreateUniIdx:    "create unique index",
		CreateProcedure: "create procedure",
		CreateFunc:      "create function",
		CreateView:      "create view",
		CreateTrig:      "create trigger",
		AlertAddCol:     "alter add column",
		AlertDropCol:    "alter drop column",
		AlertModCol:     "alter modify column",
		AlertRenameCol:  "alter rename column",
		AlertChgCol:     "alter change column",
		AlertAddPriKey:  "alter add primary key",
		AlertDropPriKey: "alter drop primary key",
		AlertAddIdx:     "alter add index",
		AlertAddUni:     "alter add unique",
		AlertAddUniIdx:  "alter add unique index",
		AlertDropIdx:    "alter drop index",
		Alter:           "alter",
		InsertSelect:    "insert into select",
		Insert:          "insert",
		Replace:         "replace into",
		DeleteWhere:     "delete from where",
		Delete:          "delete from",
		UpdateWhere:     "update set where",
		Update:          "update set",
	},
}

var TabExist = Item{
	Name: "表存在",
	ID:   "TableExist",
}

var TabSize = Item{
	Name: "表大小",
	ID:   "TableSize",
}

var TabRows = Item{
	Name: "表数据量",
	ID:   "TableRows",
}

var AffectRows = Item{
	Name: "影响行数",
	ID:   "AffectRows",
}

var FreeDisk = Item{
	Name: "磁盘可用空间",
	ID:   "FreeDisk",
}

var DiskSufficient = Item{
	Name: "磁盘充足",
	ID:   "DiskSufficient",
}

var PrimaryKeyExist = Item{
	Name: "存在主键",
	ID:   "PrimaryKeyExist",
}

var ForeignKeyExist = Item{
	Name: "存在外键",
	ID:   "ForeignKeyExist",
}

var TriggerExist = Item{
	Name: "存在触发器",
	ID:   "TriggerExist",
}

var IndexExistInWhere = Item{
	Name: "where条件中存在索引列",
	ID:   "IndexExistInWhere",
}

var CpuUsage = Item{
	Name: "CPU使用率",
	ID:   "CpuUsage",
}

var BigTransaction = Item{
	Name: "大事务",
	ID:   "BigTransaction",
}

var RuleMatch = Item{
	Name: "匹配规则名称",
	ID:   "RuleMatch",
}

var RulePriority = Item{
	Name: "匹配规则优先级",
	ID:   "RulePriority",
}

var RuleLevel = Item{
	Name: "匹配规则风险等级",
	ID:   "RuleLevel",
}
