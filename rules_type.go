package sqlrisk

//
//const (
//	OPE_NAME = "操作类型"
//	OPERATE  = "Operate"
//)
//
//type OperateType string
//
//// OperateType
//const (
//	Unknown OperateType = "UNKNOWN"
//	DQL     OperateType = "DQL"
//	DDL     OperateType = "DDL"
//	DML     OperateType = "DML"
//	DCL     OperateType = "DCL"
//)
//
///* 动作类型 */
//type ActionType string
//
//const (
//	ACT_NAME = "动作类型"
//	ACTION   = "Action"
//)
//
//// ActionType
//const (
//	Unknown  ActionType = "unknown"
//	Select   ActionType = "select"
//	Drop     ActionType = "drop"
//	Truncate ActionType = "truncate"
//	Create   ActionType = "create"
//	Alter    ActionType = "alter"
//	Insert   ActionType = "insert"
//	Replace  ActionType = "replace"
//	Delete   ActionType = "delete"
//	Update   ActionType = "update"
//)
//
///* 相关操作的关键字 */
//type KeyWordType string
//
//const (
//	KEY_WORD_NAME = "关键字"
//	KEY_WORD      = "KeyWord"
//)
//
//const (
//	Unknown KeyWordType = "unknown"
//	// select
//	Select KeyWordType = "select"
//	// drop
//	DropTab   KeyWordType = "drop table"
//	DropDB    KeyWordType = "drop database"
//	DropIdx   KeyWordType = "drop index"
//	DropProcedure KeyWordType = "drop procedure"
//	DropFun   KeyWordType = "drop function" // 暂时不支持
//	DropView  KeyWordType = "drop view"
//	DropTrig  KeyWordType = "drop trigger" // 暂时不支持
//	// truncate table
//	TruncateTab KeyWordType = "truncate table"
//	// create
//	CreateTab     KeyWordType = "create table"
//	CreateTabAs  KeyWordType = "create table as"
//	CreateTmpTab  KeyWordType = "create temporary table"
//	CreateIdx     KeyWordType = "create index"
//	CreateUniIdx KeyWordType = "create unique index"
//	CreateProcedure   KeyWordType = "create procedure"
//	CreateFunc    KeyWordType = "create function"
//	CreateView    KeyWordType = "create view"
//	CreateTrig    KeyWordType = "create trigger"
//	// alert
//	AlertAddCol      KeyWordType = "add column"
//	AlertDropCol     KeyWordType = "drop column"
//	AlertModCol      KeyWordType = "modify column"
//	AlertRenameCol   KeyWordType = "rename column"
//	AlertChgCol      KeyWordType = "change column"
//	AlertAddPriKey  KeyWordType = "add primary key"
//	AlertDropPriKey KeyWordType = "drop primary key"
//	AlertAddIdx      KeyWordType = "add index"
//	AlertAddUni      KeyWordType = "add unique"
//	AlertAddUniIdx  KeyWordType = "add unique index"
//	AlertDropIdx     KeyWordType = "drop index"
//	Alter              KeyWordType = "alert"
//	// insert
//	InsertSelect KeyWordType = "insert into select"
//	Insert        KeyWordType = "insert"
//	// replace
//	Replace KeyWordType = "replace into"
//	// delete
//	DeleteWhere KeyWordType = "delete from where"
//	Delete       KeyWordType = "delete from"
//	// update
//	UpdateWhere KeyWordType = "update set where"
//	Update       KeyWordType = "update set"
//)
//
//const (
//	// 运行时风险
//	TAB_EXIST_NAME = "表存在"
//	TAB_EXIST      = "TableExist"
//
//	TAB_SIZE_NAME = "表大小"
//	TAB_SIZE      = "TableSize"
//
//	TAB_ROWS_NAME = "表数据量"
//	TAB_ROWS      = "TableRows"
//
//	AFFECT_ROWS_NAME = "影响行数"
//	AFFECT_ROWS      = "AffectRows"
//
//	FREE_DISK_NAME = "磁盘可用空间(MB)"
//	FREE_DISK      = "FreeDisk"
//
//	PRIMARY_KEY_EXIST_NAME = "存在主键"
//	PRIMARY_KEY_EXIST      = "PrimaryKeyExist"
//
//	FOREIGN_KEY_EXIST_NAME = "存在外键"
//	FOREIGN_KEY_EXIST      = "ForeignKeyExist"
//
//	TRIGGER_EXIST_NAME = "存在触发器"
//	TRIGGER_EXIST      = "TriggerExist"
//
//	INDEX_EXIST_IN_WHERE_NAME = "where条件中存在索引列"
//	INDEX_EXIST_IN_WHERE      = "IndexExistInWhere"
//
//	CPU_USAGE_NAME = "CPU使用率"
//	CPU_USAGE      = "CpuUsage"
//
//	TRANSACTION_NAME = "存在运行的事务"
//	TRANSACTION      = "BigTransaction"
//)
