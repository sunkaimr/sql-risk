package policy

import "gorm.io/gorm"

const (
	FileStoreType  = "file"
	MysqlStoreType = "mysql"
)

type PolicyReaderWriter interface {
	Init() error
	PolicyWriter([]Policy) error
	PolicyReader() ([]Policy, error)
}

func GetStore(name string, opt any) PolicyReaderWriter {
	switch name {
	case "", FileStoreType:
		file, ok := opt.(string)
		if !ok {
			panic("file type for store need opt is string")
		}
		return &FileStore{FilePath: file}
	case MysqlStoreType:
		db, ok := opt.(*gorm.DB)
		if !ok {
			panic("mysql type for store need opt is *gorm.DB")
		}
		return &MysqlStore{db}
	default:
		panic("unsupported store type:" + name)
	}
	return nil
}
