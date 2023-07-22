package policy

type PolicyReaderWriter interface {
	Init() error
	PolicyWriter([]Policy) error
	PolicyReader() ([]Policy, error)
}
