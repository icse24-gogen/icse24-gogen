package metainfo

type CallsiteMeta struct {
	Name    string
	SrcPath string
	Args    []*ArgInCall
}

type ArgInCall struct {
	Name     string
	Type     FuzzType
	ArgIndex int
	Fpath    string
	VarLine  int
	VarCol   int
	CallLine int
	CallCol  int
}
