package main

//types of failcase
type FailType string

const (
	noFuzzVar       FailType = "noFuzzVar"
	syntaxErr       FailType = "syntaxErr"
	unsupportedType FailType = "unsupportedType"
	encodingErr     FailType = "encodingErr"
	patternErr      FailType = "patternErr"
	toolBug         FailType = "toolBug"
)

//types for metainfo
type FuzzType int32
type CalleeType int32
type UseType int32

const (
	StdCallee             CalleeType = 0
	ThisPackageCallee     CalleeType = 1
	OtherPackageCallee    CalleeType = 2
	MayThirdPackageCallee CalleeType = 3
	TestingCallee         CalleeType = 4
	CalleeInTheSameFile   CalleeType = 5 //In the same file of TestCase(Not used now)
)

const (
	DefaultUnKnown   UseType = 0
	InStore          UseType = 1
	InConvert        UseType = 2
	InIndexAddr      UseType = 3
	InSlice          UseType = 4
	InBinaryOperator UseType = 5
	InMap            UseType = 6
	InLoopComparison UseType = 7
	InCall           UseType = 8
)

const (
	UnKnown        FuzzType = -1
	FuzzableString FuzzType = 0
	FuzzableBytes  FuzzType = 1

	FuzzableInt8  FuzzType = 2
	FuzzableInt16 FuzzType = 3
	FuzzableInt32 FuzzType = 4
	FuzzableInt64 FuzzType = 5

	FuzzableUint8  FuzzType = 6
	FuzzableUint16 FuzzType = 7
	FuzzableUint32 FuzzType = 8
	FuzzableUint64 FuzzType = 9

	FuzzableInt  FuzzType = 10
	FuzzableUint FuzzType = 11

	FuzzableFloat32 FuzzType = 12
	FuzzableFloat64 FuzzType = 13
)

/*
   if isImmediateVariable == true
       ArgIndex presents the Const's parameter index of the Callee function
       SourceLine = 0
       SourceColumn = 0
       FuncInternalOffset = 0
*/
type VariableConstSourceInfo struct {
	VariableSrcPath    string
	SourceLine         int
	SourceColumn       int
	FuncInternalOffset int
	ConstValue         string
	ConstType          FuzzType
	ConstUseType       UseType

	InWhichFunc string
	IsNewFunc   bool

	IsImmediateVariable bool
	ArgIndex            int
	CallLine            int
	CallColum           int
	CallPos             int
}

type VariableGlobalSourceInfo struct {
	GlobalSrcPath string
	SourceLine    int
	SourceColumn  int
	GlobalName    string
	GlobalType    string //Mostly struct OR Array? So use "string"
}

/*
   if isImmediateVariable == true
       VarName = ""
       ArgIndex presents WHICH parameter of the Callee function (Exclude "self")
       VarLine: -1
       VarColum: -1
       VarPos: 0
       VarRelatedConstSources: []
*/
type VariableMetaInfo struct {
	IsImmediateVariable     bool                       `yaml:"IsImmediateVariable"`
	ArgIndex                int                        `yaml:"ArgIndex"`
	VarName                 string                     `yaml:"VarName"`
	VarType                 FuzzType                   `yaml:"VarType"`
	VarLine                 int                        `yaml:"VarLine"`
	VarColum                int                        `yaml:"VarColum"`
	VarPos                  int                        `yaml:"VarPos"`
	VarScore                int                        `yaml:"VarScore"` //taint score
	VarRelatedConstSources  []VariableConstSourceInfo  `yaml:"VarRelatedConstSources"`
	VarRelatedGlobalSources []VariableGlobalSourceInfo `yaml:"VarRelatedGlobalSources"`
	CallLine                int                        `yaml:"CallLine"`
	CallColum               int                        `yaml:"CallColum"`
	CallPos                 int                        `yaml:"CallPos"`
	Callee                  string                     `yaml:"Callee"`
	CalleeLoc               CalleeType                 `yaml:"CalleeLoc"`
}

type TestCaseMetaInfo struct {
	Name         string             `yaml:"Name"`
	SrcPath      string             `yaml:"SrcPath"`
	VariableList []VariableMetaInfo `yaml:"VariableList"`
}

///////////////////////// go-fuzz metadata types ///////////////////////////////////
type CoverBlock struct {
	ID        int
	File      string
	StartLine int
	StartCol  int
	EndLine   int
	EndCol    int
	NumStmt   int
}

type Literal struct {
	Val   string
	IsStr bool
}

type MetaData struct {
	Literals    []Literal
	Blocks      []CoverBlock
	Sonar       []CoverBlock
	Funcs       []string // fuzz function names; must have length > 0
	DefaultFunc string   // default function to fuzz
}

///////////////////////staticcheck types//////////////////////
type Location struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}
type Related struct {
	Location Location `json:"location"`
	End      Location `json:"end"`
	Message  string   `json:"message"`
}

type JsonResult struct {
	Code     string    `json:"code"`
	Severity string    `json:"severity,omitempty"`
	Location Location  `json:"location"`
	End      Location  `json:"end"`
	Message  string    `json:"message"`
	Related  []Related `json:"related,omitempty"`
}
