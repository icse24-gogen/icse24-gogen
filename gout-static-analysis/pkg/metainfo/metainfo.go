package metainfo

import (
	"fmt"
	"strconv"
)

type FuzzType int32
type CalleeType int32
type UseType int32
type AType int32
type APICallType int32 //binary form

const (
	EmptyCalleeType       CalleeType = 0
	StdCallee             CalleeType = 1 << 0
	ThisPackageCallee     CalleeType = 1 << 1
	OtherPackageCallee    CalleeType = 1 << 2
	MayThirdPackageCallee CalleeType = 1 << 3
	TestingCallee         CalleeType = 1 << 4
	CalleeInTheSameFile   CalleeType = 1 << 5 //In the same file of TestCase(Not used now)
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

	FuzzableBool       FuzzType = 14
	FuzzableUintptr    FuzzType = 15
	FuzzableRune       FuzzType = 16
	FuzzableComplex64  FuzzType = 17
	FuzzableComplex128 FuzzType = 18
)

const (
	BaseAlias                   AType = 0
	StoreToSameGlobalVar        AType = 1
	StoreToSameStructField      AType = 2
	StoreToSameGlobalMap        AType = 3
	RelateToSameGlobalStructVar AType = 4
)

const (
	DefaultAPICallType APICallType = 0
	InOriginalTestCase APICallType = 1 << 0
	InTestWrapper      APICallType = 1 << 1
	InTableDriven      APICallType = 1 << 2
	InTestingAPIArg    APICallType = 1 << 3
)

type AliasInfo struct {
	AliasType    AType `yaml:"AliasType"`
	IDOfAllConst int   `yaml:"IDOfAllConst"` //index in TestCaseMetaInfo.AllConstArray[]
}

/*
	if isImmediateVariable == true
        ArgIndex presents the Const's parameter index of the Callee function
        SourceLine = 0
        SourceColumn = 0
        FuncInternalOffset = 0
*/
type VariableConstSourceInfo struct {
	VariableSrcPath    string   `yaml:"VariableSrcPath"`
	SourceLine         int      `yaml:"SourceLine"`
	SourceColumn       int      `yaml:"SourceColumn"`
	FuncInternalOffset int      `yaml:"FuncInternalOffset"`
	ConstValue         string   `yaml:"ConstValue"`
	ConstType          FuzzType `yaml:"ConstType"`
	ConstUseType       UseType  `yaml:"ConstUseType"`

	InWhichFunc string `yaml:"InWhichFunc"`
	IsNewFunc   bool   `yaml:"IsNewFunc"`

	IsImmediateVariable bool `yaml:"IsImmediateVariable"`
	ArgIndex            int  `yaml:"ArgIndex"`
	CallLine            int  `yaml:"CallLine"`
	CallColum           int  `yaml:"CallColum"`
	CallPos             int  `yaml:"CallPos"`

	MayAlias     []AliasInfo `yaml:"MayAlias"`
	MustAlias    []AliasInfo `yaml:"MustAlias"`
	IDOfAllConst int         `yaml:"IDOfAllConst"` //index in TestCaseMetaInfo.AllConstArray[]
}

type VariableGlobalSourceInfo struct {
	GlobalSrcPath string `yaml:"GlobalSrcPath"`
	SourceLine    int    `yaml:"SourceLine"`
	SourceColumn  int    `yaml:"SourceColumn"`
	GlobalName    string `yaml:"GlobalName"`
	GlobalType    string `yaml:"GlobalType"` //Mostly struct OR Array? So use "string"
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
	IsSelfOfStruct          bool                       `yaml:"IsSelfOfStruct"`
	NeedsIntercepted        bool                       `yaml:"NeedsIntercepted"`
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
	APIInfoIDOfCallee       int                        `yaml:"APIInfoIDOfCallee"`
}

type TableDrivenInfo struct {
	TableVarName       string `yaml:"TableVarName"`
	TableLength        int    `yaml:"TableLength"`        //[TableLength]struct{...}
	TableItemElemCount int    `yaml:"TableItemElemCount"` //Table[x].elem1, Table[x].elem2 ... Table[x].TableItemElemCount

	IsFromGlobalVarTable bool                     `yaml:"IsFromGlobalVarTable"`
	GlobalTable          VariableGlobalSourceInfo `yaml:"GlobalTable"`      //if IsFromGlobalVarTable==true
	LocalTableLine       int                      `yaml:"LocalTableLine"`   //if IsFromGlobalVarTable==false
	LocalTableColumn     int                      `yaml:"LocalTableColumn"` //if IsFromGlobalVarTable==false
}

type APIInfo struct {
	APICallLine     int             `yaml:"APICallLine"`
	APICallColum    int             `yaml:"APICallColum"`
	APICallLocation APICallType     `yaml:"APICallLocation"`
	TableInfo       TableDrivenInfo `yaml:"TableInfo"`
}

type TestCaseMetaInfo struct {
	Name          string                    `yaml:"Name"`
	SrcPath       string                    `yaml:"SrcPath"`
	VariableList  []VariableMetaInfo        `yaml:"VariableList"`
	APISequence   []APIInfo                 `yaml:"APISequence"`
	AllConstArray []VariableConstSourceInfo `yaml:"AllConstArray"`
}

func NewVariableMetaInfo() *VariableMetaInfo {
	return &VariableMetaInfo{
		IsImmediateVariable: false,
		ArgIndex:            -1,
		VarName:             "",
		VarType:             -1,

		VarLine: -1, VarColum: -1, VarPos: -1,
		VarScore: -1,
		CallLine: -1, CallColum: -1, CallPos: -1,
		Callee: "",
	}
}
func (VMI *VariableMetaInfo) String() string {
	fmtstring := fmt.Sprintf("IsImmediateVariable:%s\n", strconv.FormatBool(VMI.IsImmediateVariable))
	fmtstring += fmt.Sprintf("ArgIndex:%d\n", VMI.ArgIndex)
	fmtstring += fmt.Sprintf("VarName:%s\n", VMI.VarName)

	switch VMI.VarType {
	case FuzzableString:
		fmtstring += fmt.Sprintf("VarType:FuzzableString\n")
	case FuzzableBytes:
		fmtstring += fmt.Sprintf("VarType:FuzzableBytes\n")
	}

	fmtstring += fmt.Sprintf("VarLine:%d VarColum:%d VarPos:%d\n", VMI.VarLine, VMI.VarColum, VMI.VarPos)
	fmtstring += fmt.Sprintf("VarScore:%d\n", VMI.VarScore)
	fmtstring += fmt.Sprintf("CallLine:%d CallColum:%d CallPos:%d\n", VMI.CallLine, VMI.CallColum, VMI.CallPos)
	fmtstring += fmt.Sprintf("Callee:%s\n", VMI.Callee)
	return fmtstring

}
