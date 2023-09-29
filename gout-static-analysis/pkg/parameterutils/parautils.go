package parameterutils

import (
	"fmt"
	"xyz.asd.qwe/gout-static-analysis/pkg/metainfo"
	"strconv"
	"strings"
)

type VariableTag struct {
	VType     string
	VarName   string
	VarLine   int
	VarColumn int
	VarPos    int
}

type ParamTag struct {
	VariableTag
	CallLine            int
	CallColumn          int
	CallPos             int
	ArgIndex            int
	IsSelf              bool
	IsPtr               bool
	IsImmediate         bool
	NeedsIntercepted    bool
	MaybeFilenameOrPath bool
	MaybeRegex          bool
	MaybeIpAddress      bool
}

type ParamInfo struct {
	Score            int
	IfFlowToOracle   bool
	Name             string
	Tag              *ParamTag //
	ConstSourceInfo  []metainfo.VariableConstSourceInfo
	GlobalSourceInfo []metainfo.VariableGlobalSourceInfo
}

var supportTypeMap = map[string]metainfo.FuzzType{
	"string": metainfo.FuzzableString, "[]byte": metainfo.FuzzableBytes,
	"int": metainfo.FuzzableInt, "uint": metainfo.FuzzableUint,
	"int8": metainfo.FuzzableInt8, "int16": metainfo.FuzzableInt16,
	"int32": metainfo.FuzzableInt32, "int64": metainfo.FuzzableInt64,
	"uint8": metainfo.FuzzableUint8, "uint16": metainfo.FuzzableUint16,
	"uint32": metainfo.FuzzableUint32, "uint64": metainfo.FuzzableUint64,
	"float32": metainfo.FuzzableFloat32, "float64": metainfo.FuzzableFloat64,
	"bool": metainfo.FuzzableBool, "uintptr": metainfo.FuzzableUintptr,
	"rune": metainfo.FuzzableRune, "complex64": metainfo.FuzzableComplex64,
	"complex128": metainfo.FuzzableComplex128,
}

func isSupportedType(variable *ParamInfo) bool {
	_, ok := supportTypeMap[variable.Tag.VType]
	return ok
}

func SwitchType(t string) metainfo.FuzzType {
	typeNum, ok := supportTypeMap[t]
	if ok {
		return typeNum
	}
	return metainfo.UnKnown
}
func ParseTagToVariableMetaInfo(variable *ParamInfo) *metainfo.VariableMetaInfo {
	if variable.Tag.MaybeFilenameOrPath || variable.Tag.MaybeRegex || variable.Tag.MaybeIpAddress { //Don't need to fuzz
		return nil
	} else { //} if isSupportedType(variable) {

		variableMetaInfo := metainfo.NewVariableMetaInfo()
		variableMetaInfo.IsSelfOfStruct = variable.Tag.IsSelf
		variableMetaInfo.NeedsIntercepted = variable.Tag.NeedsIntercepted
		if variable.Tag.IsImmediate == true || variable.Tag.NeedsIntercepted == true { //Immediate
			variableMetaInfo.IsImmediateVariable = true
			variableMetaInfo.VarName = ""
		} else {
			variableMetaInfo.IsImmediateVariable = false
			variableMetaInfo.VarName = variable.Tag.VarName
		}

		paraType := SwitchType(variable.Tag.VType)
		/*if paraType == metainfo.UnKnown {
			panic("Variable type error!")
		}*/
		variableMetaInfo.VarType = paraType
		variableMetaInfo.ArgIndex = variable.Tag.ArgIndex

		variableMetaInfo.VarLine = variable.Tag.VarLine
		variableMetaInfo.VarColum = variable.Tag.VarColumn
		variableMetaInfo.VarScore = variable.Score

		variableMetaInfo.CallLine = variable.Tag.CallLine
		variableMetaInfo.CallColum = variable.Tag.CallColumn
		variableMetaInfo.CallPos = variable.Tag.CallPos

		variableMetaInfo.VarPos = variable.Tag.VarPos
		return variableMetaInfo
	}
	return nil //not supported
}

func ShowTag(info *ParamInfo) string {
	if info.Tag.IsSelf {
		return fmt.Sprintf("<type:%s><self>", info.Tag.VType)
	} else if info.Tag.IsPtr {
		return fmt.Sprintf("<type:%s><ptr>", info.Tag.VType)
	} else {
		return fmt.Sprintf("<type:%s><immediate:%s|index:%d><mayfile:%s><varline:%d><varname:%s>", info.Tag.VType,
			strconv.FormatBool(info.Tag.IsImmediate),
			info.Tag.ArgIndex,
			strconv.FormatBool(info.Tag.MaybeFilenameOrPath),
			info.Tag.VarLine,
			strings.Replace(info.Tag.VarName, ",", " / ", -1),
		)
	}
}
