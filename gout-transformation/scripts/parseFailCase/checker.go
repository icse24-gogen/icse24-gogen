package main

func yamlHasArg(metainfo *TestCaseMetaInfo) bool {
	for _, vararg := range metainfo.VariableList {
		if vararg.IsImmediateVariable {
			//immediate variable
			return true
		} else {
			//variable
			if len(vararg.VarRelatedConstSources) > 0 || len(vararg.VarRelatedGlobalSources) > 0 {
				return true
			}
		}
	}
	return false
}

func parseFailLog(faillog []byte) FailType {

	return noFuzzVar
}
