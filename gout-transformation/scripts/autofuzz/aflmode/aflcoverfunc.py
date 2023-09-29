#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import sys 
import json
import aflparsebbmap


def GetCoverFuncs(bitmap):
    covFunc = set()
    with open('./metadata', 'r') as f:
        blocks = json.load(f)['Blocks']
    coveredBB = aflparsebbmap.parse_covered_by_bitmap(bitmap)
    for bbidx in coveredBB:
        block = blocks[bbidx-1]
        covFunc.add("{}:{}".format(block['Func'], block['File']))
    return covFunc


if __name__ == "__main__":
    fuzzname = sys.argv[1]
    bitmap = "./Testoutput/bb_bitmap"
    coveredFuncs = GetCoverFuncs(bitmap)

    fuzzbitmap = "./Fuzzoutput/bb_bitmap"
    fuzzCoverdFunc = GetCoverFuncs(fuzzbitmap)
    print(fuzzname, len(coveredFuncs) , len(fuzzCoverdFunc))