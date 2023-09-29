#! /usr/bin/env python3

from pickle import NONE
import sys
import os
import glob
import subprocess
import json

from diffblocks import getCoverBlock



BLOCKS=NONE

def parseMeta(fuzzzip):
    global BLOCKS
    assert(fuzzzip != "")
    subprocess.Popen("unzip {}".format(fuzzzip), shell=True).communicate()
    with open("metadata", 'r') as f:
        metadata = json.load(f)
        BLOCKS = metadata["Blocks"]

def getCoverFromBitmap(bitmap):
    coveredID = set()
    with open(bitmap, 'rb') as f:
        bbs = f.read()
    for idx in range(len(bbs)):
        if bbs[idx] > 0:
            coveredID.add(idx)
    return coveredID

def getCodeLocfromBBid(BBIDs):
    global BLOCKS
    blockMap = {} # int: [str]
    coveredCode = []
    for b in BLOCKS:
        # what if hash conflict
        if b["ID"] not in blockMap:
            blockMap[b["ID"]] = []
        blockMap[b["ID"]].append("{}:{}".format(b["File"], b["StartLine"]))
    for idx in BBIDs:
        coveredCode.append(blockMap[idx])
    return coveredCode

if __name__ == "__main__":
    bitmap1, bitmap2 = sys.argv[1:]
    fuzzzip = ""
    for zip in glob.glob("*.zip"):
        fuzzzip = zip
    
    parseMeta(fuzzzip)
    cover1 = getCoverFromBitmap(bitmap1)
    cover2 = getCoverFromBitmap(bitmap2)

    cover1Unique = cover1 - cover2
    cover2Unique = cover2 - cover1

    cover1Code = getCodeLocfromBBid(cover1Unique)
    cover2Code = getCodeLocfromBBid(cover2Unique)

    

    if True:  # maybe some flag to control output 
        print("-------------------------------         cover1Code unique blocks ({})          ----------------------------------".format(len(cover1)))
        for codeLoc in cover1Code:
            print(codeLoc)
    if True:
        print("-------------------------------         cover2Code unique blocks ({})          ----------------------------------".format(len(cover2)))
        for codeLoc in cover2Code:
            print(codeLoc)

    


