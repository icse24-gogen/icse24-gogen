#! /usr/bin/env python3

import subprocess
import json
import glob
import os
import shutil
import sys



BLOCKS = {}

# parser = argparse.ArgumentParser()
# parser.add_argument("proj")
# parser.add_argument("dir", default="purelib")
# parser.add_argument("bin")


def getTestCovBBS(fuzzZipPath):
    # returns a set of block-id
    global BLOCKS

    testCovBBs = set()
    fuzzZipName = os.path.basename(fuzzZipPath)
    cwd = os.getcwd()
    os.chdir(os.path.dirname(fuzzZipPath))
    testCovDirname = "testCov"
    if os.path.exists(testCovDirname):
        shutil.rmtree(testCovDirname)
    os.mkdir(testCovDirname)
    shutil.copy(fuzzZipName, testCovDirname)
    os.chdir(testCovDirname)
    subprocess.Popen("unzip {}".format(fuzzZipName), shell=True).communicate()
    with open("metadata", 'r') as f:
        metadata = json.load(f)
    BLOCKS = metadata["Blocks"]

    cmd = "go-fuzz -dryrun=true -procs=1 -bin={}".format(fuzzZipName)
    subprocess.Popen(cmd, shell=True).communicate()
    try:
        with open("maxCover.log", 'rb') as f:
            cover = f.read()
    except:
        print("[-] No maxCover.log file found")
        exit()
        pass
    
    for i in range (len(cover)):
        if cover[i] > 0:
            testCovBBs.add(i)
    os.chdir((".."))
    shutil.rmtree(testCovDirname)
    os.chdir(cwd)
    return testCovBBs



def getFuzzCovBBs(fuzzZip):
    # fuzzZip = "fiber/middleware/limiter/FuzzTest_Limiter_Headers.zip"
    # it returns a set of block-id
    cwd = os.getcwd()
    fuzzCovBBs = set()
    fuzzname = fuzzZip.split("/")[-1][:-4]
    resDir = "result"+fuzzname
    os.chdir(os.path.join(os.path.dirname(fuzzZip), resDir))
    with open("./maxCover.log", 'rb') as f:
        cover = f.read()
    for i in range(len(cover)):
        if cover[i] > 0:
            fuzzCovBBs.add(i)
    os.chdir(cwd)
    return fuzzCovBBs


def proBlocks():
    global BLOCKS
    blockMap = {} # int: [str]
    for b in BLOCKS:
        # what if hash conflict
        if b["ID"] not in blockMap:
            blockMap[b["ID"]] = []
        blockMap[b["ID"]].append("{}:{}".format(b["File"], b["StartLine"]))
    
    return blockMap


# getDiffBlock parse the blocks covered in fuzz between test
# it receives the path of fuzzZip, like "fiber/middleware/csrf/xxx.zip"
# and it returns a tuple of list ([test bbs], [fuzz bbs]), in which a bb in list is a location of source code
def getCoverBlock(fuzzZip):
    global BLOCKS

    
    testblocks = set()
    fuzzblocks = set()

    testblocks = getTestCovBBS(fuzzZip)
    fuzzblocks = getFuzzCovBBs(fuzzZip)

    return testblocks, fuzzblocks



if __name__ == "__main__":
    cwd = os.getcwd()
    args = sys.argv[1:]
    print(args)
    dir, proj, bin = args
    
    workDir = os.path.join(os.getenv("GOPATH"), "src", dir)
    os.chdir(workDir)
    proj = proj
    bin = bin
    fuzzZip = "{}/{}".format(proj, bin)

    testblocks, fuzzblocks = getCoverBlock(fuzzZip)

    testUniBbIDs = testblocks - fuzzblocks
    fuzzUniBbIDs = fuzzblocks - testblocks
    
    blockMap = proBlocks()
    
    testUnique = []
    fuzzUnique = []
    for idx in testUniBbIDs:
        testUnique.append(blockMap[idx])
        # print(blockMap[idx])

    for idx in fuzzUniBbIDs:
        fuzzUnique.append(blockMap[idx])
        # print(blockMap[idx])
    
    if True:  # maybe some flag to control output 
        print("-------------------------------         test unique blocks ({})          ----------------------------------".format(len(testblocks)))
        for codeLoc in testUnique:
            print(codeLoc)
    if True:
        print("-------------------------------         fuzz unique blocks ({})          ----------------------------------".format(len(fuzzblocks)))
        for codeLoc in fuzzUnique:
            print(codeLoc)