#! /usr/bin/env python3
# -*- coding: utf-8 -*-

from downloadProj import downloadProj
from downloadProj import collectProj
import os
import shutil
import subprocess



def parseProjIsPureLib(proj:tuple) -> bool :
    cmdstr = 'find {} -name "*.go" | xargs grep "func main()"'.format(proj[0])
    cmd = subprocess.Popen(cmdstr, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = cmd.communicate()
    for line in stdout.decode().split("\n"):
        if "func main()" in line:
            return False
    return True
    


if __name__ == "__main__":
    projs = collectProj(100, 300)
    for proj in projs:
        print(proj)
    
    
    os.chdir("/home/user/workspace/gowork/src/awesomego")
    print("[+] Start download")
    for proj in projs:
        if not downloadProj(proj):
            continue
        if parseProjIsPureLib(proj):
            print("[+] {} is pure lib".format(proj[0]))
        else:
            shutil.rmtree(proj[0])
