#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import os 
import shutil
import subprocess
import psutil
import glob



def startFuzz(proj, targetF, workdir):
    print("[+] trying to fuzz {}-{}, at {}".format(proj, targetF, os.getcwd()))
    os.chdir(workdir)

    fuzzbinName = "Fuzz{}.zip".format(targetF)
    resultDir = "resultFuzz{}".format(targetF)
    if not os.path.exists(resultDir):
        os.mkdir(resultDir)

    shutil.copyfile(fuzzbinName, "{}/{}".format(resultDir, fuzzbinName))
    os.chdir(resultDir)
    runfuzz = subprocess.Popen("timeout 6h go-fuzz -bin=Fuzz{}.zip -procs=1".format(targetF), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    return runfuzz

def getFuzzPath(projwd, yamldir, targetF):
    for fname in glob.glob(os.path.join(projwd, yamldir, '*.yaml')):
        if fname.endswith("{}.yaml".format(targetF)):
            with open(fname) as f:
                content = [i.strip() for i in f.readlines()]
            srcpath = content[1].split(": ")[1] # SrcPath: task/task_test.go
            if "/" not in srcpath:
                srcpath = "./" + srcpath
            path = srcpath.rsplit("/", 1)[0]
            if os.path.exists(os.path.join(path, "Fuzz{}.zip".format(targetF))):
                return path
    return ""


def kill(proc_pid):
    process = psutil.Process(proc_pid)
    for proc in process.children(recursive=True):
        proc.kill()
    process.kill()