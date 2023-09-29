#! /usr/bin/env python3
# -*- coding: utf-8 -*-


import os 
import shutil
import subprocess

import psutil
import glob


def GetStdPkgWithYaml():

    yamlmap = {}
    yamlmap['std'] = 'std_yaml_out_dir'
    

    return yamlmap

def GetProjsWithYaml():
    yamlmap = {}
    yamlmap['beego'] = 'beego_yaml_out_dir'
    yamlmap['go-restful'] = 'go-restful-3_yaml_out_dir'
    yamlmap['websocket'] = 'websocket_yaml_out_dir'
    yamlmap['protobuf'] = 'protobuf_yaml_out_dir'
    yamlmap['etcd'] = 'etcd_yaml_out_dir'
    yamlmap['kubernetes'] = "kubernetes_yaml_out_dir"
    yamlmap['gin'] = "gin_yaml_out_dir"
    yamlmap['frp'] = "frp_yaml_out_dir"
    yamlmap['syncthing'] = 'syncthing_yaml_out_dir'
    yamlmap['fzf'] = 'fzf_yaml_out_dir'
    yamlmap['caddy'] = 'caddy_yaml_out_dir'
    yamlmap['traefik'] = 'traefik_yaml_out_dir'
    yamlmap['minio'] = 'minio_yaml_out_dir'
    yamlmap['cobra'] = 'cobra_yaml_out_dir'
    return yamlmap

def startFuzz(proj, targetF, targetDir, fuzztime = 4):
    print("[+] trying to fuzz {}-{}, at {}".format(proj, targetF, targetDir))
    # os.chdir(targetDir)
    fuzzbinName = "Fuzz{}.zip".format(targetF)

    if not os.path.exists("{}/{}".format(targetDir, fuzzbinName)):
        return None

    resultDir = "{}/resultFuzz{}".format(targetDir, targetF)
    if not os.path.exists(resultDir):
        os.mkdir(resultDir)

    shutil.copyfile("{}/{}".format(targetDir, fuzzbinName), "{}/{}".format(resultDir, fuzzbinName))
    # os.chdir(resultDir)
    runfuzz = subprocess.Popen("timeout {}h go-fuzz -bin={} -procs=1".format(fuzztime, fuzzbinName), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=resultDir)

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
