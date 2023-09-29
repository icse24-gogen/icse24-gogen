#! /usr/bin/env python3
# -*- coding: utf-8 -*-


import os
import shutil
import subprocess
import glob


rebuild = False

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

def genAndFuzz(proj, yamldir, selectedDrivers):
    succ = [] # build succ
    fail = [] # buuild fail
    nores = [] # gen fail
    fuzzcmd = []

    selectedDriverFile = open(selectedDrivers, 'r')
    projwd = os.getcwd()
    for targetF in [i.strip() for i in selectedDriverFile.readlines() if i.strip()]:
        # print('Generating ' + targetF)
        
        succbuild = False
        if rebuild:
            gencmd = subprocess.Popen("gout-transformer-gofuzz -dir={} -spe={}".format(yamldir, targetF), shell=True, 
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = gencmd.communicate()
            for info in stderr.decode().split('\n'):
                if 'Build fuzz driver successfully' in info:
                    succ.append(targetF)
                    succbuild = True
                    print("succ: {}".format(targetF))
                    break
                elif 'failed' in info:
                    fail.append(targetF)
                    # print(info)
                    with open("{}ErrorInfos/{}".format(proj, targetF), "w+") as f:
                        f.write(stdout.decode() + "\n" + stderr.decode() + "------------------------------------------\n")
            else:
                nores.append(targetF)
                with open("{}ErrorInfos/{}".format(proj, targetF), "w") as f:
                    f.write(stdout.decode() + "\n\n" + stderr.decode())
        if succbuild or not rebuild:
            workdir = getFuzzPath(projwd, yamldir, targetF)
            if workdir== "":
                continue
            print("[+] trying to fuzz {}-{}, at {}/{}".format(proj, targetF, projwd, workdir))
            os.chdir(workdir)
            

            fuzzbinName = "Fuzz{}.zip".format(targetF)
            resultDir = "resultFuzz{}".format(targetF)
            if not os.path.exists(resultDir):
                os.mkdir(resultDir)

            shutil.copyfile(fuzzbinName, "{}/{}".format(resultDir, fuzzbinName))
            os.chdir(resultDir)

            runfuzz = subprocess.Popen("timeout 6h go-fuzz -bin=Fuzz{}.zip -procs=1".format(targetF), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            fuzzcmd.append((proj, targetF, runfuzz))
            
            # subprocess.Popen("batchcover.sh Fuzz{}".format(targetF), shell=True, cwd=)
            os.chdir(projwd)

    return succ, fail, nores, fuzzcmd



if __name__ == "__main__":
    yamlmap = {}
    # yamlmap['beego'] = 'beego_yaml_out_dir'
    # yamlmap['go-restful'] = 'go-restful-3_yaml_out_dir'
    # yamlmap['websocket'] = 'websocket-master_yaml_out_dir'
    # yamlmap['protobuf'] = 'protobuf-master_yaml_out_dir'
    yamlmap['etcd'] = 'etcd_yaml_out_dir'

    selectedDriver = {}
    selectedDriver['beego'] = 'selectedDriversbeego'
    selectedDriver['go-restful'] = 'selectedDriversgo-restful'
    selectedDriver['websocket'] = 'selectedDriverswebsocket'
    selectedDriver['protobuf'] = 'selectedDriversprotobuf'
    selectedDriver['etcd'] = 'selectedDriversetcd'

    os.chdir("/home/user/workspace/gowork/src/go-fdg-exmaples")
    cwd = os.getcwd()

    allfuzzcmd = []

    for proj in yamlmap:
        os.chdir(proj)
        if not os.path.exists("{}ErrorInfos".format(proj)):
            os.mkdir("{}ErrorInfos".format(proj))
        succ, fail, nores,fuzzcmd = genAndFuzz(proj, yamlmap[proj], "../{}".format(selectedDriver[proj]))

        allfuzzcmd += fuzzcmd


        print("{} success: {}".format(proj, len(succ)))
        print("{} failed: {}".format(proj, len(fail)))
        print("{} no result: {}".format(proj, len(nores)))

        os.chdir(cwd)

        if not os.path.exists("{}FuzzResult".format(proj)):
            os.mkdir("{}FuzzResult".format(proj))
    for fuzz in allfuzzcmd:
        proj = fuzz[0]
        targetF = fuzz[1]
        fuzzcmd = fuzz[2]
        fuzzout, fuzzerr = fuzzcmd.communicate()
        fuzzout, fuzzerr = fuzzout.splitlines(), fuzzerr.splitlines()


        with open("{}FuzzResult/{}".format(proj, targetF), 'w') as f:
            if len(fuzzout) > 50 :
                fuzzout = fuzzout[-40:]
            if len(fuzzerr) > 50:
                fuzzerr = fuzzerr[-40:]
            for out in fuzzout:
                f.write("{}\n".format(out.decode()))
            f.write("\n--------------------------------------\n")
            for err in fuzzerr:
                f.write("{}\n".format(err.decode()))
            


