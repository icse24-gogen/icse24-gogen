#! /usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import glob

def gen(proj, yamldir):
    succ = [] # build succ
    fail = [] # buuild fail
    nogetx = []
    nores = [] # gen fail
    for f in glob.glob(os.path.join(yamldir, '*.yaml')):
        targetF = f.split(".")[-2]
        

        # print('Generating ' + targetF)
        gencmd = subprocess.Popen("gout-transformer-gofuzz -dir={} -spe={}".format(yamldir, targetF), shell=True, 
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = gencmd.communicate()
        
        
        for info in stderr.decode().split('\n'):
            if "[-] Cannot find transstruct.Get" in info:
                nogetx.append(targetF)
                break
            elif '[+] Build fuzz driver successfully' in info:
                succ.append(targetF)
                # print(info)
                break
            elif '[-]Cannot build' in info:
                fail.append(targetF)
                # print(info)
                with open("{}ErrorInfos/{}".format(proj, targetF), "w") as f:
                    f.write(stdout.decode() + "\n" + stderr.decode() + "------------------------------------------\n")
                break
        else:
            nores.append(targetF)
            with open("{}ErrorInfos/{}".format(proj, targetF), "w") as f:
                f.write(stdout.decode() + "\n\n" + stderr.decode())

    return succ, fail, nogetx, nores



if __name__ == "__main__":
    yamlmap = {}
    yamlmap['beego'] = 'beego_yaml_out_dir'
    yamlmap['go-restful'] = 'go-restful-3_yaml_out_dir'
    yamlmap['websocket'] = 'websocket-master_yaml_out_dir'
    yamlmap['protobuf'] = 'protobuf-master_yaml_out_dir'
    yamlmap['etcd'] = 'etcd_yaml_out_dir'

    os.chdir("/home/user/workspace/gowork/src/go-fdg-exmaples")
    cwd = os.getcwd()

    for proj in yamlmap:
        os.chdir(proj)
        if not os.path.exists("{}ErrorInfos".format(proj)):
            os.mkdir("{}ErrorInfos".format(proj))
        succ, fail, nogetx, nores = gen(proj, yamlmap[proj])
        print("{} success: {}".format(proj, len(succ)))
        print("{} failed: {}".format(proj, len(fail)))
        print("{} no result: {}".format(proj, len(nores)))

        os.chdir(cwd)
        with open("{}SuccGenResult".format(proj), 'w') as f:
            for s in succ:
                f.write("{}\n".format(s))
        with open("{}FailGenResult".format(proj), 'w') as f:
            for s in fail:
                f.write("{}\n".format(s))
        
        with open("{}NoGetXResult".format(proj), 'w') as f:
            for s in nogetx:
                f.write("{}\n".format(s))

        with open("{}NoGenResult".format(proj), 'w') as f:
            for s in nores:
                f.write("{}\n".format(s))
            


