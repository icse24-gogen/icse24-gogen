#! /usr/bin/env python3
# -*- coding: utf-8 -*-


import os
import glob


def collect(proj):
    res = []
    for resultfile in glob.glob("{}FuzzResult/*".format(proj)):
        testname = resultfile.split("/")[-1]
        with open(resultfile, 'r') as f:
            info = f.readlines()
            for i in range(len(info)):
                finalres = info[-1-i]
                terms = finalres.split(", ")
                if len(terms) ==  7:
                    break
        
        corpus = terms[1].split(": ")[1].split(" (")[0]
        crashers = terms[2].split(": ")[1]
        cover = terms[5].split(": ")[1]
        res.append((proj, testname, corpus, crashers, cover))
    return res


if __name__ == '__main__':
    projs = {}
    projs['beego'] = ''
    projs['go-restful'] = ''
    projs['websocket'] = ''
    projs['protobuf'] = ''
    projs['etcd'] =''

    os.chdir("/home/user/workspace/gowork/src/go-fdg-exmaples")
    cwd = os.getcwd()
    allres = []
    for proj in projs:
        res = collect(proj)
        allres += res
    
    for r in allres:
        print(r)


