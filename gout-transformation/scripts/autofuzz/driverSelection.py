#! /usr/bin/env python3
# -*- coding: utf-8 -*-


from curses.ascii import isdigit
import os
import subprocess
import glob



def max(a, b):
    if a > b:
        return a
    return b

def min(a, b):
    if a < b :
        return a 
    return b

def driverScoring(proj):
    patternName = {}
    patternName['beego'] = 'github.com/beego/'
    patternName['go-restful'] = 'github.com/emicklei'
    patternName['websocket'] = 'github.com/gorilla'
    patternName['protobuf'] = 'github.com/golang/protobuf'
    patternName['etcd'] = 'etcd.io'
    res = []
    funcScore = {}
    with open("driverscore.csv") as f:
        argScores = [i.split(",") for i in f.readlines() ]
    for scoreinfo in argScores:
        if patternName[proj] not in scoreinfo[0].strip():
            continue
        testname = scoreinfo[1].strip()
        idx = 4
        while idx < len(scoreinfo):
            if scoreinfo[idx].strip() == "":
                break
            argscore = scoreinfo[idx].strip()
            if not isdigit(argscore[0]):
                idx +=1 
                continue
            
            if testname not in funcScore:
                funcScore[testname] = int(argscore)
            else:
                funcScore[testname] = max(int(argscore), funcScore[testname])
            idx +=2

    with open("{}SuccGenResult".format(proj), 'r') as f:
        succGened = [i.strip() for i in f.readlines()]

    for func in succGened:
        if func in funcScore:
            res.append((func, funcScore[func]))
        print("func {} not in funcScore".format(func))
    res.sort(key=lambda x: int(x[1]), reverse=True)
    return res
    


def select(proj, num):
    scores = driverScoring(proj)
    selected = []
    selectedDriverScores = []
    for i in range(min(int(num/2), len(scores))):
        newelem = scores[i][0]
        if newelem not in selected:
            selected.append(newelem)
            selectedDriverScores.append(scores[i][1])
        
    for i in range(min(int(num/2), len(scores))):
        newelem = scores[-i-1][0]
        if newelem not in selected:
            selected.append(newelem)
            selectedDriverScores.append(scores[-i-1][1])
    return selected, selectedDriverScores


if __name__ == "__main__":
    projDriverNums = {}
    projDriverNums['beego'] = 36
    projDriverNums['go-restful'] = 2
    projDriverNums['websocket'] = 2
    projDriverNums['protobuf'] = 2
    projDriverNums['etcd'] = 24

    os.chdir("/home/user/workspace/gowork/src/go-fdg-exmaples")

    for proj in projDriverNums:
        
        dirvers, driverScores = select(proj, projDriverNums[proj])
        with open("selectedDrivers{}".format(proj), 'w') as f:
            for driver in dirvers:
                f.write(driver + "\n")
        for driverS in driverScores:
            print(driverS)
        

        
