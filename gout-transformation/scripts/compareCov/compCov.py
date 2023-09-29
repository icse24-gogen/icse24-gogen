#! /usr/bin/env python3

import json
from multiprocessing import connection
import os

def getTestCov(proj):
    with open("testCov-0921-{}.json".format(proj)) as f:
        covdata = json.load(f)
    coverInfo = {}
    for driver in covdata:
        zipname = driver[2:]
        coverInfo[zipname] = covdata[driver]
    return coverInfo


def getFuzzCov(proj):
    covfile = {}
    covfile['casbin'] = 'fuzzres-0823-casbin.txt'
    covfile['cobra'] = 'fuzzres-0818-cobra.txt'
    covfile['colly'] = 'fuzzres-0822-colly.txt'
    covfile['echo'] = 'fuzzres-0822-echo.txt'
    covfile['fiber'] = 'fuzzres-0823-fiber.txt'
    covfile['fyne'] = 'fuzzres-0824-fyne.txt'
    covfile['go-micro'] = 'fuzzres-0819-go-micro.txt'
    covfile['gods'] = 'fuzzres-0820-gods.txt'
    covfile['gorm'] = 'fuzzres-0819-gorm.txt'
    covfile['grpc-go'] = 'fuzzres-0823-grpc-go.txt'
    covfile['httprouter'] = 'fuzzres-0821-httprouter.txt'
    covfile['iris'] = 'fuzzres-0817-iris.txt'
    covfile['kit'] = 'fuzzres-0819-kit.txt'
    covfile['mux'] = 'fuzzres-0821-mux.txt'
    covfile['mysql'] = 'fuzzres-0817-mysql.txt'
    covfile['vegeta'] = 'fuzzres-0823-vegeta.txt'
    covfile['webrtc'] = 'fuzzres-0823-webrtc.txt'
    covfile['websocket'] = 'fuzzres-0821-websocket.txt'
    with open("../autogofuzz/" + (covfile[proj]), 'r') as f:
        data = f.read()
    coverInfo = {}
    allLines = [i.strip() for i in data.split("\n") if i.strip()]
    for line in allLines:
        terms = line.split(",")
        print(terms)
        coverInfo[terms[0]] = eval(terms[2]) # zip name : coverage 
    
    return coverInfo

    
        


if __name__ == '__main__':
    projs = ['vegeta', 'iris', 'cobra', 'fiber', 'websocket', 'go-micro', 'casbin', 'gods', 'fyne', 'mux', 'echo', 'webrtc', 'httprouter', 'mysql', 'kit', 'grpc-go', 'gorm', 'colly']

    for p in projs:
        testcov = getTestCov(p)
        fuzzcov = getFuzzCov(p)
        resname = 'compareCov-{}.csv'.format(p)
        f = open(resname, "w")
        for zipname in testcov:
            if zipname not in fuzzcov or fuzzcov[zipname] == 0:
                continue
            f.write("{}, {}, {}\n".format(zipname, testcov[zipname], fuzzcov[zipname]))
    
        f.close()
