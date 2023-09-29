#! /usr/bin/env python3
# -*- coding: utf-8 -*-



import os
import glob



def mvyamltosingle():
    os.chdir("/home/user/workspace/gowork/src/go-fdg-exmaples/std/std_yaml_out_dir")
    for file in glob.glob("*.yaml"):
        # print(file)
        t = file.split("_")
        if len(t) > 1:
            pkgname = t[0]
        else:
            pkgname = file.split(".")[0]
        
        if not os.path.exists(pkgname):
            os.mkdir(pkgname)
        
        os.system("mv %s %s" % (file, pkgname))


def countstdsucc():
    os.chdir("/home/iscsi/goarea/go-fdg-exmaples/std")
    for file in glob.glob("log*"):
        succ = 0
        fail = 0
        noget = 0

        pkg = file[3:]
        if pkg == '':
            continue 

        with open(file, 'r') as f:
            info = f.readlines()
        for line in info:
            if '[+] Build fuzz driver successfully' in line :
                succ+=1 
            elif '[-]Cannot build Driver' in line:
                fail+=1
            elif '[-] Cannot find transstruct.Get from' in line:
                noget+=1
        
        print("{}\t{}\t{}\t{}\t{}".format(pkg, succ+fail+noget ,succ, fail, noget))

        
def walkcopy(dir):
    os.chdir(dir)
    if os.path.exists("internal") and not os.path.exists("enternal"):
        os.system("cp -r internal enternal")
    for dir in glob.glob("*"):
        if dir == "internal" or dir == "enternal":
            continue
        if os.path.isdir(dir):
            walkcopy(dir)
    os.chdir("..")


def copyinternal():
    os.chdir("/home/iscsi/goarea/go-fdg-exmaples/std")
    walkcopy(".")
    

if __name__ == "__main__":
    countstdsucc()
    # copyinternal()
    pass

