import os
import subprocess 
import time 

def  completeInfoTable():
    origpath = os.getcwd()
    fuzzRes = open("fuzzRes-All.txt", "w")
    fuzzRes.write("{},{},{},{},{},{},{},{}\n".format(
            "pkgname", "fuzzbinname", "gentime", "hasTested", "corpus", "cover", "crash", "resNoProblem"))
    with open("fuzz结果-总表.csv", 'r') as f:
        os.chdir("/home/user/workspace/gowork/src/go-fdg-exmaples/std")
        f.readline()
        for line in f.readlines():
            terms = line.split(",")
            fuzzbinname = terms[0]
            corpus = terms[1]
            cover = terms[2]
            crash= terms[3]

            pkgname = fuzzbinname.split("/")[0]
            gentime = None 
            if os.path.exists(fuzzbinname):
                timeinfo = time.localtime(os.stat(fuzzbinname).st_mtime)
                gentime = "{}/{}".format(timeinfo.tm_mon, timeinfo.tm_mday)
            else:
                gentime = "bin not exist"
            hasTested = True 
            resNoProblem = eval(cover) > 0
            fuzzRes.write("{},{},{},{},{},{},{},{}\n".format(pkgname, fuzzbinname, gentime, hasTested, corpus, cover, crash, resNoProblem))
    fuzzRes.close()
    os.chdir(origpath)
    return 

def findNeedRebuildBins():
    needrebuildbins = []
    with open("fatalBins-all.txt", 'r') as f:
        fatalbins = [i.strip() for i in f.readlines() if i.strip()]
    
    with open("finishedbin.list", 'r') as f:
        finishedbins = [i.strip() for i in f.readlines() if i.strip()]
    
    with open("fatalbins-needfuzz.txt", 'w') as f:
        for bi in fatalbins:
            if bi not in finishedbins:
                needrebuildbins.append(bi)
                f.write(bi + "\n")
    return needrebuildbins

def copyYaml(bins, fataldir):
    origpath = os.getcwd()
    os.chdir("/home/user/workspace/gowork/src/go-fdg-exmaples/std")
    for bi in bins:
        pkg, testname = bi.split("/Fuzz")
        testname = testname[:-4]

        yamlname = pkg.replace("/", "_") + "*." + testname + ".yaml"
        cmd = "cp {} {}".format("std_yaml_out_dir/" + yamlname, fataldir)
        subprocess.Popen(cmd, shell=True).communicate()
    os.chdir(origpath)




if __name__ == "__main__":
    completeInfoTable()
    # rebuildbins = findNeedRebuildBins()
    # copyYaml(rebuildbins, "std_yaml_fatal")

