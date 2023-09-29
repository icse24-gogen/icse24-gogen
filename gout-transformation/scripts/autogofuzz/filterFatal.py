
import os

import subprocess

from tqdm import tqdm



def getFatalBins():
    fatalBins = []
    with open("./allbin0604.txt", "r") as f:
        allbins = [i.strip() for i in f.readlines() if i.strip()] 
    origpath = os.getcwd()
    os.chdir("/home/user/workspace/gowork/src/go-fdg-exmaples/std")
    yamldir = "std_yaml_out_dir"
    for bi in allbins:
        testname = bi.split("/Fuzz")[1].split(".zip")[0]
        cmd = "gout-transformer-gofuzz -dir={} -spe={}  -nobuild=true".format(yamldir, testname)
        out, err = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        combineoutput = out + err 
        if "This case has fatal call" in combineoutput.decode():
            fatalBins.append(bi)

    os.chdir(origpath)
    return fatalBins


if __name__ == "__main__":
    fatalBins = getFatalBins() # []string
    
    with open("fatalBins.txt", "w") as f:
        for bin in fatalBins:
            f.write(bin + "\n")