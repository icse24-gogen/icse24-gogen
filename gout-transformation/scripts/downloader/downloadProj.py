#! /usr/bin/env python3
# -*- coding: utf-8 -*-



from math import fabs
import string
import subprocess
from unicodedata import name
from bs4 import BeautifulSoup
import os
import shutil



def collectProj(start: int=0 , end: int = None) -> list:
    res = []
    with open("./githubpage.html", 'r') as f:
        htmlstring = f.read()
    soup = BeautifulSoup(htmlstring)
    allproj = soup.find_all("div", attrs={"class": 'd-flex flex-justify-between my-3'}  )
    for proj in allproj:
        div = proj.find("div", attrs={"class":"d-flex flex-auto"})
        a = div.find_all('a')[-1]
        # https://github.91chi.fun/https://github.com/moby/moby.git
        link = "https://github.91chi.fun/https://github.com/{}.git".format(a["href"])
        res.append((a.string.strip(), link))

    return res[start:end]

def downloadProj(proj:tuple, redownload:bool = True) -> bool:
    projname, downloadlink = proj
    blacklist = ["kubernetes", "the-way-to-go_ZH_CN", "awesome-go","grafana","project-layout","leetcode-master"]
    if projname == "go":
        return False
    for black in blacklist:
        if black in projname:
            return False
    if not redownload and os.path.exists(projname):
        return True
    if os.path.exists(projname):
        shutil.rmtree(projname)
    print("[+] Downloading {}".format(projname))
    cmd = subprocess.Popen("git clone {}".format(downloadlink), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    cmd.communicate()
    return cmd.returncode == 0


if __name__ == "__main__":
    projs = collectProj(0,23)

    os.chdir("/home/user/workspace/gowork/src/topproj")
    projlist = []
    for proj in projs:
        if downloadProj(proj):
            print("[+] {} download success".format(proj[0]))
            projlist.append(proj)
    
    os.chdir("/home/user/workspace/gowork/src/topproj")
    f = open("projList", 'w')
    for proj in projlist:
        f.write("('{}', '/home/user/workspace/gowork/src/topproj/{}')\n".format(proj[0], proj[0]))

    f.close()


