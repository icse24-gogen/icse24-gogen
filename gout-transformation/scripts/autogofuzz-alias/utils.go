package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

func fileExists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

func elemInStringSlice(elem string, slice []string) bool {
	for _, v := range slice {
		if v == elem {
			return true
		}
	}
	return false
}

// 判断所给路径是否为文件夹
func fileIsDir(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return s.IsDir()
}

// 判断所给路径是否为文件
func fileIsFile(path string) bool {
	return fileExists(path) && !fileIsDir(path)
}

func rmtmpFile() {
	rmcmd := fmt.Sprintf(`cd /tmp; find . -maxdepth 1 -type f  -user %s -mmin +5 ! -name "*fuzz*" ! -name "*build*" -delete`, os.Getenv("USER"))
	exec.Command("/bin/sh", "-c", rmcmd).Run()
}

func rmtmpDir() {
	rmcmd := fmt.Sprintf(`cd /tmp; find . -maxdepth 1 -type d  -user %s -mmin +5 ! -name . ! -name "*fuzz*" ! -name "*build*" ! -name "tmux*" -print0 | xargs -0 rm -r`, os.Getenv("USER"))
	exec.Command("/bin/sh", "-c", rmcmd).Run()
}

func clearTmp() {
	time.Sleep(6 * time.Minute)
	for {
		go rmtmpFile()
		go rmtmpDir()
		time.Sleep(5 * time.Minute)
	}
}
