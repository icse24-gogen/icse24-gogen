package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
)

var flagWorkers = flag.Int("workers", 60, "number of workers")

func main() {
	flag.Parse()
	os.Chdir("/tmp")
	fmt.Printf("rm tmp with %d threads\n", *flagWorkers)
	rmpool := make(chan int, *flagWorkers)

	for i := 0; i < *flagWorkers; i++ {
		rmpool <- i
	}

	cmdstr := `find . -type d -delete`
	exec.Command("sh", "-c", cmdstr).Run()

}

func rmInode(inode string, pool chan string) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Println(err)
		}
		<-pool
	}()
	cmdstr := fmt.Sprintf("find ./ -maxdepth 1 -inum %s -delete", inode)
	exec.Command("/bin/bash", "-c", cmdstr).Run()

}

func run1Cmd(cmd *exec.Cmd, pool chan int) {
	cmd.Wait()
	fmt.Println(<-pool)
}
