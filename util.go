package main

import (
	//"io/ioutil"
	"fmt"
	"os"
)

func pidfile() {
	fd, err := os.Create("pms.pid")
	defer fd.Close()

	if err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}

	fmt.Fprintf(fd, "%v\n", os.Getpid())
}
