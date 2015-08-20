package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func Log(cID int64, msg string) {

	if Config.C.Logfile != "" {
		fd, err := os.OpenFile(Config.C.Logfile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		defer fd.Close()

		if err != nil {
			log.Fatalf("Error log file: %v", err)
		}

		log.SetOutput(fd)
	}

	log.Printf("%d > %s\n", cID, msg)
}

func pidfile() {
	fd, err := os.Create("pms.pid")
	defer fd.Close()

	if err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}

	fmt.Fprintf(fd, "%v\n", os.Getpid())
}

//camilstored riped
func Signals(shutdownc <-chan io.Closer) {
	c := make(chan os.Signal, 1)

	signal.Notify(c, syscall.SIGHUP)
	signal.Notify(c, syscall.SIGINT)

	for {
		sig := <-c
		sysSig, ok := sig.(syscall.Signal)
		if !ok {
			log.Fatal("Not a unix signal")
		}
		switch sysSig {
		case syscall.SIGHUP:
			Log(0, "SIGHUP: Restarting")
			syscall.Exec("/proc/self/exe", os.Args, os.Environ())
		case syscall.SIGINT:
			Log(0, "SIGINT: Shutting down")
			os.Remove("pms.pid")
			donec := make(chan bool)
			go func() {
				cl := <-shutdownc
				if err := cl.Close(); err != nil {
					fmt.Printf("Error shutting down: %v\n", err)
					os.Exit(1)
				}
				donec <- true
			}()
			select {
			case <-donec:
				log.Printf("Shut down.")
				os.Exit(0)
			case <-time.After(2 * time.Second):
				fmt.Println("Timeout shutting down. Exiting uncleanly.")
				os.Exit(1)
			}
		default:
			Log(0, "Received another signal, should not happen.")
		}
	}
}
