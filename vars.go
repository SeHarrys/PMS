package main

import (
	"log"
	"os"
)

type Cfg struct {
	Daemon struct {
		Listen string
		Tls bool
		Timeout int
	}
	Smtp struct {
		Maxsize int
		Maxrcpts int
		Maxerrors int
		Banlimit int
		Bantime int
		Counter int
	}
	Queue struct {
		Maildir string
		Hidereceived bool
		Sgid int
		Guid int
		Symlinks bool
	}
	Redis struct {
		Server string
	}
	Db struct {
		User string
		Pass string
		Name string
		Host string
	}
	Checks struct {
		Timer int
	}
	C struct {
		Debug bool
		Relay string
		Host string
		Logfile string
		Plugs string
	}
}

const (
	RECV_BUF_LEN = 1024
	MAIL_CMD     = 1
	MAIL_AUTH    = 2
	MAIL_QUEUE   = 4
	MAIL_EXIT    = 5
	MAIL_TLS     = 6
	MAIL_SPAM    = 8
	DENY_RELAY   = 550
	DENY_USER    = 551
	DENY_SPAM    = 552
	// Client constant for method to chan
	CL_QUEUE     = 1
	CL_RELAY     = 2
)

func Log(msg string) {

	if Config.C.Logfile != "" {
		fd, err := os.OpenFile(Config.C.Logfile, os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
		defer fd.Close()
		
		if err != nil {
			log.Fatalf("Error log file: %v", err)
		}

		log.SetOutput(fd)
	}

	log.Println(msg)
}
