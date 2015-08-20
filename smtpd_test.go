package main

import (
	//"fmt"
	//"os"
	"testing"
	"time"
)

func TestDaemon(t *testing.T) {

	Daemon := &Daemon{
		AuthMethods: make(map[string]bool),
		Plugins:     make(map[string]bool),
		clientID:    1,
		timeout:     time.Duration(Config.Daemon.Timeout),
		listen:      "127.0.0.1:4545",
		TLS:         false,
	}

	Daemon.AuthMethods["PLAIN"] = true
	Daemon.Plugins["filterdb"] = true

	//Daemon.New()
}
