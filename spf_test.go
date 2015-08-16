package main

import (
	//"fmt"
	"testing"
)

func TestSpfFail(t *testing.T) {
	SPF := Spf{helo: "test", client_ip: "145.110.30.4", envelope: "tester@tester.com"}
	SPF.New()

	if SPF.status != "fail" {
		t.Errorf("SPF status: fail != %s", SPF.status)
	}
}

func TestSpfValid(t *testing.T) {
	SPF := Spf{helo: "test", client_ip: "176.31.102.50", envelope: "tester@tester.com"}
	SPF.New()

	if SPF.status != "pass" {
		t.Errorf("SPF status: pass != %s", SPF.status)
	}
}

func TestSpfSyntax(t *testing.T) {
	SPF := Spf{helo: "test", client_ip: "127.0.0.1", envelope: "tester@tester.com"}

	_ = SPF.Get(SPF.helo)

	SPF.Parser("v=spf1 test-failde all")
	SPF.Check()
	SPF.MakeHeader()

	//fmt.Printf("%q\n",SPF)

	if SPF.status != "permerror" {
		t.Errorf("SPF status: permerror != %s", SPF.status)
	}
}
