package main

import(
	"time"
	"net"
	"strings"
	"github.com/saintienn/go-spamc"
)

func EarlyTalker(cl *Client)(ret int) {
	cl.conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	_, err := cl.bufin.ReadByte()

	if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
		ret = 1
	} else {
		ret = 0
	}

	return
}

func spam(cl *Client) {
	spam := spamc.New("127.0.0.1:783",10)

	reply, _ := spam.Process(cl.data)

	// Si es SPAM pasa 14 lo elimina
	// Si pasa de 8 el Subject
	if reply.Vars["isSpam"] == true {
		spam.Report()
		cl.state = DENY_SPAM
		cl.subject = "*** SPAM-MAIL *** " + cl.subject
	}

	if str, ok := reply.Vars["body"].(string); ok {
		str = strings.Trim(str, " \n\r")
		cl.data = str
	} else {
		//cl.state = DENY_RELAY
	}
}
