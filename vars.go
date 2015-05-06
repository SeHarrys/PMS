package main

var Config = map[string]string {
	"VERSION"    : "PMS 001",
	"CONFIG"     : "pms.conf.json",
}

var cDaemon = map[string]int {
	"MAX_SIZE"   : 131072,
	"TIMEOUT"    : 60,
	"RELAY"      : 1,
	"STARTTLS"   : 0,
	"BAN_LIMIT"  : 4,
	"BAN_TIME"   : 3600,
	"AUTH_MD5"   : 0,
	"AUTH_PLAIN" : 0,
	"EARLYTALK"  : 0,
	"MAX_ERRORS" : 3,
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
