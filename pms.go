/*** PMS

 Redis stats
 SMTP or ESMTP codes

***/

package main

import (
	"bufio"
	"bytes"
	"database/sql"
	//"errors"
	"fmt"
	"log"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"code.google.com/p/gcfg"
	_ "github.com/go-sql-driver/mysql"
)

type Client struct {
	IP          []byte // IPv4 4bytes - IPv6 16bytes
	host        string
	auth        bool
	state       int
	status      int
	helo        string
	mail_to     string
	mail_from   string
	mail_con    string // Mail content
	rcpt_to     string
	rcpts       map[string]string
	my_rcpt     string // Actual RCPT
	rcpts_count int    // Stupid but rcpts duplicates...
	res         string
	addr        string
	data        string
	subject     string
	hash        string
	headers     map[string]string // Email headers
	time        int64
	conn        net.Conn
	bufin       *bufio.Reader
	bufout      *bufio.Writer
	kill_time   int64
	errors      int
	clientID    int64
	savedNotify chan int
	relayNotify chan int
	tls_on      bool
}

var db *sql.DB // Global mysql DB
var allowedHosts = make(map[string]int)
var bannedHosts = make(map[string]int)
var AuthMethods = make(map[string]bool)
var Plugins = make(map[string]bool)

var clientID int64
var sem chan int // currently active clients

var WriteMailChan chan *Client // Channel WriteMail
var RelayMailChan chan *Client // Channel RelayMail

var Version = "PMS 004"

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	
	log.Printf("%s - Go %s (%s/%s) - CPUs %d", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU())

	var cfgFile = "pms.conf"

	if os.Getenv("PMS_CONFIG") != "" {
		cfgFile = os.Getenv("PMS_CONFIG")
	}

	err := gcfg.ReadFileInto(&Config, cfgFile)

	if err != nil {
		fmt.Printf("%v", err)
	}

	// SET Auth Methods
	if Config.Smtp.Authmethods != "" {
		authm := strings.Split(Config.Smtp.Authmethods, ":")
		for auth := range authm {
			AuthMethods[authm[auth]] = true
			Log(0, "[OK] Auth method: "+authm[auth])
		}
	}

	// SET Plugins
	if Config.C.Plugins != "" {
		plgns := strings.Split(Config.C.Plugins, ":")
		for plg := range plgns {
			Plugins[plgns[plg]] = true
			Log(0, "[OK] Plugin: "+plgns[plg])
		}
	}

	// init MySQL
	db, err = sql.Open("mysql", Config.Db.User+":"+Config.Db.Pass+Config.Db.Host+"/"+Config.Db.Name)
	defer db.Close()

	if err != nil {
		log.Fatalf("Error on init mysql: %s", err.Error())
		return
	}

	db.SetMaxOpenConns(40)
	db.SetMaxIdleConns(60)

	err = db.Ping()
	if err != nil {
		log.Fatalf("Error on opening database connection: %s", err.Error())
	}

	// Domains valid RCPT
	ValidsRCPT()

	// Channels
	sem = make(chan int, 20)

	WriteMailChan = make(chan *Client, 20)
	RelayMailChan = make(chan *Client, 10)
	
	for i := 0; i < 20; i++ {
		go WriteData()
	}

	for i := 0; i < 10; i++ {
		go RelayMail()
	}


	// Config && Vars per domain
	lis := strings.Split(Config.Daemon.Listen,",")
	for addr := range lis {
		fmt.Println("Listen: ",lis[addr])
		
		Daemon := &Daemon{
			clientID: 1,
			timeout: time.Duration(Config.Daemon.Timeout),
			listen: lis[addr],
			TLS: true,
		}
		
		go Daemon.New()
	}
	
	Checks()
}

func Checks() {
	for {
		time.Sleep(15 * time.Minute)

		fmt.Printf("Sesiones Abiertas: %d\n", clientID)

		for k, v := range bannedHosts {
			if v > Config.Smtp.Banlimit && int(time.Now().Unix()) > v {
				fmt.Printf("Limpiamos: %s - %d\n", k, v)
				delete(bannedHosts, k)
			}
		}

		err := db.Ping()
		if err != nil {
			log.Fatalf("Error on Ping connection: %s", err.Error())
		}

		// Generar stats: Monitorix
		// reject / deny / temp / queue / relay / spam / virus
		
		ValidsRCPT()
	}
}

func WriteData() {

	for {
		cl := <-WriteMailChan

		var Header bytes.Buffer
		
		cl.subject = mimeHeaderDecode(cl.subject)
		cl.hash = md5hex(cl.mail_from + cl.subject + strconv.FormatInt(time.Now().UnixNano(), 10))

		email, domain := getMail(cl.my_rcpt)

		Header.WriteString("Delivered-To: " + cl.my_rcpt + "\r\n")

		if Config.Queue.Hidereceived == true && cl.auth == true {
			Header.WriteString("Received: from localhost\r\n")
		} else {
			Header.WriteString("Received: from " + cl.helo + " (" + cl.helo + "  [" + cl.addr + "])\r\n")
		}

		Header.WriteString("   by " + Config.C.Host + " with SMTP id " + cl.hash + "@" + Config.C.Host + ";\r\n")
		Header.WriteString("   " + time.Now().Format(time.RFC1123Z) + "\r\n")

		cl.headers["X-EMail"] = Version

		for k, v := range cl.headers {
			Header.WriteString(k + ": " + v + "\r\n")
		}

		cl.data = Header.String() + cl.mail_con

		real_dir := Config.Queue.Maildir + domain + "/" + email + "/"
		new_dir, _ := filepath.EvalSymlinks(real_dir)

		parts := strings.Split(new_dir, "/")
		leng := len(parts)

		pms_user := parts[leng-1]
		pms_domain := parts[leng-2]

		// Filters EMail
		var dir_out string = ""

		if Plugins["filterdb"] == true {
			dir_out = filterDb(cl, pms_user, pms_domain)
		}

		var my_file string = Config.Queue.Maildir + domain + "/" + email + "/Maildir/" + dir_out + "new/" +
			strconv.FormatInt(cl.clientID, 9) + "_" + cl.hash + ":2,"

		saveFile(cl, my_file)

		cl.savedNotify <- 1
	}
}

func saveFile(cl *Client, my_file string) {

	if Config.C.Debug == true {
		Log(cl.clientID, my_file)
	}

	file, err := os.Create(my_file)
	defer file.Close()

	if err != nil {
		log.Println(err)
		cl.savedNotify <- 452
	}

	w := bufio.NewWriter(file)
	fmt.Fprint(w, cl.data)
	w.Flush()
}

func RelayMail() {

	for {
		cl := <-RelayMailChan

		c, err := smtp.Dial(Config.C.Relay)

		if err != nil {
			cl.relayNotify <- -1
			return
		}

		c.Mail(cl.mail_from)
		c.Rcpt(cl.my_rcpt)

		// Send the email body
		wc, err := c.Data()
		//defer wc.Close()

		if err != nil {
			Log(cl.clientID, fmt.Sprintf("%s", err))
			cl.relayNotify <- 500
		}

		buf := bytes.NewBufferString(cl.data)

		if _, err = buf.WriteTo(wc); err != nil {
			log.Println(err)
			cl.relayNotify <- 500
		}

		wc.Close()

		cl.relayNotify <- 1
	}
}
