/*** PMS

***/

package main

import (
	"bytes"
	"bufio"
        "crypto/md5"
	"crypto/hmac"
	"crypto/tls"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
        "encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"io"
	"io/ioutil"
	"time"
	"os"
	"net"
	"net/mail"
	"net/smtp"
	"log"
	"regexp"
	"strconv"
	"strings"
	"runtime"
	_"github.com/go-sql-driver/mysql"
	"github.com/sloonz/go-iconv"
	"github.com/sloonz/go-qprintable"
	"github.com/saintienn/go-spamc"
)

type Client struct {
	IP	    []byte // IPv4 4bytes - IPv6 16bytes
	auth        bool
	relay       bool
        state       int
	status      int
        helo        string
	mail_to     string
        mail_from   string
	mail_con    string           // Mail content
	relay_rcpt  string
        rcpt_to     string
        read_buffer string
        res         string
        addr        string
        data        string
        subject     string
        hash        string
	domain      string
	user        string
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

var TLSconfig *tls.Config

var db *sql.DB                    // Global mysql DB
var timeout time.Duration
var allowedHosts = make(map[string]bool, 16)
var bannedHosts = make(map[string]int,1)

var clientID int64
var sem chan int                  // currently active clients

var WriteMailChan chan *Client    // Channel WriteMail
var RelayMailChan chan *Client    // Channel RelayMail

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
	"MAX_ERRORS" : 4,
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

func main() {
        log.Printf("%s - Go %s (%s/%s) - CPUs %d",Config["VERSION"],runtime.Version(),runtime.GOOS,runtime.GOARCH,runtime.NumCPU())

	// Read config from env 
	if os.Getenv("PMS_CONFIG") != "" {
		Config["CONFIG"] = os.Getenv("PMS_CONFIG")
	}
	
        b, err := ioutil.ReadFile(Config["CONFIG"])
        if err != nil {
                log.Fatalln("Could not read config file: " + Config["CONFIG"])
        }

        var myConfig map[string]string
        err = json.Unmarshal(b, &myConfig)
        if err != nil {
                log.Fatalln("Could not parse config file")
        }

        for k, v := range myConfig {
                Config[k] = v
        }

	// Enabled TLS
	if Config["TLS"] == "1" {
		cDaemon["STARTTLS"] = 1
		cert, err := tls.LoadX509KeyPair("./pms-cert.pem", "./pms-cert.key")
		if err != nil {
			log.Fatalln("Error: tls.LoadX509KeyPair")
		}
		TLSconfig = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.VerifyClientCertIfGiven, ServerName: Config["HOSTNAME"] }
		TLSconfig.Rand = rand.Reader
	}

	timeout = time.Duration(cDaemon["TIMEOUT"])

	// init MySQL
	db, err = sql.Open("mysql", Config["DB_USER"]+":"+Config["DB_PASS"]+Config["DB_HOST"]+"/"+Config["DB_NAME"])
        defer db.Close()
	
        if err != nil {
                log.Fatalf("Error on init mysql: %s", err.Error())
                return
        }

	db.SetMaxIdleConns(120)

	err = db.Ping() // This DOES open a connection if necessary. This makes sure the database is accessible
	if err != nil {
		log.Fatalf("Error on opening database connection: %s", err.Error())
	}

	// Domains valid RCPT
	ValidsRCPT()
	
	//if arr := strings.Split(Config["RCPT_HOSTS"], ","); len(arr) > 0 {
	//	for i := 0; i < len(arr); i++ {
	//		allowedHosts[arr[i]] = true
	//	}
	//}
	
	// Channels
        sem = make(chan int, 10)
	
        WriteMailChan = make(chan *Client, 10)
	RelayMailChan = make(chan *Client, 10)
	
	for i := 0; i < 10; i++ {
                go WriteData()
        }

	for i := 0; i < 10; i++ {
		go RelayMail()
	}
	
	srv, err := net.Listen("tcp",Config["LISTEN"])

	if err != nil {
		log.Fatalln("Error Listen :", err.Error())
	} else {
		log.Printf("Listen: %s",Config["LISTEN"])
	}

	clientID = 1

	go Checks()
	
	for {
		conn, err := srv.Accept()
		if err != nil {
			log.Print("Error client :", err.Error())
			continue
		}
		
                //log.Print("Goroutines: "+strconv.Itoa(runtime.NumGoroutine()))

                sem <- 1
		go Parser(&Client{
			conn:        conn,
			addr:        conn.RemoteAddr().String(),
			headers:     make(map[string]string),
			time:        time.Now().Unix(),
			bufin:       bufio.NewReader(conn),
			bufout:      bufio.NewWriter(conn),
			clientID:    clientID,
			savedNotify: make(chan int),
			relayNotify: make(chan int),
		})
                clientID++
	}
}

func Checks() {
	for {
		log.Printf("Sesiones Abiertas: %d",clientID);
		
		time.Sleep(30 * time.Second)

		for k,v := range bannedHosts {
			if v > cDaemon["BAN_LIMIT"] && int(time.Now().Unix()) > v {
				log.Printf("Limpiamos: %s - %d",k,v)
				delete(bannedHosts,k)
			}
		}

		ValidsRCPT()
	}
}

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

func Parser(cl *Client) {
        defer closeClient(cl)

	if cDaemon["EARLYTALK"] == 1 {
		if EarlyCheck := EarlyTalker(cl); EarlyCheck == 0 {
			cl.res = "550 Connecting host started transmitting before SMTP greeting\r\n"
			cl.conn.Write([]byte(string(cl.res)))
			return
		}
	}
	
	var counter_cmd int

	cl.res = "220 " + Config["HOSTNAME"] + " ESMTP " + strconv.FormatInt(cl.clientID, 9) + " " + Config["VERSION"] + "\r\n"
	cl.state = 1
	cl.conn.Write([]byte(string(cl.res)))

	for i := 0; i < 24; i++ {

		s := strings.Split(cl.addr, ":")
		if bannedHosts[s[0]] > 3 {
			killClient(cl,"521 You are banned")
		}
		
		if counter_cmd >= 3 {
			killClient(cl,"521 Closing connection. 4 unrecognized commands")
		}

		switch cl.state {
		case 1:
                        input, err := readSmtp(cl)
                        if err != nil {
                                if err == io.EOF {
                                        //killClient(cl)
					return
                                }
                                if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
					//killClient(cl)
                                        return
                                }
                                break
                        }
                        //input = strings.Trim(input, " \n\r")
                        cmd := strings.ToUpper(input)
			switch {
			case strings.Index(cmd, "EHLO") == 0,strings.Index(cmd, "HELO") == 0:
				if len(input) > 5 {
                                        cl.helo = input[5:]
                                }
				greeting(cl)
			case strings.Index(cmd, "DATA") == 0:
				if len(cl.mail_from) == 0 || len(cl.rcpt_to) == 0 && len(cl.relay_rcpt) == 0  {
                                        cl.res = "503 5.1.0 Bad syntax RCPT TO and MAIL FROM not defined"
                                        break
                                }
				cl.res = "354 go ahead"
				cl.state = MAIL_QUEUE
			case strings.Index(cmd, "STARTTLS") == 0:
				if cl.tls_on {
					cl.res = "502 STARTTLS is active"
					cl.state = MAIL_CMD
				} else {
					cl.res = "220 2.0.0 Go TLS"
					cl.state = MAIL_TLS
				}
			case strings.Index(cmd, "NOOP") == 0:
				cl.res = "220 2.0.0 OK"
			case strings.Index(cmd, "AUTH") == 0:
				//Auth(cl,auth_method)
				auth_method := input[5:]
				switch { 
				case strings.Index(auth_method,"CRAM-MD5") == 0:
					AuthMD5(cl)
				case strings.Index(auth_method,"PLAIN") == 0:
					if strings.Index(auth_method,"PLAIN ") == 0 {
						auth_b64 := input[11:]
						AuthPlain(cl,auth_b64)
					} else {
						// Some clients wait for a response...
						cl.res = "334\r\n"
						cl.conn.Write([]byte(string(cl.res)))
						
						my_buf,err := readSmtp(cl)
						if err != nil {
							println("Error reading:", err.Error())
							return
						}
						AuthPlain(cl,string(my_buf))
					}
				default:
					cl.res = "504 Undefinied authentication method"
				}
			case strings.Index(cmd, "MAIL FROM:") == 0:
				if len(cmd) > 10 {
					_,err = mail.ParseAddress(cmd[10:])
					if err != nil {
						cl.res = "501 could not parse your mail from command"
						break
					}
					cl.mail_from = cmd[10:]
				}
				cl.res = "250 2.1.0 OK " +strconv.FormatInt(cl.clientID, 9)
			case strings.Index(cmd, "RCPT TO:") == 0:

				if len(cl.mail_from) == 0 {
					cl.res = "503 5.1.0 Bad syntax RCPT TO is before MAIL FROM"
					break
				}
				
                                if len(cmd) > 8 {
					rcpt_to(cl,cmd[8:])
                                }

				if cl.status == 1 {
					cl.res = "250 2.1.5 OK " +strconv.FormatInt(cl.clientID, 9)
				}
				
			case strings.Index(cmd, "QUIT") == 0:
				killClient(cl,"221 2.0.0 " + strconv.FormatInt(cl.clientID, 9) + " closing connection.")
			default:
				counter_cmd++
				cl.res = "502 5.5.1 Unrecognized command."
			}
		case 2:
		case 3:
		case 4:
			var err error
			cl.data, err = readData(cl)
                        if err != nil {
                                println(fmt.Sprintf("Read error: %v", err))
                                if err == io.EOF {
                                        return
                                }
                                if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
                                        return
                                }
                                break
                        }
			
			if cl.relay == true {
				RelayMailChan <- cl
				status := <-cl.relayNotify

				if status == 1 {
					cl.res = "250 2.0.0 OK " + cl.hash + " " + strconv.FormatInt(cl.clientID, 9)
					cl.state = MAIL_CMD
				} else if status == 500 {
					cl.res = "554 Error: transaction failed"
					cl.state = MAIL_EXIT
				} else {
					cl.res = "421 SMTP RELAY Error connect: "+Config["SMTP_RELAY"]
					cl.state = MAIL_EXIT
				}
			} else if cl.status == 1 && cl.state == 4 { 
				WriteMailChan <- cl
				status := <-cl.savedNotify
				
				if status == 1 {
					cl.res = "250 2.0.0 OK " + cl.hash + " " + strconv.FormatInt(cl.clientID, 9)
					cl.state = MAIL_CMD
				} else if status == 500 {
					cl.res = "554 Error: queue"
					cl.state = MAIL_EXIT
				} else {
					cl.res = "554 Error: transaction failed"
					cl.state = MAIL_EXIT
				}
			}

		case 5:
			//killClient(cl,cl.res)
		case 6:
			var tlsConn *tls.Conn
			tlsConn = tls.Server(cl.conn, TLSconfig)
			err := tlsConn.Handshake()
			if err == nil {
				cl.conn = net.Conn(tlsConn)
				cl.bufin = bufio.NewReader(cl.conn)
				cl.bufout = bufio.NewWriter(cl.conn)
				cl.tls_on = true
			} else {
				log.Print(fmt.Sprintf("Could not TLS handshake:%v", err))
			}
			cl.state = 1
		case 8:
		case 550:
			killClient(cl,"550 5.7.1 Relaying denied")
		case 551:
			cl.res = "550 5.1.1 The user does not exist"
			cl.errors++
			if ( cl.errors > cDaemon["MAX_ERRORS"] ) {
				killClient(cl,"550 Oh noo")
			} else {
				cl.state = 1
			}
		case 552:
			killClient(cl,"550 You are SPAM to me")
		}

		if cl.res != "" {
			cl.res = cl.res + "\r\n"
			cl.conn.Write([]byte(string(cl.res)))
			cl.res = ""
		}

		if cl.kill_time > 1 {
			return
		}
	}
}

// FIXME **
func readData(client *Client) (input string, err error) {
        var reply string
        var msg   string
	suffix := "\r\n.\r\n"

        for err == nil {
                client.conn.SetDeadline(time.Now().Add(timeout * time.Second))
		//reply, err = emaiReadMessage(r io.Reader) (msg *Message, err error)
                reply, err = client.bufin.ReadString('\n')

                if reply != "" {
                        input = input + reply
                        if len(input) > cDaemon["MAX_SIZE"] {
                                err = errors.New("Maximum DATA size exceeded (" + strconv.Itoa(cDaemon["MAX_SIZE"]) + ")")
                                return input, err
                        }
                        if client.subject == "" && (len(reply) > 8) {
                                test := strings.ToUpper(reply[0:9])
                                if i := strings.Index(test, "SUBJECT: "); i == 0 {
                                        // first line with \r\n 
                                        client.subject = reply[9:]
                                }
                        } else if strings.HasSuffix(client.subject, "\r\n") {
                                // chop off the \r\n
                                client.subject = client.subject[0 : len(client.subject)-2]
                                if (strings.HasPrefix(reply, " ")) || (strings.HasPrefix(reply, "\t")) {
                                        // subject is multi-line 
                                        client.subject = client.subject + reply[1:]
                                }
                        } else {
				msg = msg + reply
			}
                }

                if err != nil { break }
                if strings.HasSuffix(input, suffix) { break }
        }

        //client.mail_con = msg // Mail content
	client.data = input

	if Config["CHECK_SPAMC"] == "1" && ! client.auth {
		spam(client)
	}
	
	// FIXME => net/mail : Peta cuando el MailAddress devuelve error
        my_msg, err := mail.ReadMessage(bytes.NewBuffer([]byte(client.data)))

        if err != nil {
                log.Fatalln("Failed parsing message: %v", err)
		killClient(client,"500 Failed parsing messag")
		return
	}
	
	for i,k := range my_msg.Header {
		client.headers[i] = strings.Join(k, " ")
	}

        body, err := ioutil.ReadAll(my_msg.Body)
        if err != nil {
                //fmt.Println("test #%d: Failed reading body: %v", i, err)
                log.Fatal("Body error")
	}

	client.mail_con = string(body)

        return input, err
}

func readSmtp(client *Client) (input string, err error) {
        var reply string
        suffix := "\r\n"

        for err == nil {
                client.conn.SetDeadline(time.Now().Add(timeout * time.Second))
                reply, err = client.bufin.ReadString('\n')
                if reply != "" {
                        input = input + reply
                        if len(input) > cDaemon["MAX_SIZE"] {
                                err = errors.New("Maximum DATA size exceeded (" + strconv.Itoa(cDaemon["MAX_SIZE"]) + ")")
                                return input, err
                        }
		}

                if err != nil { break }
                if strings.HasSuffix(input, suffix) { break }
        }

	input = strings.Trim(input, " \n\r")

        return input, err
}

func killClient(cl *Client,msg string) {
        cl.kill_time = time.Now().Unix()
	cl.state = MAIL_EXIT
	cl.res = msg
}

func closeClient(cl *Client) {
	cl.conn.Close()
        <-sem // Done; enable next client to run.
}

func greeting(cl *Client) {
	cl.res =
		"250-" + Config["HOSTNAME"] + " Uluba-babula, [" + string(cl.addr) + "]" + "\r\n" +
		"250-SIZE " + strconv.Itoa(cDaemon["MAX_SIZE"]) + "\r\n" +
		"250-PIPELINING\r\n" +
		"250-8BITMIME\r\n"

	if ! cl.tls_on {
                cl.res = cl.res + "250-STARTTLS\r\n"
        }

	cl.res = cl.res + "250 AUTH PLAIN CRAM-MD5"
}

func rcpt_to(cl *Client,rcpt_to string) {
	_,err := mail.ParseAddress(rcpt_to)
	if err != nil {
		cl.res = "501 could not parse your mail from command"
		return
	}

	rcpt_to = strings.Trim(rcpt_to," \n\r")
	rcpt_to = strings.Replace(rcpt_to, "<", "", -1)
	rcpt_to = strings.Replace(rcpt_to, ">", "", -1)
	
        s := strings.Split(rcpt_to, "@")

	if len(s) < 2 {
		cl.state = DENY_USER
		return
	}
	
        email, domain := s[0], s[1]

	cl.domain = strings.ToLower(domain)
	cl.user   = strings.ToLower(email)

        cl.domain = strings.Replace(cl.domain, "\n", "", -1)

	// Checks Domains valid RCPT && User
        if ! allowedHosts[cl.domain] && cl.auth == false {
                cl.state  = DENY_RELAY
		return
        } else if ! allowedHosts[cl.domain] {
		cl.relay_rcpt = rcpt_to
		cl.relay  = true
		cl.status = 1
                return
        } else 	if ! validUser(cl.user) {
		cl.state = DENY_USER
		return
	}
	
	rcpt_path := Config["MAILDIR"]+cl.domain+"/"+cl.user

        _, err = os.Open(rcpt_path)
        if err != nil {
		if Config["DEBUG"] == "1" {
			log.Print("RCPT_TO Error: "+cl.domain+"/"+cl.user)
		}
		cl.state = DENY_USER
		cl.status = 0
        } else {
		cl.status = 1

		if len(cl.rcpt_to) > 0 {
			cl.rcpt_to = cl.rcpt_to + "," + rcpt_to
		} else {
			cl.rcpt_to = rcpt_to
		}
		
	}
	
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

func WriteData() {
        
	for {
                cl := <-WriteMailChan

		cl.subject = mimeHeaderDecode(cl.subject)
		cl.hash = md5hex(cl.mail_from + cl.subject + strconv.FormatInt(time.Now().UnixNano(), 10))

		if cl.user == cl.mail_from && ! cl.auth { cl.savedNotify <- -1 }

		res := strings.Split(cl.rcpt_to,",")

		for i := range res {
			my_rcpt := res[i]
		        s := strings.Split(my_rcpt, "@")
			email, domain := strings.ToLower(s[0]),strings.ToLower(s[1])
			
			add_head := ""
			add_head += "Delivered-To: " + my_rcpt + "\r\n"
			add_head += "Received: from " + cl.helo + " (" + cl.helo + "  [" + cl.addr + "])\r\n"
			add_head += "   by " + Config["HOSTNAME"] + " with SMTP id " + cl.hash + "@" + Config["HOSTNAME"] + ";\r\n"
			add_head += "   " + time.Now().Format(time.RFC1123Z) + "\r\n"
			
			cl.headers["X-EMail-Server"] = Config["VERSION"]
			
			for k,v := range cl.headers {
				add_head += k + ": " + v + "\r\n"
			}
			
			cl.data = add_head + cl.mail_con
			
			real_dir := Config["MAILDIR"] + domain + "/" + email + "/"
			new_dir,_ := filepath.EvalSymlinks(real_dir)
			
			parts := strings.Split(new_dir,"/")
			leng  := len(parts)
			
			pms_user := parts[leng - 1]
			pms_domain := parts[leng - 2]
			
			// Filters EMail
			var dir_out string = filterDb(cl,pms_user,pms_domain)
			
			var my_file string = Config["MAILDIR"] + domain + "/" + email + "/Maildir/" + dir_out + "new/" +
				strconv.FormatInt(cl.clientID, 9) + "_" + cl.hash + ":2,"
			
			saveFile(cl,my_file)
		}
		
		cl.savedNotify <- 1
	}
}

func filterDb(cl *Client,pms_user string,pms_domain string) (dir_out string) {
	
	rows, err := db.Query("SELECT f.method,f.method_arg,f.value,f.out FROM control c LEFT JOIN filters f ON f.control = c.id WHERE c.pw_name = ? AND c.pw_domain = ?",pms_user,pms_domain)

	if err != nil { log.Fatal(err) }

	for rows.Next() {
		var method, method_arg, out, value string

		if err := rows.Scan(&method,&method_arg,&value,&out); err != nil {
			log.Fatal(err)
		}

		if method == "from" && strings.ToUpper(cl.headers["From"]) == strings.ToUpper(value) {
			fmt.Printf("%s %s %s %s\n",method,method_arg,value,out)
			dir_out = out + "/"
			return
		}
	}

	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
	
	return
}

// Si no se puede guardar que notifique el problema RFC
func saveFile(cl *Client,my_file string) {
	
	if Config["DEBUG"] == "1" {
		log.Print(my_file)
	}
	
	file, err := os.Create(my_file)

	if err != nil {
		log.Println(err)
		cl.savedNotify <- 500
		return
	}
	
	w := bufio.NewWriter(file)
	fmt.Fprint(w, cl.data)
	w.Flush()
	file.Close()	
}

func nullTermToStrings(b []byte) (s []string) {
        for _, x := range bytes.Split(b, []byte{0}) {
                s = append(s, string(x))
        }
        if len(s) > 0 && s[len(s)-1] == "" {
                s = s[:len(s)-1]
        }
        return
}

func AuthFail(cl *Client,msg string) {
	cl.res = "535 " + msg
	cl.state = MAIL_EXIT
	cl.kill_time = time.Now().Unix()
	banHost(cl.addr)	
}

func AuthPlain(cl *Client,auth_b64 string) {
	arr := nullTermToStrings([]byte(fromBase64(auth_b64)))
	
	// El 1 elemento es null
        login := strings.Split(arr[1], "@")

	// login && passwd no vacios
        if validHost(login[1]) == "" || len(arr) < 3 {
		AuthFail(cl,"PLAIN Authentication failed")
		return
        }
	
	var (
		id int
		status int
		pw_dir string
		pw_passwd string
	)

	sqlerr := db.QueryRow("SELECT id,pw_passwd,pw_dir,status FROM control WHERE pw_name = ? AND pw_domain = ? AND pw_clear_passwd = ? LIMIT 1", login[0],login[1],arr[2]).Scan(&id,&pw_passwd,&pw_dir,&status)

	switch {
	case sqlerr == sql.ErrNoRows:
                AuthFail(cl,"PLAIN Authentication failed")
	case sqlerr != nil:
                AuthFail(cl,"PLAIN Authentication failed")
	default:
		if Config["DEBUG"] == "1" {
			log.Printf("PMS: %s %s %d\n", pw_passwd,pw_dir,status)
		}
		cl.res = "235 PLAIN Authentication successful for: "+arr[1]
                cl.auth = true
		cl.state = 1
	}

}

func AuthMD5(cl *Client) {
	str := toBase64(fmt.Sprintf("<%x.%x@%s>", cl.hash , time.Now().Unix(), Config["HOSTNAME"]))

        cl.res = "334 " + str + "\r\n"
        cl.conn.Write([]byte(string(cl.res)))
	
        my_buf := make([]byte, RECV_BUF_LEN)
        _, err := cl.conn.Read(my_buf)
        if err != nil {
                println("Error reading:", err.Error())
		return
        }

	input := string(bytes.Trim(my_buf, "\x00"))
	
	input = strings.Replace(input,"\r\n","",-1)

	arr := strings.Split(fromBase64(input), " ")
	login := strings.Split(arr[0],"@")

	var pw_clear_passwd string

	sqlerr := db.QueryRow("SELECT pw_clear_passwd FROM control WHERE pw_name = ? AND pw_domain = ? LIMIT 1", login[0],login[1]).Scan(&pw_clear_passwd)
	
        switch {
	case sqlerr == sql.ErrNoRows:
                AuthFail(cl,"CRAM-MD5 Authentication failed")		
		return
	case sqlerr != nil:
                AuthFail(cl,"CRAM-MD5 Authentication failed")
		return
        }

	d := hmac.New(md5.New, []byte(pw_clear_passwd))
	d.Write([]byte(fromBase64(str)))
	s := make([]byte, 0, d.Size())

	challenge := toBase64(fmt.Sprintf("%s %x", arr[0], d.Sum(s)))

	if input == challenge {
		cl.res = "235 CRAM-MD5 Authentication successful for:"+arr[0]
		cl.auth = true
		cl.state = 1
	} else {
                AuthFail(cl,"CRAM-MD5 Authentication failed for:"+arr[0])		
	}
	
}

func RelayMail() {

	for {
		cl := <-RelayMailChan
		
		c, err := smtp.Dial(Config["SMTP_RELAY"])
		
		if err != nil {
			log.Println(err)
			cl.relayNotify <- -1
		}
		

		c.Mail(cl.mail_from)
		c.Rcpt(cl.relay_rcpt)

		// Send the email body
		wc, err := c.Data()
		
		if err != nil {
			log.Println(err)
			cl.relayNotify <- 500
		}
		
		defer wc.Close()
		
		buf := bytes.NewBufferString(cl.data)
		
		if _, err = buf.WriteTo(wc); err != nil {
			log.Println(err)
			cl.relayNotify <- 500
		}

		cl.relayNotify <- 1
	}
}

func validateEmailData(client *Client) (user string, host string, addr_err error) {
        if user, host, addr_err = extractEmail(client.mail_from); addr_err != nil {
                return user, host, addr_err
        }
        client.mail_from = user + "@" + host
        if user, host, addr_err = extractEmail(client.rcpt_to); addr_err != nil {
                return user, host, addr_err
        }
        client.rcpt_to = user + "@" + host
        // check if on allowed hosts
        if allowed := allowedHosts[host]; !allowed {
                return user, host, errors.New("invalid host:" + host)
        }
        return user, host, addr_err
}

func extractEmail(str string) (name string, host string, err error) {
        re, _ := regexp.Compile(`<(.+?)@(.+?)>`) // go home regex, you're drunk!
        if matched := re.FindStringSubmatch(str); len(matched) > 2 {
                host = validHost(matched[2])
                name = matched[1]
        } else {
                if res := strings.Split(str, "@"); len(res) > 1 {
                        name = res[0]
                        host = validHost(res[1])
                }
        }
        if host == "" || name == "" {
                err = errors.New("Invalid address, [" + name + "@" + host + "] address:" + str)
        }
        return name, host, err
}

func validHost(host string) string {
        host = strings.Trim(host, " ")
        re, _ := regexp.Compile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)
        if re.MatchString(host) {
                return host
        }
        return ""
}

func validUser(user string) (bool) {
        re, _ := regexp.Compile(`^\w+$`)
	if re.MatchString(user) {
		return true
	}
	return false
}

func md5hex(str string) string {
        h := md5.New()
        h.Write([]byte(str))
        sum := h.Sum([]byte{})
        return hex.EncodeToString(sum)
}

func fromBase64(data string) string {
        buf := bytes.NewBufferString(data)
        decoder := base64.NewDecoder(base64.StdEncoding, buf)
        res, _ := ioutil.ReadAll(decoder)
        return string(res)
}

func toBase64(data string) string {
	str := base64.StdEncoding.EncodeToString([]byte(data))
        return string(str)
}

// Decode strings in Mime header format
// eg. =?ISO-2022-JP?B?GyRCIVo9dztSOWJAOCVBJWMbKEI=?=
func mimeHeaderDecode(str string) string {
        reg, _ := regexp.Compile(`=\?(.+?)\?([QBqp])\?(.+?)\?=`)
        matched := reg.FindAllStringSubmatch(str, -1)
        var charset, encoding, payload string
        if matched != nil {
                for i := 0; i < len(matched); i++ {
                        if len(matched[i]) > 2 {
                                charset = matched[i][1]
                                encoding = strings.ToUpper(matched[i][2])
                                payload = matched[i][3]
                                switch encoding {
                                case "B":
                                        str = strings.Replace(str, matched[i][0], mailTransportDecode(payload, "base64", charset), 1)
                                case "Q":
                                        str = strings.Replace(str, matched[i][0], mailTransportDecode(payload, "quoted-printable", charset), 1)
                                }
                        }
                }
        }
        return str
}

// decode from 7bit to 8bit UTF-8
// encoding_type can be "base64" or "quoted-printable"
func mailTransportDecode(str string, encoding_type string, charset string) string {
        if charset == "" {
                charset = "UTF-8"
        } else {
                charset = strings.ToUpper(charset)
        }
        if encoding_type == "base64" {
                str = fromBase64(str)
        } else if encoding_type == "quoted-printable" {
                str = fromQuotedP(str)
        }
        if charset != "UTF-8" {
                charset = fixCharset(charset)
                // eg. charset can be "ISO-2022-JP"
                convstr, err := iconv.Conv(str, "UTF-8", charset)
                if err == nil {
                        return convstr
                }
        }
        return str
}

func fromQuotedP(data string) string {
        buf := bytes.NewBufferString(data)
        decoder := qprintable.NewDecoder(qprintable.BinaryEncoding, buf)
        res, _ := ioutil.ReadAll(decoder)
        return string(res)
}

func fixCharset(charset string) string {
        reg, _ := regexp.Compile(`[_:.\/\\]`)
        fixed_charset := reg.ReplaceAllString(charset, "-")
        // Fix charset
        // borrowed from http://squirrelmail.svn.sourceforge.net/viewvc/squirrelmail/trunk/squirrelmail/include/languages.php?revision=13765&view=markup
        // OE ks_c_5601_1987 > cp949
        fixed_charset = strings.Replace(fixed_charset, "ks-c-5601-1987", "cp949", -1)
        // Moz x-euc-tw > euc-tw
        fixed_charset = strings.Replace(fixed_charset, "x-euc", "euc", -1)
        // Moz x-windows-949 > cp949
        fixed_charset = strings.Replace(fixed_charset, "x-windows_", "cp", -1)
        // windows-125x and cp125x charsets
        fixed_charset = strings.Replace(fixed_charset, "windows-", "cp", -1)
        // ibm > cp
        fixed_charset = strings.Replace(fixed_charset, "ibm", "cp", -1)
        // iso-8859-8-i -> iso-8859-8
        fixed_charset = strings.Replace(fixed_charset, "iso-8859-8-i", "iso-8859-8", -1)
        if charset != fixed_charset {
                return fixed_charset
        }
        return charset
}

func banHost(host string) {
	s := strings.Split(host, ":")

	if bannedHosts[s[0]] == 0 {
		bannedHosts[s[0]] = 1
	} else if ( bannedHosts[s[0]] == cDaemon["BAN_LIMIT"] - 1 ) {
		bannedHosts[s[0]] = int(time.Now().Unix()) + cDaemon["BAN_TIME"]
	} else {
		bannedHosts[s[0]] = bannedHosts[s[0]] + 1
	}
	
	log.Printf("Banned: %s - %d",s[0],bannedHosts[s[0]])
}

func ValidsRCPT() {
        rows, err := db.Query("SELECT dominio FROM domains WHERE estado = 1")
	
	if err != nil { log.Fatalln(err) }
	
	for rows.Next() {
		var domain string
		
		if err := rows.Scan(&domain); err != nil {
			log.Fatal(err)
		}
		allowedHosts[domain] = true
	}
	
	if err := rows.Err(); err != nil {
		log.Fatalln(err)
	}
}
