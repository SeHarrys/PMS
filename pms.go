/*** PMS

 Redis stats
***/

package main

import (
	"bytes"
	"bufio"
	"crypto/tls"
	"crypto/rand"
	"database/sql"
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
	"strconv"
	"strings"
	"runtime"
	"code.google.com/p/gcfg"
	_"github.com/go-sql-driver/mysql"
)

type Client struct {
	IP	    []byte // IPv4 4bytes - IPv6 16bytes
	host        string
	auth        bool
        state       int
	status      int
        helo        string
	mail_to     string
        mail_from   string
	mail_con    string           // Mail content
        rcpt_to     string
	rcpts       map[string]string
	my_rcpt     string           // Actual RCPT
	rcpts_count int              // Stupid but rcpts duplicates...
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
var allowedHosts = make(map[string]bool)
var bannedHosts = make(map[string]int)
var Plugins = make(map[string]bool)

var clientID int64
var sem chan int                  // currently active clients

var WriteMailChan chan *Client    // Channel WriteMail
var RelayMailChan chan *Client    // Channel RelayMail
var Version = "PMS 001"
var Config Cfg

type Daemon struct {
	LimitConn int // Max connections
	TLSconfig *tls.Config
	bannedHosts map[string]int
}

func main() {
        log.Printf("%s - Go %s (%s/%s) - CPUs %d",Version,runtime.Version(),runtime.GOOS,runtime.GOARCH,runtime.NumCPU())

	var cfgFile = "pms.conf"

	if os.Getenv("PMS_CONFIG") != "" {
		cfgFile = os.Getenv("PMS_CONFIG")
	}
	
	err := gcfg.ReadFileInto(&Config, cfgFile)

	if err != nil {
		fmt.Printf("%v",err)
	}

	// SET Plugins
	plgns := strings.Split(Config.C.Plugs,":")
	for plg := range plgns {
		Plugins[plgns[plg]] = true
	}

	// Enabled TLS
	if Config.Daemon.Tls == true {
		cert, err := tls.LoadX509KeyPair("./pms-cert.pem", "./pms-cert.key")
		if err != nil {
			log.Fatalln("Error: tls.LoadX509KeyPair")
		}
		TLSconfig = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.VerifyClientCertIfGiven, ServerName: Config.C.Host }
		TLSconfig.Rand = rand.Reader
	}

	timeout = time.Duration(Config.Daemon.Timeout)

	// init MySQL
	db, err = sql.Open("mysql", Config.Db.User + ":" + Config.Db.Pass + Config.Db.Host + "/" + Config.Db.Name)
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
	
        WriteMailChan = make(chan *Client, 10)
	RelayMailChan = make(chan *Client, 10)
	
	for i := 0; i < 10; i++ {
                go WriteData()
        }

	for i := 0; i < 10; i++ {
		go RelayMail()
	}
	
	srv, err := net.Listen("tcp",Config.Daemon.Listen)

	if err != nil {
		log.Fatalln("Error Listen :", err.Error())
	} else {
		Log("Listen: " + Config.Daemon.Listen)
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
		        rcpts:       make(map[string]string),
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
		fmt.Printf("Sesiones Abiertas: %d\n",clientID);
		
		time.Sleep(1800 * time.Second)

		for k,v := range bannedHosts {
			if v > Config.Smtp.Banlimit && int(time.Now().Unix()) > v {
				fmt.Printf("Limpiamos: %s - %d\n",k,v)
				delete(bannedHosts,k)
			}
		}

		ValidsRCPT()
	}
}

func Parser(cl *Client) {
        defer closeClient(cl)

	if Config.C.Debug == true {
		Log("Incoming: "+cl.addr)
	}
	
	if Plugins["earlytalk"] == true {
		if EarlyCheck := EarlyTalker(cl); EarlyCheck == 0 {
			cl.res = "550 Connecting host started transmitting before SMTP greeting\r\n"
			cl.conn.Write([]byte(string(cl.res)))
			return
		}
	}

	var counter_cmd int

	cl.res = "220 " + Config.C.Host + " ESMTP " + strconv.FormatInt(cl.clientID, 9) + " " + Version + "\r\n"
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
				if len(cl.mail_from) == 0 || len(cl.rcpts) == 0 {
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
					if ! cl.tls_on {
						cl.res = "502 Auth PLAIN require STARTTLS"
						break;
					}
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
					cl.res = "504 5.5.1 Undefinied authentication method"
					cl.errors++
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
				
				if cl.rcpts_count > Config.Smtp.Maxrcpts {
					killClient(cl,"452 4.5.3 To many recipient")
					break
				}
				
				if len(cl.mail_from) == 0 {
					cl.res = "503 5.1.0 Bad syntax RCPT TO is before MAIL FROM"
					break
				}

				rcpt_to(cl,cmd[8:])
				
				if cl.status == 1 {
					cl.res = "250 2.1.5 OK " +strconv.FormatInt(cl.clientID, 9)
				} else if cl.status == 2 {
					cl.res = "250 2.1.5 OK " +strconv.FormatInt(cl.clientID, 9)+ " but rcpt_to is repeat"
				} else if cl.status == 3 {
					cl.res = "250 2.1.5 OK " +strconv.FormatInt(cl.clientID, 9)+ " relay"
				} else {
					Log("RCPT TO: "+cmd[8:])
					cl.res = "550 5.1.1 The user does not exist"
					cl.errors++
				}

			case strings.Index(cmd, "QUIT") == 0:
				killClient(cl,"221 2.0.0 " + Config.C.Host + " closing connection.")
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
			
			for i := range cl.rcpts {
				cl.my_rcpt = i

				if cl.rcpts[i] == "relay" {
					RelayMailChan <- cl
					status := <-cl.relayNotify
					
					if status == 1 {
						cl.res = "250 2.0.0 OK " + cl.hash + " " + strconv.FormatInt(cl.clientID, 9)
						cl.state = MAIL_CMD
					} else if status == 500 {
						cl.res = "554 Error: transaction failed"
						cl.state = MAIL_EXIT
					} else {
						cl.res = "421 SMTP RELAY Error connect: " + Config.C.Relay
						cl.state = MAIL_EXIT
					}
				} else {
					WriteMailChan <- cl
					status := <-cl.savedNotify
					
					if status == 1 {
						cl.res = "250 2.0.0 OK " + cl.hash + " " + strconv.FormatInt(cl.clientID, 9)
						cl.state = MAIL_CMD
					} else if status == 452 {
						cl.res = "452 Error: message temporarily denied"
						cl.state = MAIL_CMD
					} else if status == 500 {
						cl.res = "554 Error: queue"
						cl.state = MAIL_EXIT
					} else {
						cl.res = "554 Error: transaction failed"
						cl.state = MAIL_EXIT
					}
				}
			}
			
		case 5:
			break
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
		case 552:
			killClient(cl,"550 You are SPAM to me")
		}

		if Config.C.Debug == true {
			Log(cl.res)
		}
		
		if ( cl.errors >= Config.Smtp.Maxerrors ) {
			killClient(cl,"221 Oh no to many errors")
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
                        if len(input) > Config.Smtp.Maxsize {
                                err = errors.New("Maximum DATA size exceeded (" + strconv.Itoa(Config.Smtp.Maxsize) + ")")
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

	client.data = input
	
	if Plugins["spamc"] == true && ! client.auth {
		var status bool

		// Plugins : whitelist hacer bucle tipo perl
		if Plugins["whitelist"] == true {
			status = WhiteList(client)
		}
		
		if status == false {
			Spamc(client)
		}
	}
	
	// FIXME => net/mail : Peta cuando el MailAddress devuelve error
        my_msg, err := mail.ReadMessage(bytes.NewBuffer([]byte(client.data)))

        if err != nil {
                log.Printf("Failed parsing message: %v", err)
		killClient(client,"500 Failed parsing message")
		return
	}
	
	for i,k := range my_msg.Header {
		client.headers[i] = strings.Join(k, " ")
	}

        body, err := ioutil.ReadAll(my_msg.Body)
        if err != nil {
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
                        if len(input) > Config.Smtp.Maxsize {
                                err = errors.New("Maximum DATA size exceeded (" + strconv.Itoa(Config.Smtp.Maxsize) + ")")
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
		"250-" + Config.C.Host + " Uluba-babula, [" + string(cl.addr) + "]" + "\r\n" +
		"250-SIZE " + strconv.Itoa(Config.Smtp.Maxsize) + "\r\n" +
		"250-PIPELINING\r\n" +
		"250-8BITMIME\r\n"

	if ! cl.tls_on {
                cl.res = cl.res + "250-STARTTLS\r\n"
        }

	cl.res = cl.res + "250 AUTH PLAIN CRAM-MD5"
}

func WriteData() {
        
	for {
                cl := <-WriteMailChan

		cl.subject = mimeHeaderDecode(cl.subject)
		cl.hash = md5hex(cl.mail_from + cl.subject + strconv.FormatInt(time.Now().UnixNano(), 10))

		if cl.user == cl.mail_from && ! cl.auth { cl.savedNotify <- -1 }

		my_rcpt := cl.my_rcpt
		s := strings.Split(my_rcpt, "@")
		email, domain := strings.ToLower(s[0]),strings.ToLower(s[1])
		
		add_head := ""
		add_head += "Delivered-To: " + my_rcpt + "\r\n"
		
		if Config.Queue.Hidereceived == true {
			add_head += "Received: from localhost\r\n"
		} else {
			add_head += "Received: from " + cl.helo + " (" + cl.helo + "  [" + cl.addr + "])\r\n"
		}
		
		add_head += "   by " + Config.C.Host + " with SMTP id " + cl.hash + "@" + Config.C.Host + ";\r\n"
		add_head += "   " + time.Now().Format(time.RFC1123Z) + "\r\n"
		
		cl.headers["X-EMail"] = Version
		
		for k,v := range cl.headers {
			add_head += k + ": " + v + "\r\n"
		}
		
		cl.data = add_head + cl.mail_con
		
		real_dir := Config.Queue.Maildir + domain + "/" + email + "/"
		new_dir,_ := filepath.EvalSymlinks(real_dir)
		
		parts := strings.Split(new_dir,"/")
		leng  := len(parts)
		
		pms_user := parts[leng - 1]
		pms_domain := parts[leng - 2]
		
		// Filters EMail
		var dir_out string = filterDb(cl,pms_user,pms_domain)
		
		var my_file string = Config.Queue.Maildir + domain + "/" + email + "/Maildir/" + dir_out + "new/" +
			strconv.FormatInt(cl.clientID, 9) + "_" + cl.hash + ":2,"
		
		saveFile(cl,my_file)
		
		cl.savedNotify <- 1
	}
}

func filterDb(cl *Client,pms_user string,pms_domain string) (dir_out string) {
	dir_out = ""
	
	rows, err := db.Query("SELECT f.method,f.method_arg,f.value,f.out FROM control c LEFT JOIN filters f ON f.control = c.id WHERE c.pw_name = ? AND c.pw_domain = ?",pms_user,pms_domain)

	if err != nil {
		return
	}

	for rows.Next() {
		var method, method_arg, out, value string

		if err := rows.Scan(&method,&method_arg,&value,&out); err != nil {
			return
		}

		if method == "from" && strings.ToUpper(cl.headers["From"]) == strings.ToUpper(value) {
			if Config.C.Debug == true {
				//Log(fmt.Printf("Filter DB: %s %s %s %s\n",method,method_arg,value,out))
			}
				dir_out = out + "/"
			return
		}
	}

	if err := rows.Err(); err != nil {
		return
	}
	
	return
}

// Si no se puede guardar que notifique el problema RFC
func saveFile(cl *Client,my_file string) {
	
	if Config.C.Debug == true {
		Log(my_file)
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
			log.Println(err)
			cl.relayNotify <- -1
		}
		

		c.Mail(cl.mail_from)
		c.Rcpt(cl.my_rcpt)

		// Send the email body
		wc, err := c.Data()
		//defer wc.Close()
		
		if err != nil {
			log.Println(err)
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
