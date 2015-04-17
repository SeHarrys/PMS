/*** PMS

  - SpamAssasin : github.com/saintienn/go-spamc
  - Redis / MySQL
  - Listen on two interfaces
  - Header : Array para headers : add / del / edit
   -- Checking a : MAIL FROM && RCPT TO
  - handleSignals : ./server/camlistored/camlistored.go
  - DKIM
  - LOG : Auth brute force
  - RCPT_TO : Desde Config o DB
  - Plugins

V 001

 + Auth : PLAIN && CRAM-MD5 
 + No respeta formato \r\n al agregar las cabeceras del SPAM
 * Filters migrado qpsmtpd
 - Estructura basica para el Maildir : https://github.com/luksen/maildir/blob/master/maildir.go
 - Generar cabeceras basicas : TO / FROM / SUBJECT al parsear readData()

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
	tls_on      bool
}

var TLSconfig *tls.Config

var db *sql.DB                    // Global mysql DB
var max_size int                  // max email DATA size
var timeout time.Duration
var allowedHosts = make(map[string]bool, 16)

var sem chan int                  // currently active clients
var WriteMailChan chan *Client    // Channel WriteMail

var Config = map[string]string {
	"VERSION"    : "PMS 001",
	"CONFIG"     : "pms.conf.json",
}

var cDaemon = map[string]int {
	"MAX_SIZE" : 131072,
	"TIMEOUT"  : 60,
	"STARTTLS" : 0,
}

const (
	RECV_BUF_LEN = 1024
	MAIL_CMD     = 1
	MAIL_AUTH    = 2
	MAIL_RELAY   = 3
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

        // Domains valid RCPT                                                                                                                                               
        if arr := strings.Split(Config["RCPT_HOSTS"], ","); len(arr) > 0 {
                for i := 0; i < len(arr); i++ {
                        allowedHosts[arr[i]] = true
                }
        }

	timeout = time.Duration(cDaemon["TIMEOUT"])
	max_size = cDaemon["MAX_SIZE"]

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

	// Channels
        sem = make(chan int, 50)
        WriteMailChan = make(chan *Client, 5)
	
	for i := 0; i < 5; i++ {
                go WriteData()
        }
	
	srv, err := net.Listen("tcp",Config["LISTEN"])

	if err != nil {
		log.Fatalln("Error Listen :", err.Error())
	}

	var clientID int64
	clientID = 1

	for {
		conn, err := srv.Accept()
		if err != nil {
			print("Error client :", err.Error())
			continue
		}

                log.Print("Goroutines: "+strconv.Itoa(runtime.NumGoroutine()))

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
		})
                clientID++
	}
}
 
func Parser(cl *Client) {
        defer closeClient(cl)

	var counter_cmd int

	cl.res = "220 " + Config["HOSTNAME"] + " localhost ESMTP " + strconv.FormatInt(cl.clientID, 9) + " " + Config["VERSION"] + "\r\n"

	cl.state = 1
	cl.conn.Write([]byte(string(cl.res)))

	for i := 0; i < 16; i++ {
		if counter_cmd >= 3 {
			cl.res = "521 Closing connection. 4 unrecognized commands"
			killClient(cl)
		}
		switch cl.state {
		case 1:
                        input, err := readSmtp(cl)
                        if err != nil {
                                println(fmt.Sprintf("Read error: %v", err))
                                if err == io.EOF {
                                        // client closed the connection already
                                        return
                                }
                                if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
                                        // too slow, timeout
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
				if len(cl.mail_from) == 0 || len(cl.rcpt_to) == 0 {
                                        cl.res = "503 5.1.0 Bad syntax RCPT TO and MAIL FROM not defined"
                                        break
                                }
				cl.res = "354 go ahead"
				cl.state = MAIL_QUEUE
			case strings.Index(cmd, "STARTTLS") == 0:
                                cl.res = "220 2.0.0 Go TLS"
                                cl.state = MAIL_TLS
			case strings.Index(cmd, "AUTH") == 0:
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
                                        cl.mail_from = cmd[10:]
					//Addr,_ = mail.ParseAddress(cl.mail_from)
				}
				cl.res = "250 2.1.0 OK " +strconv.FormatInt(cl.clientID, 9)
			case strings.Index(cmd, "RCPT TO:") == 0:
				if len(cl.mail_from) == 0 {
					cl.res = "503 5.1.0 Bad syntax RCPT TO is before MAIL FROM"
					break
				}
                                if len(cmd) > 8 {
                                        cl.rcpt_to = cmd[8:]
					rcpt_to(cl)
                                }

				if cl.status == 1 {
					cl.res = "250 2.1.5 OK " +strconv.FormatInt(cl.clientID, 9)
				}
			case strings.Index(cmd, "QUIT") == 0:
				cl.res = "221 2.0.0 " + strconv.FormatInt(cl.clientID, 9) + " closing connection."
				killClient(cl)
			default:
				counter_cmd++
				cl.res = "502 5.5.1 Unrecognized command."
			}
		case 2:
			//Auth(cl)
		case 3:
			if cl.auth == true {
				Relay(cl)
			}
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
			
			if cl.status == 1 && cl.state == 4 { 
				WriteMailChan <- cl
				// wait for the save to complete
				status := <-cl.savedNotify
				
				if status == 1 {
					cl.res = "250 2.0.0 OK " + cl.hash + " " + strconv.FormatInt(cl.clientID, 9)
				} else {
					cl.res = "554 Error: transaction failed"
				}
				cl.state = 1
			} else if cl.status == 2 {
				Relay(cl)
				cl.state = 1
			}

		case 5:
			killClient(cl)
		case 6:
			var tlsConn *tls.Conn
			tlsConn = tls.Server(cl.conn, TLSconfig)
			err := tlsConn.Handshake() // not necessary to call here, but might as well
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
			cl.res = "550 5.7.1 Relaying denied"
			killClient(cl)
		case 551:
			cl.res = "550 5.1.1 The user does not exist"
			killClient(cl)
		case 552:
			cl.res = "550 You are SPAM to me"
			killClient(cl)
		}

		cl.res = cl.res + "\r\n"
		cl.conn.Write([]byte(string(cl.res)))
		cl.res = ""

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
                        if len(input) > max_size {
                                err = errors.New("Maximum DATA size exceeded (" + strconv.Itoa(max_size) + ")")
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
	
	// FIXME => net/mail : Peta cuando el MailAddress devuelve error de tal modo que se ha de convertir la estructura de otro modo....
        my_msg, err := mail.ReadMessage(bytes.NewBuffer([]byte(client.data)))

        if err != nil {
                log.Fatalln("Failed parsing message: %v", err)
	}
	
	for i,k := range my_msg.Header {
		client.headers[i] = strings.Join(k, " ")
		//fmt.Println(strings.Join(k, ", ")) //," : ",k)
	}

        body, err := ioutil.ReadAll(my_msg.Body)
        if err != nil {
                //fmt.Println("test #%d: Failed reading body: %v", i, err)
                log.Fatal("Body errror")
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
                        if len(input) > max_size {
                                err = errors.New("Maximum DATA size exceeded (" + strconv.Itoa(max_size) + ")")
                                return input, err
                        }
		}

                if err != nil { break }
                if strings.HasSuffix(input, suffix) { break }
        }

	input = strings.Trim(input, " \n\r")

        //fmt.Println("From : ",client.addr ,"recv bytes of data =", input)
        return input, err
}

func killClient(cl *Client) {
        cl.kill_time = time.Now().Unix()
}

func closeClient(cl *Client) {
	cl.conn.Close()
        <-sem // Done; enable next client to run.
}

func greeting(cl *Client) {
	cl.res =
		"250-" + Config["HOSTNAME"] + " Uluba-babula, [" + string(cl.addr) + "]" + "\r\n" +
		"250-SIZE " + strconv.Itoa(max_size) + "\r\n" +
		"250-PIPELINING\r\n" +
		"250-8BITMIME\r\n"

	if ! cl.tls_on {
                cl.res = cl.res + "250-STARTTLS\r\n"
        }

	cl.res = cl.res + "250 AUTH PLAIN CRAM-MD5"
}

func rcpt_to(cl *Client) {
	cl.rcpt_to = strings.Trim(cl.rcpt_to," \n\r")
        cl.rcpt_to = strings.Replace(cl.rcpt_to, "<", "", -1)
        cl.rcpt_to = strings.Replace(cl.rcpt_to, ">", "", -1)

        s := strings.Split(cl.rcpt_to, "@")
        email, domain := s[0], s[1]

	cl.domain = strings.ToLower(domain)
	cl.user   = strings.ToLower(email)

        cl.domain = strings.Replace(cl.domain, "\n", "", -1)

	// Domains valid RCPT
        if ! allowedHosts[cl.domain] && cl.auth == false {
                cl.state  = DENY_RELAY
                cl.status = 0
        } else if ! allowedHosts[cl.domain] {
                cl.status = 2
                return
        }

	rcpt_path := Config["MAILDIR"]+cl.domain+"/"+cl.user

        _, err := os.Open(rcpt_path)
        if err != nil {
		if Config["DEBUG"] == "1" {
			log.Print("RCPT_TO Error: "+cl.domain+"/"+cl.user)
		}
		cl.state = DENY_USER
		cl.status = 0
        } else {
		cl.status = 1
	}
}

func spam(cl *Client) {
	spam := spamc.New("127.0.0.1:783",10)
	
	reply, _ := spam.Process(cl.data) //, "saintienn")                                                                                                       

	// Si es SPAM pasa 14 lo elimina                                                                                                                   
	// Si pasa de 8 el Subject                                                                                                                       
	if reply.Vars["isSpam"] == true {
		//spam.Report()
		//cl.state = DENY_SPAM
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

		//return Qpsmtpd::DSN->relaying_denied() if $headers->get('To') eq $transaction->sender->address && ! $self->auth_user();
		if cl.user == cl.mail_from && ! cl.auth { cl.savedNotify <- -1 }

		add_head := ""
                add_head += "Delivered-To: " + cl.rcpt_to + "\r\n"
                add_head += "Received: from " + cl.helo + " (" + cl.helo + "  [" + cl.addr + "])\r\n"
                add_head += "   by " + Config["HOSTNAME"] + " with SMTP id " + cl.hash + "@" + Config["HOSTNAME"] + ";\r\n"
                add_head += "   " + time.Now().Format(time.RFC1123Z) + "\r\n"

		//cl.headers["EMail-Server"] = "PMS 0001"

		for k,v := range cl.headers {
			add_head += k + ": " + v + "\r\n"
		}

                cl.data = add_head + cl.mail_con
		
		real_dir := Config["MAILDIR"] + cl.domain + "/" + cl.user + "/"
		new_dir,_ := filepath.EvalSymlinks(real_dir)

		parts := strings.Split(new_dir,"/")
		leng  := len(parts)

		pms_user := parts[leng - 1]
		pms_domain := parts[leng - 2]

		// Filters EMail
		var control int
		_ = db.QueryRow("SELECT id FROM control WHERE pw_name = ? AND pw_domain = ?",pms_user,pms_domain).Scan(&control)

		rows, err := db.Query("SELECT f.method,f.method_arg,f.value,f.out FROM filters f WHERE f.control = ?",control)

		if err != nil { log.Fatal(err) }
		
		for rows.Next() {
			var method, method_arg, out, value string
			
			if err := rows.Scan(&method,&method_arg,&out,&value); err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%s %s %s %s\n",method,method_arg,out,value)
		}

		if err := rows.Err(); err != nil {
			log.Fatal(err)
		}

		var my_file string = Config["MAILDIR"] + cl.domain + "/" + cl.user + "/Maildir/new/" + strconv.FormatInt(cl.clientID, 9) + "_" + cl.hash + ":2,"

		if Config["DEBUG"] == "1" {
			log.Print(my_file)
		}

		file,_ := os.Create(my_file)
		w := bufio.NewWriter(file)
		fmt.Fprint(w, cl.data)	
		w.Flush()
		file.Close()

		cl.savedNotify <- 1
	}
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

func AuthPlain(cl *Client,auth_b64 string) {
	arr := nullTermToStrings([]byte(fromBase64(auth_b64)))
	
	// El 1 elemento es null
        login := strings.Split(arr[1], "@")

	// login && passwd no vacios
        if validHost(login[1]) == "" || len(arr) < 3 { 
		cl.res = "535 PLAIN Authentication failed"
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
		cl.res = "535 PLAIN Authentication failed for:"+arr[1]
		cl.status = MAIL_EXIT
	case sqlerr != nil:
		cl.res = "535 PLAIN Authentication failed"
		cl.status = MAIL_EXIT
	default:
		if Config["DEBUG"] == "1" {
			log.Print(fmt.Printf("PMS: %s %s %d\n", pw_passwd,pw_dir,status))
		}
		cl.res = "235 PLAIN Authentication successful for: "+arr[1]
                cl.auth = true
	}
	
        cl.state = 1
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

	if Config["DEBUG"] == "1" {
		println("From : ",cl.addr ,"recv bytes of data =", input)
	}

	arr := strings.Split(fromBase64(input), " ")
	login := strings.Split(arr[0],"@")

	var pw_clear_passwd string

	sqlerr := db.QueryRow("SELECT pw_clear_passwd FROM control WHERE pw_name = ? AND pw_domain = ? LIMIT 1", login[0],login[1]).Scan(&pw_clear_passwd)

        switch {
	case sqlerr == sql.ErrNoRows:
                cl.res = "535 PLAIN Authentication failed for:"+arr[1]
                cl.status = MAIL_EXIT
		return
	case sqlerr != nil:
                cl.res = "535 PLAIN Authentication failed"
                cl.status = MAIL_EXIT
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
		cl.res = "535 CRAM-MD5 authentication failed for "+arr[0]
	}
	
}

func Relay(cl *Client) {
        c, err := smtp.Dial(Config["SMTP_RELAY"])
	
        if err != nil {
                log.Println(err)
		cl.res = "421 SMTP RELAY error"
		return 
        }

        c.Mail(cl.mail_from)
        c.Rcpt(cl.rcpt_to)

        // Send the email body
        wc, err := c.Data()

        if err != nil {
		fmt.Println(err)
        }

        defer wc.Close()

        buf := bytes.NewBufferString(cl.data)

        if _, err = buf.WriteTo(wc); err != nil {
		fmt.Println(err)
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
