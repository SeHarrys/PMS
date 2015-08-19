package main

import (
	"bytes"
	"errors"
	"time"
	"crypto/rand"
	"crypto/tls"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"log"
	"strconv"
	"io"
	"io/ioutil"
	"fmt"
	"os"
	"path/filepath"
	//"runtime"
	"bufio"
)

type Daemon struct {
	clientID    int64
	listen      string
	timeout     time.Duration
	LimitConn   int            // Max connections
	TLS         bool
	TLSconfig   *tls.Config
	allowedHosts map[string]int
	bannedHosts  map[string]int
	AuthMethods  map[string]bool
	Plugins      map[string]bool
	WriteMailChan chan *Client // Channel WriteMail
	RelayMailChan chan *Client // Channel RelayMail
}

func (dmn *Daemon) New() {

	// Enabled TLS
	if dmn.TLS == true {
		cert, err := tls.LoadX509KeyPair("./pms-cert.pem", "./pms-cert.key")
		if err != nil {
			log.Fatalln("Error: tls.LoadX509KeyPair")
		}
		dmn.TLSconfig = &tls.Config{Certificates: []tls.Certificate{cert}, ClientAuth: tls.VerifyClientCertIfGiven, ServerName: Config.C.Host}
		dmn.TLSconfig.Rand = rand.Reader
	}

	// SET Auth Methods
	if Config.Smtp.Authmethods != "" {
		authm := strings.Split(Config.Smtp.Authmethods, ":")
		for auth := range authm {
			dmn.AuthMethods[authm[auth]] = true
			Log(0, "[OK] Auth method: "+authm[auth])
		}
	}

	// SET Plugins
	if Config.C.Plugins != "" {
		plgns := strings.Split(Config.C.Plugins, ":")
		for plg := range plgns {
			dmn.Plugins[plgns[plg]] = true
			Log(0, "[OK] Plugin: "+plgns[plg])
		}
	}

	dmn.WriteMailChan = make(chan *Client, 20)
	dmn.RelayMailChan = make(chan *Client, 10)
	
	// Channels
	for i := 0; i < 20; i++ {
		go dmn.WriteData()
	}

	for i := 0; i < 10; i++ {
		go dmn.RelayMail()
	}
	
	dmn.Listen()	
}

func (dmn *Daemon) Listen() {
        srv, err := net.Listen("tcp", dmn.listen )

	if err != nil {
		log.Fatalln("Error Listen :", err.Error())
	} else {
		Log(0, "Listen: " + dmn.listen )
	}

	for {
		conn, err := srv.Accept()
		if err != nil {
			log.Print("Error client :", err.Error())
			continue
		}

		sem <- 1
		go dmn.Parser(&Client{
			conn:        conn,
			addr:        conn.RemoteAddr().String(),
			headers:     make(map[string]string),
			rcpts:       make(map[string]string),
			time:        time.Now().Unix(),
			bufin:       bufio.NewReader(conn),
			bufout:      bufio.NewWriter(conn),
			clientID:    dmn.clientID,
			savedNotify: make(chan int),
			relayNotify: make(chan int),
		})
		dmn.clientID++
	}
	
}

func (dmn *Daemon) greeting(cl *Client) {
	var Greet bytes.Buffer

	Greet.WriteString("250-" + Config.C.Host + " Uluba-babula, [" + cl.addr + "]" + "\r\n")
	Greet.WriteString("250-SIZE " + strconv.Itoa(Config.Smtp.Maxsize) + "\r\n")
	//Greet.WriteString("250-PIPELINING\r\n")

	if dmn.TLS == true && !cl.tls_on {
			Greet.WriteString("250-STARTTLS\r\n")
	}

	if len(Config.Smtp.Authmethods) > 0 {
		Greet.WriteString("250-AUTH " + strings.Replace(Config.Smtp.Authmethods, ":", " ", -1) + "\r\n")
	}

	Greet.WriteString("250 8BITMIME")
	
	cl.res = Greet.String()
}

func (dmn *Daemon) Parser(cl *Client) {
	defer dmn.closeClient(cl)
	
	if Config.C.Debug == true {
		Log(cl.clientID, "Incoming: " + cl.addr )
	}
	
	if dmn.Plugins["earlytalk"] == true {
		if EarlyCheck := EarlyTalker(cl); EarlyCheck == false {
			cl.res = "550 Connecting host started transmitting before SMTP greeting\r\n"
			cl.conn.Write([]byte(cl.res))
			return
		}
	}
	
	var counter_cmd int
	
	cl.res = "220 " + Config.C.Host + " ESMTP " + strconv.FormatInt(cl.clientID, 9) + " " + Version + "\r\n"
	cl.state = 1
	cl.conn.Write([]byte(cl.res))
	
	for i := 0; i < 24; i++ {
		
		if bannedHosts[cl.addr] > 3 {
			dmn.killClient(cl, "521 You are banned")
		}
		
		if counter_cmd >= Config.Smtp.Counter {
			// Prevent AUTH brute force when ignore greeting
			banHost(cl.addr)
			dmn.killClient(cl, "521 Closing connection. max unrecognized commands")
		}

	switch cl.state {
	case 1:
		input, err := dmn.readSmtp(cl)
		if err != nil {
			if err == io.EOF {
				//dmn.killClient(cl)
				return
			}
			if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
				//dmn.killClient(cl)
				return
			}
			break
		}
		if Config.C.Debug == true {
			Log(cl.clientID, input)
		}
		//input = strings.Trim(input, " \n\r")
		cmd := strings.ToUpper(input)
		switch {
		case strings.Index(cmd, "VRFY") == 0, strings.Index(cmd, "HELP") == 0:
			cl.res = "252 2.1.5 Command not supported."
			counter_cmd++
			// Oops
		case strings.Index(cmd, "EHLO") == 0, strings.Index(cmd, "HELO") == 0:
			if len(input) > 5 {
				cl.helo = input[5:]
			}
			dmn.greeting(cl)
		case strings.Index(cmd, "DATA") == 0:
			if len(cl.mail_from) == 0 || len(cl.rcpts) == 0 {
				cl.res = "503 5.1.0 Bad syntax RCPT TO and MAIL FROM not defined"
				break
			}
			cl.res = "354 go ahead"
			cl.state = MAIL_QUEUE
		case strings.Index(cmd, "STARTTLS") == 0:
			if dmn.TLS == true  {
				if cl.tls_on {
					cl.res = "502 STARTTLS is active"
					cl.state = MAIL_CMD
				} else {
					cl.res = "220 2.0.0 Go TLS"
					cl.state = MAIL_TLS
				}
			} else {
				cl.res = "252 2.1.5 Command not supported."
				counter_cmd++
			}
		case strings.Index(cmd, "NOOP") == 0:
			cl.res = "220 2.0.0 OK"
		case strings.Index(cmd, "AUTH") == 0:
			if len(Config.Smtp.Authmethods) > 0 {
				dmn.Auth(cl, input)
			} else {
				cl.res = "252 2.1.5 Command not supported."
				counter_cmd++
			}
			// Parse Mail From options ( SIZE= )
		case strings.Index(cmd, "MAIL FROM:") == 0:
			if len(cmd) > 10 {
				mycmd := cmd[10:]
				arr := strings.Fields(mycmd)
				//for k := range arr {
				//      fmt.Println(arr[k])
				//}
				_, err = mail.ParseAddress(arr[0])
				if err != nil {
					cl.res = "501 could not parse your mail from command"
					break
				}
				cl.mail_from = arr[0]
				// Ordenar debidamente
				if dmn.Plugins["spf"] == true {
					SPF := Spf{helo: cl.helo, client_ip: cl.addr, envelope: cl.mail_from}
					SPF.New()
					cl.headers["Received-SPF"] = SPF.header
				}
				cl.res = "250 2.1.0 OK " + strconv.FormatInt(cl.clientID, 9)
			} else {
				cl.res = "501 could not parse your mail from command"
				break
			}
		case strings.Index(cmd, "RCPT TO:") == 0:

			// RFC say 100 max
			if cl.rcpts_count > Config.Smtp.Maxrcpts {
				dmn.killClient(cl, "452 4.5.3 To many recipient")
				break
			}

			if len(cl.mail_from) == 0 {
				cl.res = "503 5.1.0 Bad syntax RCPT TO is before MAIL FROM"
				break
			}

			rcpt_to(cl, cmd[8:])

			if cl.status == 1 {
				cl.res = "250 2.1.5 OK " + strconv.FormatInt(cl.clientID, 9)
			} else if cl.status == 2 {
				cl.res = "250 2.1.5 OK " + strconv.FormatInt(cl.clientID, 9) + " but rcpt_to is repeat"
			} else if cl.status == 3 {
				cl.res = "250 2.1.5 OK " + strconv.FormatInt(cl.clientID, 9) + " relay"
			} else if cl.status == 4 {
				cl.res = "554 5.7.1 Authentication first, omitted"
				cl.errors++
			} else {
				cl.res = "550 5.1.1 The user does not exist"
				cl.errors++
			}
		case strings.Index(cmd, "RSET") == 0:
			for rcpt := range cl.rcpts {
				delete(cl.rcpts, rcpt)
			}
			cl.mail_from = ""
			cl.res = "250 2.0.0 OK"
		case strings.Index(cmd, "QUIT") == 0:
			dmn.killClient(cl, "221 2.0.0 "+Config.C.Host+" closing connection.")
		default:
			counter_cmd++
			cl.res = "502 5.5.1 Unrecognized command."
		}
	case 2:
	case 3:
	case 4:
		var err error
		cl.data, err = dmn.readData(cl)
		if err != nil {
			Log(cl.clientID,fmt.Sprintf("Read error: %v", err))
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
				dmn.RelayMailChan <- cl
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
				dmn.WriteMailChan <- cl
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
	case 6: // MAIL_TLS
		var tlsConn *tls.Conn
		tlsConn = tls.Server(cl.conn, dmn.TLSconfig)
		err := tlsConn.Handshake()
		if err == nil {
			cl.conn = net.Conn(tlsConn)
			cl.bufin = bufio.NewReader(cl.conn)
			cl.bufout = bufio.NewWriter(cl.conn)
			cl.tls_on = true
		} else {
			Log(cl.clientID, fmt.Sprintf("Could not TLS handshake:%v", err))
			cl.res =  "454 TLS not available due to temporary reason"
		}
		cl.state = 1
	case 8:
	case 550:
		dmn.killClient(cl, "550 5.7.1 Relaying denied")
	case 552:
		dmn.killClient(cl, "550 You are SPAM to me")
	}

	if Config.C.Debug == true {
		Log(cl.clientID, cl.res)
	}

	if cl.errors >= Config.Smtp.Maxerrors {
		dmn.killClient(cl, "221 Oh no to many errors")
	}

	if cl.res != "" {
		cl.res = cl.res + "\r\n"
		cl.conn.Write([]byte(cl.res))
		cl.res = ""
	}

		if cl.kill_time > 1 {
			return
		}
	}
	
	cl.res = "221 Oh no to many commands\r\n"
	cl.conn.Write([]byte(cl.res))
}

// FIXME
func (dmn *Daemon) readData(cl *Client) (input string, err error) {
	var reply string
	var msg string
	suffix := "\r\n.\r\n"

	for err == nil {
		cl.conn.SetDeadline(time.Now().Add(dmn.timeout * time.Second))
		//reply, err = emaiReadMessage(r io.Reader) (msg *Message, err error)
		reply, err = cl.bufin.ReadString('\n')

		if reply != "" {
			input = input + reply
			if len(input) > Config.Smtp.Maxsize {
				err = errors.New("Maximum DATA size exceeded (" + strconv.Itoa(Config.Smtp.Maxsize) + ")")
				return input, err
			}
			if cl.subject == "" && (len(reply) > 8) {
				test := strings.ToUpper(reply[0:9])
				if i := strings.Index(test, "SUBJECT: "); i == 0 {
					// first line with \r\n
					cl.subject = reply[9:]
				}
			} else if strings.HasSuffix(cl.subject, "\r\n") {
				// chop off the \r\n
				cl.subject = cl.subject[0 : len(cl.subject)-2]
				if (strings.HasPrefix(reply, " ")) || (strings.HasPrefix(reply, "\t")) {
					// subject is multi-line
					cl.subject = cl.subject + reply[1:]
				}
			} else {
				msg = msg + reply
			}
		}

		if err != nil {
			break
		}

		if strings.HasSuffix(input, suffix) {
			break
		}
	}

	cl.data = input
	
	if dmn.Plugins["spamc"] == true && !cl.auth {
		var status bool

		// Plugins: whitelist hacer bucle tipo perl
		if dmn.Plugins["whitelist"] == true {
			status = WhiteList(cl)
		}

		if status == false {
			Spamc(cl)
		}
	}

	my_msg, err := mail.ReadMessage(bytes.NewBuffer([]byte(cl.data)))

	if err != nil {
		log.Printf("Failed parsing message: %v", err)
		dmn.killClient(cl, "500 Failed parsing message")
		return
	}

	for i, k := range my_msg.Header {
		cl.headers[i] = strings.Join(k, " ")
	}

	body, err := ioutil.ReadAll(my_msg.Body)
	
	if err != nil {
		Log(cl.clientID, "Body error "+strconv.FormatInt(cl.clientID, 9))
		dmn.killClient(cl, "500 Failed parsing message")
		return
	}

	cl.mail_con = string(body)

	if Config.C.Debug {
		Log(cl.clientID, input)
	}

	return input, err
}

func (dmn *Daemon) readSmtp(cl *Client) (input string, err error) {
	var reply string
	suffix := "\r\n"

	for err == nil {
		cl.conn.SetDeadline(time.Now().Add(dmn.timeout * time.Second))
		reply, err = cl.bufin.ReadString('\n')
		if reply != "" {
			input = input + reply
			if len(input) > Config.Smtp.Maxsize {
				err = errors.New("Maximum DATA size exceeded (" + strconv.Itoa(Config.Smtp.Maxsize) + ")")
				return input, err
			}
		}

		if err != nil {
			break
		}
		if strings.HasSuffix(input, suffix) {
			break
		}
	}

	input = strings.Trim(input, " \n\r")

	//Log(cl.clientID,input)

	return input, err
}

func (dmn *Daemon) closeClient(cl *Client) {
	cl.conn.Close()
	
	if Config.C.Debug {
		Log(cl.clientID, "Closed "+cl.addr)
	}
	<-sem // Done; enable next client to run.
}

func (dmn *Daemon) killClient(cl *Client, msg string) {
	cl.kill_time = time.Now().Unix()
	cl.state = MAIL_EXIT
	cl.res = msg
}

func (dmn *Daemon) WriteData() {
	
	for {
		cl := <- dmn.WriteMailChan
		
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
		
		if dmn.Plugins["filterdb"] == true {
			dir_out = filterDb(cl, pms_user, pms_domain)
		}
		
		var my_file string = Config.Queue.Maildir + domain + "/" + email + "/Maildir/" + dir_out + "new/" +
			strconv.FormatInt(cl.clientID, 9) + "_" + cl.hash + ":2,"
		
		dmn.saveFile(cl, my_file)
		
		cl.savedNotify <- 1
	}
}

func (dmn *Daemon) saveFile(cl *Client, my_file string) {
	
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

func (dmn *Daemon) RelayMail() {

	for {
		cl := <- dmn.RelayMailChan

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

