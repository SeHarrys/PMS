package main

import(
	"time"
	"net"
	"strings"
	"fmt"
	"regexp"
	"github.com/saintienn/go-spamc"
	//"github.com/mirtchovski/clamav"
)

func EarlyTalker(cl *Client)(ret bool) {
	cl.conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	_, err := cl.bufin.ReadByte()

	if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
		ret = true
	} else {
		ret = false
	}

	return
}

func Spamc(cl *Client) {
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
	}
}

func ClamAV(cl *Client) {

}

// ToDO : whitelist per domain
func WhiteList(cl *Client)(status bool) {

	_,cldom := getMail(cl.mail_from)
	
	rows, err := db.Query("SELECT domain FROM whitelist")

	if err != nil {
		Log(cl.clientID,"Whitelist DB")
		return false
	}

	for rows.Next() {
		var domain string
		
		if err := rows.Scan(&domain); err != nil {
			return false
		}

		if cldom == strings.ToUpper(domain) {
			status = true
			return
		}
		
	}
	
	return false
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

		if Config.C.Debug == true {
			fmt.Printf("Filter DB: %s %s %s %s\n",method,method_arg,value,out)
		}

		if method == "from" {
			switch method_arg {
			case "email":
				if strings.ToUpper(cl.headers["From"]) == strings.ToUpper(value) {
					dir_out = out + "/"
					return
				}
			case "domain":
				_,domain := getMail(cl.mail_from)
				if strings.ToUpper(value) == domain {
					dir_out = out + "/"
					return
				}
			}
		} else if method_arg == "Subject" && method == "headers" {
			if re, _ := regexp.Compile(value); re.MatchString(cl.subject) {
				dir_out = out + "/"
				return
			}
		} else if method == "headers" {
			switch method_arg {
			case "List-Id":
				if cl.headers["List-Id"] == value {
					dir_out = out + "/"
					return
				}
			}
		}

		if err := rows.Err(); err != nil {
			return
		}
	}

	return
}

func FCrDNS(cl *Client) {

}
