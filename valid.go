package main

import (
	"bytes"
        "crypto/md5"
	"encoding/base64"
        "encoding/hex"
	"io/ioutil"
	"time"
	"os"
	"net/mail"
	"log"
	"fmt"
	"regexp"
	"strings"
	_"github.com/go-sql-driver/mysql"
	"github.com/sloonz/go-iconv"
	"github.com/sloonz/go-qprintable"
)

func rcpt_to(cl *Client,rcpt_to string) {
	cl.rcpts_count++
	cl.status = 0

	_,err := mail.ParseAddress(rcpt_to)
	if err != nil {
		cl.res = "501 5.1.3 could not parse your mail from command"
		cl.errors++
		return
	}

	rcpt_to = strings.Trim(rcpt_to," \n\r")
	rcpt_to = strings.Replace(rcpt_to, "<", "", -1)
	rcpt_to = strings.Replace(rcpt_to, ">", "", -1)
	
        s := strings.Split(rcpt_to, "@")

	if len(s) < 2 {
		cl.status = DENY_USER
		return
	}
	
        email, domain := s[0], s[1]

	cl.domain = strings.ToLower(domain)
	cl.user   = strings.ToLower(email)

        cl.domain = strings.Replace(cl.domain, "\n", "", -1)

	// Checks Domains valid RCPT && User
        if ! allowedHosts[cl.domain] && cl.auth == false {
		cl.status = DENY_USER
		return
        } else if ! allowedHosts[cl.domain] && cl.auth == true {
		cl.rcpts[rcpt_to] = "relay"
		cl.status = 3
                return
        } else 	if ! validUser(cl.user) {
		cl.status = DENY_USER
		return
	}
	
	rcpt_path := Config.Queue.Maildir + cl.domain + "/" + cl.user

        _, err = os.Open(rcpt_path)
        if err != nil {
		cl.status = DENY_USER
		return
        }

	if cl.rcpts[rcpt_to] != "" {
		cl.status = 2
	} else {
		cl.status = 1
		cl.rcpts[rcpt_to] = "mail"
	}
	
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
	} else if ( bannedHosts[s[0]] == Config.Smtp.Banlimit ) {
		bannedHosts[s[0]] = int(time.Now().Unix()) + Config.Smtp.Bantime
	} else {
		bannedHosts[s[0]] = bannedHosts[s[0]] + 1
	}
	
	fmt.Printf("Banned: %s - %d \n",s[0],bannedHosts[s[0]])
}

func ValidsRCPT() {
        rows, err := db.Query("SELECT dominio FROM domains WHERE estado = 1")
	
	if err != nil { log.Fatalln(err) }

	for domain := range allowedHosts {
		delete(allowedHosts, domain)
	}
	
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
