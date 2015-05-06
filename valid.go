package main

import (
	"bytes"
        "crypto/md5"
	"encoding/base64"
        "encoding/hex"
	"errors"
	"io/ioutil"
	"time"
	"os"
	"net/mail"
	"log"
	"regexp"
	"strings"
	_"github.com/go-sql-driver/mysql"
	"github.com/sloonz/go-iconv"
	"github.com/sloonz/go-qprintable"
)

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

	cl.status = 0
	
	// Checks Domains valid RCPT && User
        if ! allowedHosts[cl.domain] && cl.auth == false {
		cl.state = DENY_USER
		return
        } else if ! allowedHosts[cl.domain] && cl.auth == true {
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
		cl.state = DENY_USER
        } else {
		cl.status = 1

		if len(cl.rcpt_to) > 0 {
			cl.rcpt_to = cl.rcpt_to + "," + rcpt_to
		} else {
			cl.rcpt_to = rcpt_to
		}
		
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
