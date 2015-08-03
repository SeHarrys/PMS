package main

import (
	"bytes"
	"io"
	"crypto/sha1"
	"crypto/md5"
	"crypto/hmac"
	"database/sql"
	"fmt"
	"time"
	"log"
	"strings"
	_"github.com/go-sql-driver/mysql"
)

func Auth(cl *Client,input string) {
	auth_method := input[5:]
	
	switch {
	case AuthMethods["CRAM-MD5"] == true, strings.Index(auth_method,"CRAM-MD5") == 0:
		AuthMD5(cl)
	case AuthMethods["PLAIN"] == true, strings.Index(auth_method,"PLAIN") == 0:
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
	
}

func AuthFail(cl *Client,msg string) {
	cl.res = "535 " + msg
	//cl.kill_time = time.Now().Unix()
	banHost(cl.addr)
}

// Auth PLAIN only via TLS
func AuthPlain(cl *Client,auth_b64 string) {
	arr := nullTermToStrings([]byte(fromBase64(auth_b64)))

	if len(arr) < 3 {
		AuthFail(cl,"PLAIN Authentication failed")
		return
	}

	// El 1 elemento es null
        login := strings.Split(arr[1], "@")
	
	// login && passwd no vacios
        if len(login) != 2 {
		AuthFail(cl,"PLAIN Authentication failed")
		return
        }

	h := sha1.New()
	io.WriteString(h,arr[2])
	arr[2] = fmt.Sprintf("%x", h.Sum(nil))
	
	var (
		id int
		status int
		pw_dir string
		pw_passwd string
	)

	sqlerr := db.QueryRow("SELECT id,pw_passwd,pw_dir,status FROM control WHERE pw_name = ? AND pw_domain = ? AND pw_passwd = ? LIMIT 1",
		              login[0],login[1],arr[2]).Scan(&id,&pw_passwd,&pw_dir,&status)

	switch {
	case sqlerr == sql.ErrNoRows, sqlerr != nil:
                AuthFail(cl,"PLAIN Authentication failed")
	default:
		if Config.C.Debug == true {
			log.Printf("PMS: %s %s %d\n", pw_passwd,pw_dir,status)
		}
		cl.res = "235 PLAIN Authentication successful for: "+arr[1]
                cl.auth = true
		cl.state = 1
	}
	
}

// Auth CRAM-MD5
// Como generamos la semilla en cada transaccion se usa pw_clear_passwd para tener el passwd , mejor usar PLAIN via TLS o DIGEST-MD5
func AuthMD5(cl *Client) {
	str := toBase64(fmt.Sprintf("<%x.%x@%s>", cl.hash , time.Now().Unix(), Config.C.Host))

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

	if len(login) != 2 {
		AuthFail(cl,"CRAM-MD5 Authentication failed")
		return
	}

	var pw_clear_passwd string

	sqlerr := db.QueryRow("SELECT pw_clear_passwd FROM control WHERE pw_name = ? AND pw_domain = ? LIMIT 1", login[0],login[1]).Scan(&pw_clear_passwd)

        switch {
	case sqlerr == sql.ErrNoRows, sqlerr != nil:
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

// Auth DIGEST-MD5
func AuthDigestMD5 (cl *Client,b64 string) {

}

// Auth GSSAPI

func nullTermToStrings(b []byte) (s []string) {
	for _, x := range bytes.Split(b, []byte{0}) {
		s = append(s, string(x))
	}
	if len(s) > 0 && s[len(s)-1] == "" {
		s = s[:len(s)-1]
	}
	return
}
