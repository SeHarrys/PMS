/*** PMS

 Redis stats
 SMTP or ESMTP codes

***/

package main

import (
	"code.google.com/p/gcfg"
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"time"	
)

var db *sql.DB // Global mysql DB
var allowedHosts = make(map[string]int)
//var bannedHosts = make(map[string]int)

var clientID int64
var sem chan int // currently active clients

var Version = "PMS 005"

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

	pidfile()
	// camlistored
	shutdownc := make(chan io.Closer, 1) // receives io.Closer to cleanly shut down
	go Signals(shutdownc)

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

	// Config && Vars per domain
	lis := strings.Split(Config.Daemon.Listen, ",")
	for addr := range lis {

		Daemon := &Daemon{
			AuthMethods: make(map[string]bool),
			Plugins:     make(map[string]bool),
			bannedHosts: make(map[string]int),
			clientID:    1,
			timeout:     time.Duration(Config.Daemon.Timeout),
			listen:      lis[addr],
			TLS:         Config.Daemon.Tls,
		}

		go Daemon.New()
	}

	Checks()
}

func Checks() {
	for {
		time.Sleep(15 * time.Minute)

		fmt.Printf("Sesiones Abiertas: %d\n", clientID)

		/*
		for k, v := range bannedHosts {
			if v > Config.Smtp.Banlimit && int(time.Now().Unix()) > v {
				fmt.Printf("Limpiamos: %s - %d\n", k, v)
				delete(bannedHosts, k)
			}
		}
*/
		err := db.Ping()
		if err != nil {
			log.Fatalf("Error on Ping connection: %s", err.Error())
		}

		// Generar stats: Monitorix
		// reject / deny / temp / queue / relay / spam / virus

		ValidsRCPT()
	}
}
