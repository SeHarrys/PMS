package main

// RFC6531: SMTP Extension for Internationalized Email
// RFC7372: Email Authentication Status Codes
// manejar debidamente los errores
// temperror : no resolution
// ip4 == Net IP4 ¿? benchmark

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

type Spf struct {
	lookup_limit int // DNS Lookups limits
	client_ip    string
	helo         string
	mechanism    string
	envelope     string // MAIL FROM:
	result       string
	status       string
	header       string
	domain       string
	ip4          []string
	ip6          []string
	records      []string
}

var (
	reg_version   = regexp.MustCompile(`^v=spf1$`)
	reg_ip4       = regexp.MustCompile(`^ip4:(.*)$`)
	reg_ip6       = regexp.MustCompile(`^ip6:(.*)$`)
	reg_include   = regexp.MustCompile(`^(?:include|mx):(.*)$`)
	reg_redirect  = regexp.MustCompile(`^redirect:(.*)$`)
	reg_exp       = regexp.MustCompile(`^exp:(.*)$`)
	reg_mechanism = regexp.MustCompile(`^\-?\~?(a|ptr|exists|all)$`)
)

func (SPF *Spf) New() {
	SPF.status = "fail"

	SPF.Domain()

	//fmt.Println(SPF.status)

	if SPF.status != "temperror" {
		SPF.Parser(SPF.records[0])
		SPF.Check()
	}

	SPF.MakeHeader()
}

// Check helo or doamin
func (SPF *Spf) Domain() {

	_, domain := getMail(SPF.envelope)

	error := SPF.Get(domain)

	if error != nil {
		SPF.Get(SPF.helo)
		SPF.domain = SPF.helo
	} else {
		SPF.domain = domain
	}

}

func (SPF *Spf) Get(dns string) error {
	SPF.LookupInc()

	txt, err := net.LookupTXT(dns)

	if err != nil {
		SPF.status = "temperror"
		return errors.New(fmt.Sprintf("%q", err))
	} else {
		SPF.status = "fail"
		SPF.records = txt
		return nil
	}

}

func (SPF *Spf) LookupMX(dns string) bool {
	SPF.LookupInc()

	txt, err := net.LookupMX(dns)

	if err != nil {
		fmt.Println(err)
		return false
	}

	SPF.ip4 = append(SPF.ip4, SPF.Lookup(txt[0].Host))

	return true
}

func (SPF *Spf) Lookup(domain string) string {
	SPF.LookupInc()

	ip, err := net.ResolveIPAddr("ip4", domain)

	if err != nil {
		fmt.Printf("%s error: %s\n", domain, err)
	}

	return ip.String()
}

// Max 10 lookup
func (SPF *Spf) LookupInc() bool {

	if SPF.lookup_limit >= 10 {
		SPF.status = "temperror"
		return false
	}

	SPF.lookup_limit++

	return true
}

func (SPF *Spf) Check() {

	tip := net.ParseIP(SPF.client_ip)

	if tip.To4() != nil {
		for _, ip := range SPF.ip4 {
			if ip == SPF.client_ip {
				SPF.mechanism = "ip4:" + ip
				SPF.status = "pass"
				return
			}
		}
	} else {
		for _, ip := range SPF.ip6 {
			if ip == SPF.client_ip {
				SPF.mechanism = "ip6:" + ip
				SPF.status = "pass"
				return
			}
		}
	}

}

func (SPF *Spf) Parser(txt string) {

	record := strings.Split(txt, " ")

	if !reg_version.MatchString(record[0]) {
		SPF.status = "permerror"
		return
	}

	// First ommited -> reg_version
	for i := 1; i < len(record); i++ {
		switch {
		case reg_mechanism.MatchString(record[i]):
			//fmt.Println("Mechanism :",record[i])
			if record[i] == "mx" {
				SPF.LookupMX(SPF.helo)
			}
		case reg_ip4.MatchString(record[i]):
			m := reg_ip4.FindStringSubmatch(record[i])
			tip := net.ParseIP(m[1])
			if tip.To4() == nil {
				SPF.CheckCIDR(m[1])
			} else {
				SPF.ip4 = append(SPF.ip4, m[1])
			}
		case reg_ip6.MatchString(record[i]):
			// FIX IPv6
			m := reg_ip6.FindStringSubmatch(record[i])
			SPF.ip6 = append(SPF.ip6, m[1])
		case reg_include.MatchString(record[i]):
			m := reg_include.FindStringSubmatch(record[i])
			SPF.Get(m[1])
			SPF.Parser(SPF.records[0])
		default:
			//fmt.Printf("No coincidencia: %s\n",record[i])
			SPF.status = "permerror"
			return
		}
	}

}

//
func (SPF *Spf) CheckCIDR(cidr string) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Println("Invalid IP4 CDIR - FAIL : ", cidr)
		SPF.status = "permerror"
		return
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		SPF.ip4 = append(SPF.ip4, ip.String())
	}

}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func (SPF *Spf) Mechanism(record string) {

}

func (SPF *Spf) MakeHeader() {
	var Header bytes.Buffer

	// Header.WriteString(fmt.Sprintf("Received-SPF: %s ",SPF.status))
	Header.WriteString(fmt.Sprintf("%s ", SPF.status))

	Header.WriteString(fmt.Sprintf("(%s: domain of %s ", SPF.domain, SPF.envelope))

	if SPF.status != "pass" {
		Header.WriteString("does not ")
	}

	Header.WriteString(fmt.Sprintf("designate %s as permitted sender) ", SPF.client_ip))

	if SPF.status == "pass" {
		Header.WriteString(fmt.Sprintf("receiver=%s;", SPF.domain))
	}

	if SPF.mechanism != "" {
		Header.WriteString(fmt.Sprintf("mechanism=%s; ", SPF.mechanism))
	}

	Header.WriteString("identity=mailfrom; ")
	Header.WriteString(fmt.Sprintf("client-ip=%s; envelope-from=\"%s\";", SPF.client_ip, SPF.envelope))

	if SPF.status == "pass" {
		Header.WriteString(fmt.Sprintf("helo=%s; ", SPF.helo))
	}

	SPF.header = Header.String()
}
