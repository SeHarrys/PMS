# PMS - Pachanga Mail Server

  PMS is a simple email server SMTP writen in Go and based on go-guerrilla and the great qpsmtpd

  Accept all emails of hosts valid in "allowedHosts" or is authenticated user to relay mail

  The structure of the users is so simple if the directory exists and is a valid domain
  is a welcome user, you can make symbolic links between directories to make a alias email

  For the config file first read $ENV{PMS_CONFIG} and next file pms.conf

```shell
go get github.com/SeHarrys/PMS
export GOPATH=`pwd`
export PATH=$PATH:$GOPATH/bin
go build
```

### AllowedHost type

  1 : normal
  
  2 : mirror domain
  
  3 : centralized all emails in user 'all' (all rcpt_to are valid to all@domain)

## Config
   
## Auth

  PLAIN		: Only with SSL enabled
  
  CRAM-MD5	:

  Is authenticade user and relay is enabled

## Queue

  The emails are saved in files in Maildir format
  
## Relay

  For send emails you can specify a relay server for example postfix at 127.0.0.1:12025

## SPAM

  It's my breakfast

## Plugins

  autoresponder	: You can set a message in DB
  
  clamav	: ToDo - https://github.com/dutchcoders/go-clamd

  DKIM		: In the relay server

  DMARC		: TODO parse XML and report (make db filter)
  
  spf		: Sender Policy Framework
  
  earlytalker	: Check that the client doesn't talk before we send the SMTP banner (qpsmtpd)
  
  spamc		: spamassasin client

  whitelist	: Domains whitelisted DB
  
  greylisting	: 

  filterdb	: 

## Web Interface

  You can get https://github.com/SeHarrys/pms-web a admin web interface made with Mojolicious (Perl)