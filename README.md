# PMS - Pachanga Mail Server

  PMS is a simple email server SMTP writen in Go and based on go-guerrilla and the great qpsmtpd

  For the config file first read $ENV{PMS_CONFIG} and next file pms.conf

```shell
go get github.com/SeHarrys/PMS
go build
```

### AllowedHost type

  1 : normal
  
	The structure of the users is so simple if the directory exists and is a valid domain
	
  2 : mirror domain
  
  3 : centralized all emails in user 'all' (all rcpt_to are valid to all@domain)

## Email Alias

   You can make symbolic links between directories to make a alias email

## Config
   
## Auth

  PLAIN		: Only with SSL enabled
  
  CRAM-MD5	:

  Is authenticade user and relay is enabled

## Queue

  The emails are saved in files in Maildir format
  
## Relay

   To send emails you can specify a relay server for auth users only

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

  fcrdns	:

## Web Interface

  You can get https://github.com/SeHarrys/pms-web a admin web interface made with Mojolicious (Perl)