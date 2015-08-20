# PMS - Pachanga Mail Server

  PMS is a simple email server SMTP write in Go and based on go-guerrilla and the great qpsmtpd

  For the config file first read $ENV{PMS_CONFIG} and next file pms.conf

```shell
go get github.com/SeHarrys/PMS
go build
```

### AllowedHost type

  [1] normal : The structure of the users is so simple if the directory exists and is a valid domain are welcome
	
  [2] mirror domain

  [3] centralized all emails in user 'all' (all rcpt_to are valid to all@domain)

## Email Alias

   You can make symbolic links between directories to make a alias email

## Config

   The examples are in pms.conf

   You can reload pms :

```shell
kill -SIGHUP `cat pms.pid`
```

## Auth

  PLAIN		: Only with SSL enabled
  
  CRAM-MD5	: Store the clear password in db

## Queue

  The emails are saved in files in Maildir format
  
## Relay

   With enabled relay is only available for authenticated users

## (Plugins)[https://github.com/SeHarrys/PMS]

## Web Interface

  You can get https://github.com/SeHarrys/pms-web a admin web interface made with Mojolicious (Perl)