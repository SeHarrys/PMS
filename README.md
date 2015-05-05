# PMS - Pachanga Mail Server

PMS is a simple email server based on go-guerrilla and the great Perl qpsmtpd

For send emails use a relay server for example a postfix at 127.0.0.1:12025

Accept all emails of hosts valid in "rcpt_to hosts" or is authenticated user to relay mail

The structure of the users is so simple if the directory exists, is a welcome user

You can make symbolic links between directories to make a alias email

For the config file first read PMS_CONFIG environment and next file pms.conf.json

# Autoresponder

# Auth
  Is authenticade user and relay is enabled

# Queue

# Relay

# DKIM

# SPAM

# Virus
 ClamAV