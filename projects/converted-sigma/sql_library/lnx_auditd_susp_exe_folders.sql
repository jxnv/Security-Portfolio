-- Title: Program Executions in Suspicious Folders
-- ID: a39d7fa7-3fbd-4dc2-97e1-d87f546b1bbc
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2018-01-23
-- Tags: attack.t1587, attack.t1584, attack.resource-development
-- Description: Detects program executions in suspicious non-program folders related to malware or hacking activity
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (type = 'SYSCALL' AND (exe ILIKE '/tmp/%' OR exe ILIKE '/var/www/%' OR exe ILIKE '/home/*/public_html/%' OR exe ILIKE '/usr/local/apache2/%' OR exe ILIKE '/usr/local/httpd/%' OR exe ILIKE '/var/apache/%' OR exe ILIKE '/srv/www/%' OR exe ILIKE '/home/httpd/html/%' OR exe ILIKE '/srv/http/%' OR exe ILIKE '/usr/share/nginx/html/%' OR exe ILIKE '/var/lib/pgsql/data/%' OR exe ILIKE '/usr/local/mysql/data/%' OR exe ILIKE '/var/lib/mysql/%' OR exe ILIKE '/var/vsftpd/%' OR exe ILIKE '/etc/bind/%' OR exe ILIKE '/var/named/%'))
