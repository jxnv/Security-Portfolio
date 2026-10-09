-- Title: Linux Webshell Indicators
-- ID: 818f7b24-0fba-4c49-a073-8b755573b9c7
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)
-- Date: 2021-10-15
-- Tags: attack.persistence, attack.t1505.003
-- Description: Detects suspicious sub processes of web server processes
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((((ParentImage ILIKE '%/httpd' OR ParentImage ILIKE '%/lighttpd' OR ParentImage ILIKE '%/nginx' OR ParentImage ILIKE '%/apache2' OR ParentImage ILIKE '%/node' OR ParentImage ILIKE '%/caddy')) OR ((ParentCommandLine ILIKE '%/bin/java%' AND ParentCommandLine ILIKE '%tomcat%')) OR ((ParentCommandLine ILIKE '%/bin/java%' AND ParentCommandLine ILIKE '%websphere%'))) AND ((Image ILIKE '%/whoami' OR Image ILIKE '%/ifconfig' OR Image ILIKE '%/ip' OR Image ILIKE '%/bin/uname' OR Image ILIKE '%/bin/cat' OR Image ILIKE '%/bin/crontab' OR Image ILIKE '%/hostname' OR Image ILIKE '%/iptables' OR Image ILIKE '%/netstat' OR Image ILIKE '%/pwd' OR Image ILIKE '%/route')) AND NOT ((ParentImage ILIKE '%/node' AND CommandLine ILIKE '%ip neigh show%')))
