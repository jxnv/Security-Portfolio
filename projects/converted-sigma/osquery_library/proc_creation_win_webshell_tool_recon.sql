-- Title: Webshell Tool Reconnaissance Activity
-- ID: f64e5c19-879c-4bae-b471-6d84c8339677
-- Status: test
-- Level: high
-- Author: Cian Heasley, Florian Roth (Nextron Systems)
-- Date: 2020-07-22
-- Tags: attack.persistence, attack.t1505.003
-- Description: Detects processes spawned from web servers (PHP, Tomcat, IIS, etc.) that perform reconnaissance looking for the existence of popular scripting tools (perl, python, wget) on the system via the help commands
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((ParentImage="*\\java.exe" OR ParentImage="*\\javaw.exe") AND (ParentImage LIKE '%-tomcat-%' OR ParentImage LIKE '%\\tomcat%')) OR ((ParentImage="*\\java.exe" OR ParentImage="*\\javaw.exe") AND (CommandLine LIKE '%CATALINA_HOME%' OR CommandLine LIKE '%catalina.jar%')) OR ((ParentImage="*\\caddy.exe" OR ParentImage="*\\httpd.exe" OR ParentImage="*\\nginx.exe" OR ParentImage="*\\php-cgi.exe" OR ParentImage="*\\w3wp.exe" OR ParentImage="*\\ws_tomcatservice.exe"))) AND ((CommandLine LIKE '%perl --help%' OR CommandLine LIKE '%perl -h%' OR CommandLine LIKE '%python --help%' OR CommandLine LIKE '%python -h%' OR CommandLine LIKE '%python3 --help%' OR CommandLine LIKE '%python3 -h%' OR CommandLine LIKE '%wget --help%')))
