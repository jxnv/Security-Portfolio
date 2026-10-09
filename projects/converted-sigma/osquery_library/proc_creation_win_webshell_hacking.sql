-- Title: Webshell Hacking Activity Patterns
-- ID: 4ebc877f-4612-45cb-b3a5-8e3834db36c9
-- Status: test
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-03-17
-- Tags: attack.persistence, attack.discovery, attack.t1505.003, attack.t1018, attack.t1033, attack.t1087
-- Description: Detects certain parent child patterns found in cases in which a web shell is used to perform certain credential dumping or exfiltration activities on a compromised system
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((ParentImage="*\\java.exe" OR ParentImage="*\\javaw.exe") AND (ParentImage LIKE '%-tomcat-%' OR ParentImage LIKE '%\\tomcat%')) OR ((ParentImage="*\\java.exe" OR ParentImage="*\\javaw.exe") AND (CommandLine LIKE '%catalina.jar%' OR CommandLine LIKE '%CATALINA_HOME%')) OR ((ParentImage="*\\caddy.exe" OR ParentImage="*\\httpd.exe" OR ParentImage="*\\nginx.exe" OR ParentImage="*\\php-cgi.exe" OR ParentImage="*\\w3wp.exe" OR ParentImage="*\\ws_tomcatservice.exe"))) AND (((CommandLine LIKE '%rundll32%' AND CommandLine LIKE '%comsvcs%')) OR ((CommandLine LIKE '% -hp%' AND CommandLine LIKE '% a %' AND CommandLine LIKE '% -m%')) OR ((CommandLine LIKE '%net%' AND CommandLine LIKE '% user %' AND CommandLine LIKE '% /add%')) OR ((CommandLine LIKE '%net%' AND CommandLine LIKE '% localgroup %' AND CommandLine LIKE '% administrators %' AND CommandLine LIKE '%/add%')) OR ((Image="*\\ntdsutil.exe" OR Image="*\\ldifde.exe" OR Image="*\\adfind.exe" OR Image="*\\procdump.exe" OR Image="*\\Nanodump.exe" OR Image="*\\vssadmin.exe" OR Image="*\\fsutil.exe")) OR ((CommandLine LIKE '% -decode %' OR CommandLine LIKE '% -NoP %' OR CommandLine LIKE '% -W Hidden %' OR CommandLine LIKE '% /decode %' OR CommandLine LIKE '% /ticket:%' OR CommandLine LIKE '% sekurlsa%' OR CommandLine LIKE '%.dmp full%' OR CommandLine LIKE '%.downloadfile(%' OR CommandLine LIKE '%.downloadstring(%' OR CommandLine LIKE '%FromBase64String%' OR CommandLine LIKE '%process call create%' OR CommandLine LIKE '%reg save %' OR CommandLine LIKE '%whoami /priv%'))))
