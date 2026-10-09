// Title: Webshell Hacking Activity Patterns
// ID: 4ebc877f-4612-45cb-b3a5-8e3834db36c9
// Status: test
// Level: high
// Author: Florian Roth (Nextron Systems)
// Date: 2022-03-17
// Tags: attack.persistence, attack.discovery, attack.t1505.003, attack.t1018, attack.t1033, attack.t1087
// Description: Detects certain parent child patterns found in cases in which a web shell is used to perform certain credential dumping or exfiltration activities on a compromised system
// Converted by: Sigma Universal SIEM/EDR CLI

((((ParentImage="*\\java.exe" OR ParentImage="*\\javaw.exe") AND (ParentImage contains "-tomcat-" OR ParentImage contains "\\tomcat")) OR ((ParentImage="*\\java.exe" OR ParentImage="*\\javaw.exe") AND (CommandLine contains "catalina.jar" OR CommandLine contains "CATALINA_HOME")) OR ((ParentImage="*\\caddy.exe" OR ParentImage="*\\httpd.exe" OR ParentImage="*\\nginx.exe" OR ParentImage="*\\php-cgi.exe" OR ParentImage="*\\w3wp.exe" OR ParentImage="*\\ws_tomcatservice.exe"))) AND (((CommandLine contains "rundll32" AND CommandLine contains "comsvcs")) OR ((CommandLine contains " -hp" AND CommandLine contains " a " AND CommandLine contains " -m")) OR ((CommandLine contains "net" AND CommandLine contains " user " AND CommandLine contains " /add")) OR ((CommandLine contains "net" AND CommandLine contains " localgroup " AND CommandLine contains " administrators " AND CommandLine contains "/add")) OR ((Image="*\\ntdsutil.exe" OR Image="*\\ldifde.exe" OR Image="*\\adfind.exe" OR Image="*\\procdump.exe" OR Image="*\\Nanodump.exe" OR Image="*\\vssadmin.exe" OR Image="*\\fsutil.exe")) OR ((CommandLine contains " -decode " OR CommandLine contains " -NoP " OR CommandLine contains " -W Hidden " OR CommandLine contains " /decode " OR CommandLine contains " /ticket:" OR CommandLine contains " sekurlsa" OR CommandLine contains ".dmp full" OR CommandLine contains ".downloadfile(" OR CommandLine contains ".downloadstring(" OR CommandLine contains "FromBase64String" OR CommandLine contains "process call create" OR CommandLine contains "reg save " OR CommandLine contains "whoami /priv"))))
