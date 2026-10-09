-- Title: New Port Forwarding Rule Added Via Netsh.EXE
-- ID: 322ed9ec-fcab-4f67-9a34-e7c6aef43614
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), omkar72, oscd.community, Swachchhanda Shrawan Poudel
-- Date: 2019-01-29
-- Tags: attack.lateral-movement, attack.command-and-control, attack.t1090
-- Description: Detects the execution of netsh commands that configure a new port forwarding (PortProxy) rule
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((Image="*\\netsh.exe") OR (OriginalFileName = 'netsh.exe')) AND (((CommandLine LIKE '%interface%' AND CommandLine LIKE '%portproxy%' AND CommandLine LIKE '%add%' AND CommandLine LIKE '%v4tov4%')) OR ((CommandLine LIKE '%i %' AND CommandLine LIKE '%p %' AND CommandLine LIKE '%a %' AND CommandLine LIKE '%v %')) OR ((CommandLine LIKE '%connectp%' AND CommandLine LIKE '%listena%' AND CommandLine LIKE '%c=%'))))
