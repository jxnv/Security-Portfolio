-- Title: New Port Forwarding Rule Added Via Netsh.EXE
-- ID: 322ed9ec-fcab-4f67-9a34-e7c6aef43614
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems), omkar72, oscd.community, Swachchhanda Shrawan Poudel
-- Date: 2019-01-29
-- Tags: attack.lateral-movement, attack.command-and-control, attack.t1090
-- Description: Detects the execution of netsh commands that configure a new port forwarding (PortProxy) rule
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((Image ILIKE '%\\netsh.exe') OR (OriginalFileName = 'netsh.exe')) AND (((CommandLine ILIKE '%interface%' AND CommandLine ILIKE '%portproxy%' AND CommandLine ILIKE '%add%' AND CommandLine ILIKE '%v4tov4%')) OR ((CommandLine ILIKE '%i %' AND CommandLine ILIKE '%p %' AND CommandLine ILIKE '%a %' AND CommandLine ILIKE '%v %')) OR ((CommandLine ILIKE '%connectp%' AND CommandLine ILIKE '%listena%' AND CommandLine ILIKE '%c=%'))))
