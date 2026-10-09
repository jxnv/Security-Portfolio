-- Title: Local Network Connection Initiated By Script Interpreter
-- ID: 08249dc0-a28d-4555-8ba5-9255a198e08c
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-08-28
-- Tags: attack.command-and-control, attack.t1105
-- Description: Detects a script interpreter (Wscript/Cscript) initiating a local network connection to download or execute a script hosted on a shared folder.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (Initiated = 'true' AND (Image ILIKE '%\\wscript.exe' OR Image ILIKE '%\\cscript.exe') AND (cidrmatch("127.0.0.0/8", DestinationIp) OR cidrmatch("10.0.0.0/8", DestinationIp) OR cidrmatch("172.16.0.0/12", DestinationIp) OR cidrmatch("192.168.0.0/16", DestinationIp) OR cidrmatch("169.254.0.0/16", DestinationIp) OR cidrmatch("::1/128", DestinationIp) OR cidrmatch("fe80::/10", DestinationIp) OR cidrmatch("fc00::/7", DestinationIp)))
