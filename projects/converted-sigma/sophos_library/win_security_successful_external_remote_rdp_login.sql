-- Title: External Remote RDP Logon from Public IP
-- ID: 259a9cdf-c4dd-4fa2-b243-2269e5ab18a2
-- Status: test
-- Level: medium
-- Author: Micah Babinski (@micahbabinski), Zach Mathis (@yamatosecurity)
-- Date: 2023-01-19
-- Tags: attack.privilege-escalation, attack.persistence, attack.initial-access, attack.credential-access, attack.stealth, attack.t1133, attack.t1078, attack.t1110
-- Description: Detects successful logon from public IP address via RDP. This can indicate a publicly-exposed RDP port.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((EventID = 4624 AND LogonType = 10) AND NOT (((IpAddress = '-') OR ((cidrmatch("::1/128", IpAddress) OR cidrmatch("10.0.0.0/8", IpAddress) OR cidrmatch("127.0.0.0/8", IpAddress) OR cidrmatch("172.16.0.0/12", IpAddress) OR cidrmatch("192.168.0.0/16", IpAddress) OR cidrmatch("169.254.0.0/16", IpAddress) OR cidrmatch("fc00::/7", IpAddress) OR cidrmatch("fe80::/10", IpAddress))))))
