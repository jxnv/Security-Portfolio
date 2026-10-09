// Title: Outbound Network Connection Initiated By Script Interpreter
// ID: 992a6cae-db6a-43c8-9cec-76d7195c96fc
// Status: test
// Level: high
// Author: frack113, Florian Roth (Nextron Systems)
// Date: 2022-08-28
// Tags: attack.command-and-control, attack.t1105
// Description: Detects a script interpreter wscript/cscript opening a network connection to a non-local network. Adversaries may use script to download malicious payloads.
// Converted by: Sigma Universal SIEM/EDR CLI

((Initiated == "true" AND (Image="*\\wscript.exe" OR Image="*\\cscript.exe")) AND NOT ((((cidrmatch("127.0.0.0/8", DestinationIp) OR cidrmatch("10.0.0.0/8", DestinationIp) OR cidrmatch("172.16.0.0/12", DestinationIp) OR cidrmatch("192.168.0.0/16", DestinationIp) OR cidrmatch("169.254.0.0/16", DestinationIp) OR cidrmatch("::1/128", DestinationIp) OR cidrmatch("fe80::/10", DestinationIp) OR cidrmatch("fc00::/7", DestinationIp))) OR (cidrmatch("20.0.0.0/11", DestinationIp)))))
