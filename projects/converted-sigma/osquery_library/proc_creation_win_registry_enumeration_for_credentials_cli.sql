-- Title: Enumeration for 3rd Party Creds From CLI
-- ID: 87a476dc-0079-4583-a985-dee7a20a03de
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-06-20
-- Tags: attack.credential-access, attack.t1552.002
-- Description: Detects processes that query known 3rd party registry keys that holds credentials via commandline
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%\\Software\\Aerofox\\Foxmail\\V3.1%' OR CommandLine LIKE '%\\Software\\Aerofox\\FoxmailPreview%' OR CommandLine LIKE '%\\Software\\DownloadManager\\Passwords%' OR CommandLine LIKE '%\\Software\\FTPWare\\COREFTP\\Sites%' OR CommandLine LIKE '%\\Software\\IncrediMail\\Identities%' OR CommandLine LIKE '%\\Software\\Martin Prikryl\\WinSCP 2\\Sessions%' OR CommandLine LIKE '%\\Software\\Mobatek\\MobaXterm\\%' OR CommandLine LIKE '%\\Software\\OpenSSH\\Agent\\Keys%' OR CommandLine LIKE '%\\Software\\OpenVPN-GUI\\configs%' OR CommandLine LIKE '%\\Software\\ORL\\WinVNC3\\Password%' OR CommandLine LIKE '%\\Software\\Qualcomm\\Eudora\\CommandLine%' OR CommandLine LIKE '%\\Software\\RealVNC\\WinVNC4%' OR CommandLine LIKE '%\\Software\\RimArts\\B2\\Settings%' OR CommandLine LIKE '%\\Software\\SimonTatham\\PuTTY\\Sessions%' OR CommandLine LIKE '%\\Software\\SimonTatham\\PuTTY\\SshHostKeys\\%' OR CommandLine LIKE '%\\Software\\Sota\\FFFTP%' OR CommandLine LIKE '%\\Software\\TightVNC\\Server%' OR CommandLine LIKE '%\\Software\\WOW6432Node\\Radmin\\v3.0\\Server\\Parameters\\Radmin%')) AND NOT ((Image="*reg.exe" AND (CommandLine LIKE '%export%' OR CommandLine LIKE '%save%'))))
