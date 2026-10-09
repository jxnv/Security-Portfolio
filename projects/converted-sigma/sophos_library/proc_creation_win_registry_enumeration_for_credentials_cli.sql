-- Title: Enumeration for 3rd Party Creds From CLI
-- ID: 87a476dc-0079-4583-a985-dee7a20a03de
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2022-06-20
-- Tags: attack.credential-access, attack.t1552.002
-- Description: Detects processes that query known 3rd party registry keys that holds credentials via commandline
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '%\\Software\\Aerofox\\Foxmail\\V3.1%' OR CommandLine ILIKE '%\\Software\\Aerofox\\FoxmailPreview%' OR CommandLine ILIKE '%\\Software\\DownloadManager\\Passwords%' OR CommandLine ILIKE '%\\Software\\FTPWare\\COREFTP\\Sites%' OR CommandLine ILIKE '%\\Software\\IncrediMail\\Identities%' OR CommandLine ILIKE '%\\Software\\Martin Prikryl\\WinSCP 2\\Sessions%' OR CommandLine ILIKE '%\\Software\\Mobatek\\MobaXterm\\%' OR CommandLine ILIKE '%\\Software\\OpenSSH\\Agent\\Keys%' OR CommandLine ILIKE '%\\Software\\OpenVPN-GUI\\configs%' OR CommandLine ILIKE '%\\Software\\ORL\\WinVNC3\\Password%' OR CommandLine ILIKE '%\\Software\\Qualcomm\\Eudora\\CommandLine%' OR CommandLine ILIKE '%\\Software\\RealVNC\\WinVNC4%' OR CommandLine ILIKE '%\\Software\\RimArts\\B2\\Settings%' OR CommandLine ILIKE '%\\Software\\SimonTatham\\PuTTY\\Sessions%' OR CommandLine ILIKE '%\\Software\\SimonTatham\\PuTTY\\SshHostKeys\\%' OR CommandLine ILIKE '%\\Software\\Sota\\FFFTP%' OR CommandLine ILIKE '%\\Software\\TightVNC\\Server%' OR CommandLine ILIKE '%\\Software\\WOW6432Node\\Radmin\\v3.0\\Server\\Parameters\\Radmin%')) AND NOT ((Image ILIKE '%reg.exe' AND (CommandLine ILIKE '%export%' OR CommandLine ILIKE '%save%'))))
