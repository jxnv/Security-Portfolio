-- Title: Registry Export of Third-Party Credentials
-- ID: cc1abf27-78a3-4ac5-a51c-f3070b1d8e40
-- Status: experimental
-- Level: high
-- Author: Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2025-05-22
-- Tags: attack.credential-access, attack.t1552.002
-- Description: Detects the use of reg.exe to export registry paths associated with third-party credentials.
-- Credential stealers have been known to use this technique to extract sensitive information from the registry.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%\\Software\\Aerofox\\Foxmail\\V3.1%' OR CommandLine ILIKE '%\\Software\\Aerofox\\FoxmailPreview%' OR CommandLine ILIKE '%\\Software\\DownloadManager\\Passwords%' OR CommandLine ILIKE '%\\Software\\FTPWare\\COREFTP\\Sites%' OR CommandLine ILIKE '%\\Software\\IncrediMail\\Identities%' OR CommandLine ILIKE '%\\Software\\Martin Prikryl\\WinSCP 2\\Sessions%' OR CommandLine ILIKE '%\\Software\\Mobatek\\MobaXterm%' OR CommandLine ILIKE '%\\Software\\OpenSSH\\Agent\\Keys%' OR CommandLine ILIKE '%\\Software\\OpenVPN-GUI\\configs%' OR CommandLine ILIKE '%\\Software\\ORL\\WinVNC3\\Password%' OR CommandLine ILIKE '%\\Software\\Qualcomm\\Eudora\\CommandLine%' OR CommandLine ILIKE '%\\Software\\RealVNC\\WinVNC4%' OR CommandLine ILIKE '%\\Software\\RimArts\\B2\\Settings%' OR CommandLine ILIKE '%\\Software\\SimonTatham\\PuTTY\\Sessions%' OR CommandLine ILIKE '%\\Software\\SimonTatham\\PuTTY\\SshHostKeys%' OR CommandLine ILIKE '%\\Software\\Sota\\FFFTP%' OR CommandLine ILIKE '%\\Software\\TightVNC\\Server%' OR CommandLine ILIKE '%\\Software\\WOW6432Node\\Radmin\\v3.0\\Server\\Parameters\\Radmin%')) AND ((CommandLine ILIKE '%save%' OR CommandLine ILIKE '%export%')) AND ((Image ILIKE '%\\reg.exe') OR (OriginalFileName = 'reg.exe')))
