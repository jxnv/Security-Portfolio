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

SELECT * FROM processes WHERE (((CommandLine LIKE '%\\Software\\Aerofox\\Foxmail\\V3.1%' OR CommandLine LIKE '%\\Software\\Aerofox\\FoxmailPreview%' OR CommandLine LIKE '%\\Software\\DownloadManager\\Passwords%' OR CommandLine LIKE '%\\Software\\FTPWare\\COREFTP\\Sites%' OR CommandLine LIKE '%\\Software\\IncrediMail\\Identities%' OR CommandLine LIKE '%\\Software\\Martin Prikryl\\WinSCP 2\\Sessions%' OR CommandLine LIKE '%\\Software\\Mobatek\\MobaXterm%' OR CommandLine LIKE '%\\Software\\OpenSSH\\Agent\\Keys%' OR CommandLine LIKE '%\\Software\\OpenVPN-GUI\\configs%' OR CommandLine LIKE '%\\Software\\ORL\\WinVNC3\\Password%' OR CommandLine LIKE '%\\Software\\Qualcomm\\Eudora\\CommandLine%' OR CommandLine LIKE '%\\Software\\RealVNC\\WinVNC4%' OR CommandLine LIKE '%\\Software\\RimArts\\B2\\Settings%' OR CommandLine LIKE '%\\Software\\SimonTatham\\PuTTY\\Sessions%' OR CommandLine LIKE '%\\Software\\SimonTatham\\PuTTY\\SshHostKeys%' OR CommandLine LIKE '%\\Software\\Sota\\FFFTP%' OR CommandLine LIKE '%\\Software\\TightVNC\\Server%' OR CommandLine LIKE '%\\Software\\WOW6432Node\\Radmin\\v3.0\\Server\\Parameters\\Radmin%')) AND ((CommandLine LIKE '%save%' OR CommandLine LIKE '%export%')) AND ((Image="*\\reg.exe") OR (OriginalFileName = 'reg.exe')))
