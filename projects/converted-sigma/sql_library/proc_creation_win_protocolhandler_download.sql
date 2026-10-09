-- Title: File Download Using ProtocolHandler.exe
-- ID: 104cdb48-a7a8-4ca7-a453-32942c6e5dcb
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-07-13
-- Tags: attack.stealth, attack.t1218
-- Description: Detects usage of "ProtocolHandler" to download files. Downloaded files will be located in the cache folder (for example - %LOCALAPPDATA%\Microsoft\Windows\INetCache\IE)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%ftp://%' OR CommandLine ILIKE '%http://%' OR CommandLine ILIKE '%https://%')) AND ((Image ILIKE '%\\protocolhandler.exe') OR (OriginalFileName = 'ProtocolHandler.exe')))
