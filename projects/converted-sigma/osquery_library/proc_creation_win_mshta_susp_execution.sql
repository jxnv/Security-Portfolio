-- Title: MSHTA Execution with Suspicious File Extensions
-- ID: cc7abbd0-762b-41e3-8a26-57ad50d2eea3
-- Status: test
-- Level: high
-- Author: Diego Perez (@darkquassar), Markus Neis, Swisscom (Improve Rule), Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date: 2019-02-22
-- Tags: attack.stealth, attack.t1140, attack.t1218.005, attack.execution, attack.t1059.007, cve.2020-1599
-- Description: Detects execution of mshta.exe with file types that looks like they do not typically represent HTA (HTML Application) content,
-- such as .png, .jpg, .zip, .pdf, and others, which are often polyglots. MSHTA is a legitimate Windows utility for executing HTML Applications
-- containing VBScript or JScript. Threat actors often abuse this lolbin utility to download and
-- execute malicious scripts disguised as benign files or hosted under misleading extensions to evade detection.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%.7z%' OR CommandLine LIKE '%.avi%' OR CommandLine LIKE '%.bat%' OR CommandLine LIKE '%.bmp%' OR CommandLine LIKE '%.conf%' OR CommandLine LIKE '%.csv%' OR CommandLine LIKE '%.dll%' OR CommandLine LIKE '%.doc%' OR CommandLine LIKE '%.gif%' OR CommandLine LIKE '%.gz%' OR CommandLine LIKE '%.ini%' OR CommandLine LIKE '%.jpe%' OR CommandLine LIKE '%.jpg%' OR CommandLine LIKE '%.json%' OR CommandLine LIKE '%.lnk%' OR CommandLine LIKE '%.log%' OR CommandLine LIKE '%.mkv%' OR CommandLine LIKE '%.mp3%' OR CommandLine LIKE '%.mp4%' OR CommandLine LIKE '%.pdf%' OR CommandLine LIKE '%.png%' OR CommandLine LIKE '%.ppt%' OR CommandLine LIKE '%.rar%' OR CommandLine LIKE '%.rtf%' OR CommandLine LIKE '%.svg%' OR CommandLine LIKE '%.tar%' OR CommandLine LIKE '%.tmp%' OR CommandLine LIKE '%.txt%' OR CommandLine LIKE '%.xls%' OR CommandLine LIKE '%.xml%' OR CommandLine LIKE '%.yaml%' OR CommandLine LIKE '%.yml%' OR CommandLine LIKE '%.zip%' OR CommandLine LIKE '%vbscript%')) AND ((Image="*\\mshta.exe") OR (OriginalFileName = 'mshta.exe')))
