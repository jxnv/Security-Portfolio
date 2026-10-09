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

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%.7z%' OR CommandLine ILIKE '%.avi%' OR CommandLine ILIKE '%.bat%' OR CommandLine ILIKE '%.bmp%' OR CommandLine ILIKE '%.conf%' OR CommandLine ILIKE '%.csv%' OR CommandLine ILIKE '%.dll%' OR CommandLine ILIKE '%.doc%' OR CommandLine ILIKE '%.gif%' OR CommandLine ILIKE '%.gz%' OR CommandLine ILIKE '%.ini%' OR CommandLine ILIKE '%.jpe%' OR CommandLine ILIKE '%.jpg%' OR CommandLine ILIKE '%.json%' OR CommandLine ILIKE '%.lnk%' OR CommandLine ILIKE '%.log%' OR CommandLine ILIKE '%.mkv%' OR CommandLine ILIKE '%.mp3%' OR CommandLine ILIKE '%.mp4%' OR CommandLine ILIKE '%.pdf%' OR CommandLine ILIKE '%.png%' OR CommandLine ILIKE '%.ppt%' OR CommandLine ILIKE '%.rar%' OR CommandLine ILIKE '%.rtf%' OR CommandLine ILIKE '%.svg%' OR CommandLine ILIKE '%.tar%' OR CommandLine ILIKE '%.tmp%' OR CommandLine ILIKE '%.txt%' OR CommandLine ILIKE '%.xls%' OR CommandLine ILIKE '%.xml%' OR CommandLine ILIKE '%.yaml%' OR CommandLine ILIKE '%.yml%' OR CommandLine ILIKE '%.zip%' OR CommandLine ILIKE '%vbscript%')) AND ((Image ILIKE '%\\mshta.exe') OR (OriginalFileName = 'mshta.exe')))
