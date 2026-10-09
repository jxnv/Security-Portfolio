-- Title: Suspicious WebDav Client Execution Via Rundll32.EXE
-- ID: 982e9f2d-1a85-4d5b-aea4-31f5e97c6555
-- Status: test
-- Level: high
-- Author: Nasreddine Bencherchali (Nextron Systems), Florian Roth (Nextron Systems)
-- Date: 2023-03-16
-- Tags: attack.exfiltration, attack.t1048.003, cve.2023-23397
-- Description: Detects "svchost.exe" spawning "rundll32.exe" with command arguments like C:\windows\system32\davclnt.dll,DavSetCookie. This could be an indicator of exfiltration or use of WebDav to launch code (hosted on WebDav Server) or potentially a sign of exploitation of CVE-2023-23397
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((ParentImage ILIKE '%\\svchost.exe' AND ParentCommandLine ILIKE '%-s WebClient%' AND Image ILIKE '%\\rundll32.exe' AND CommandLine ILIKE '%C:\\windows\\system32\\davclnt.dll,DavSetCookie%' AND REGEXP_LIKE(CommandLine, '://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')) AND NOT (((CommandLine ILIKE '%://10.%' OR CommandLine ILIKE '%://192.168.%' OR CommandLine ILIKE '%://172.16.%' OR CommandLine ILIKE '%://172.17.%' OR CommandLine ILIKE '%://172.18.%' OR CommandLine ILIKE '%://172.19.%' OR CommandLine ILIKE '%://172.20.%' OR CommandLine ILIKE '%://172.21.%' OR CommandLine ILIKE '%://172.22.%' OR CommandLine ILIKE '%://172.23.%' OR CommandLine ILIKE '%://172.24.%' OR CommandLine ILIKE '%://172.25.%' OR CommandLine ILIKE '%://172.26.%' OR CommandLine ILIKE '%://172.27.%' OR CommandLine ILIKE '%://172.28.%' OR CommandLine ILIKE '%://172.29.%' OR CommandLine ILIKE '%://172.30.%' OR CommandLine ILIKE '%://172.31.%' OR CommandLine ILIKE '%://127.%' OR CommandLine ILIKE '%://169.254.%'))))
