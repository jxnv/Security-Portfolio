-- Title: Capture Credentials with Rpcping.exe
-- ID: 93671f99-04eb-4ab4-a161-70d446a84003
-- Status: test
-- Level: medium
-- Author: Julia Fomina, oscd.community
-- Date: 2020-10-09
-- Tags: attack.credential-access, attack.t1003
-- Description: Detects using Rpcping.exe to send a RPC test connection to the target server (-s) and force the NTLM hash to be sent in the process.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE ((((CommandLine LIKE '%-s%' OR CommandLine LIKE '%/s%')) AND ((Image="*\\RpcPing.exe") OR (OriginalFileName = '\\RpcPing.exe'))) AND (((CommandLine LIKE '%-t%' OR CommandLine LIKE '%/t%') AND CommandLine LIKE '%ncacn_np%') OR ((CommandLine LIKE '%-u%' OR CommandLine LIKE '%/u%') AND CommandLine LIKE '%NTLM%')))
