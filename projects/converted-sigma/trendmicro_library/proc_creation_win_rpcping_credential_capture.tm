// Title: Capture Credentials with Rpcping.exe
// ID: 93671f99-04eb-4ab4-a161-70d446a84003
// Status: test
// Level: medium
// Author: Julia Fomina, oscd.community
// Date: 2020-10-09
// Tags: attack.credential-access, attack.t1003
// Description: Detects using Rpcping.exe to send a RPC test connection to the target server (-s) and force the NTLM hash to be sent in the process.
// Converted by: Sigma Universal SIEM/EDR CLI

((((CommandLine: "*-s*" OR CommandLine: "*/s*")) AND ((Image="*\\RpcPing.exe") OR (OriginalFileName: "\\RpcPing.exe"))) AND (((CommandLine: "*-t*" OR CommandLine: "*/t*") AND CommandLine: "*ncacn_np*") OR ((CommandLine: "*-u*" OR CommandLine: "*/u*") AND CommandLine: "*NTLM*")))
