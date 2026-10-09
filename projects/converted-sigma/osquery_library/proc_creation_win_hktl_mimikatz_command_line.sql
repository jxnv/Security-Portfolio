-- Title: HackTool - Mimikatz Execution
-- ID: a642964e-bead-4bed-8910-1bb4d63e3b4d
-- Status: test
-- Level: high
-- Author: Teymur Kheirkhabarov, oscd.community, David ANDRE (additional keywords), Tim Shelton
-- Date: 2019-10-22
-- Tags: attack.credential-access, attack.t1003.001, attack.t1003.002, attack.t1003.004, attack.t1003.005, attack.t1003.006
-- Description: Detection well-known mimikatz command line arguments
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '%::aadcookie%' OR CommandLine LIKE '%::detours%' OR CommandLine LIKE '%::memssp%' OR CommandLine LIKE '%::mflt%' OR CommandLine LIKE '%::ncroutemon%' OR CommandLine LIKE '%::ngcsign%' OR CommandLine LIKE '%::printnightmare%' OR CommandLine LIKE '%::skeleton%' OR CommandLine LIKE '%::preshutdown%' OR CommandLine LIKE '%::mstsc%' OR CommandLine LIKE '%::multirdp%')) OR ((CommandLine LIKE '%rpc::%' OR CommandLine LIKE '%token::%' OR CommandLine LIKE '%crypto::%' OR CommandLine LIKE '%dpapi::%' OR CommandLine LIKE '%sekurlsa::%' OR CommandLine LIKE '%kerberos::%' OR CommandLine LIKE '%lsadump::%' OR CommandLine LIKE '%privilege::%' OR CommandLine LIKE '%process::%' OR CommandLine LIKE '%vault::%')) OR ((CommandLine LIKE '%DumpCreds%' OR CommandLine LIKE '%mimikatz%')))
