-- Title: Suspicious CertReq Command to Download
-- ID: 4480827a-9799-4232-b2c4-ccc6c4e9e12b
-- Status: experimental
-- Level: high
-- Author: Christian Burkard (Nextron Systems)
-- Date: 2021-11-24
-- Tags: attack.command-and-control, attack.t1105
-- Description: Detects a suspicious CertReq execution downloading a file.
-- This behavior is often used by attackers to download additional payloads or configuration files.
-- Certreq is a built-in Windows utility used to request and retrieve certificates from a certification authority (CA). However, it can be abused by threat actors for malicious purposes.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (((CommandLine ILIKE '%-config%' OR CommandLine ILIKE '%/config%')) AND ((CommandLine ILIKE '%-Post%' OR CommandLine ILIKE '%/Post%')) AND (CommandLine ILIKE '%http%') AND ((Image ILIKE '%\\certreq.exe') OR (OriginalFileName = 'CertReq.exe')))
