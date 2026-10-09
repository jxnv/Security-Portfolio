-- Title: Nslookup PowerShell Download Cradle
-- ID: 999bff6d-dc15-44c9-9f5c-e1051bfc86e1
-- Status: test
-- Level: medium
-- Author: Sai Prashanth Pulisetti @pulisettis, Aishwarya Singam
-- Date: 2022-12-10
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects a powershell download cradle using nslookup. This cradle uses nslookup to extract payloads from DNS records.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Data ILIKE '%powershell%' AND Data ILIKE '%nslookup%' AND Data ILIKE '%[1]%') AND (Data ILIKE '%-q=txt http%' OR Data ILIKE '%-querytype=txt http%' OR Data ILIKE '%-type=txt http%'))
