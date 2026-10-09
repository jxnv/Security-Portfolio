-- Title: Nslookup PowerShell Download Cradle
-- ID: 999bff6d-dc15-44c9-9f5c-e1051bfc86e1
-- Status: test
-- Level: medium
-- Author: Sai Prashanth Pulisetti @pulisettis, Aishwarya Singam
-- Date: 2022-12-10
-- Tags: attack.execution, attack.t1059.001
-- Description: Detects a powershell download cradle using nslookup. This cradle uses nslookup to extract payloads from DNS records.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((Data LIKE '%powershell%' AND Data LIKE '%nslookup%' AND Data LIKE '%[1]%') AND (Data LIKE '%-q=txt http%' OR Data LIKE '%-querytype=txt http%' OR Data LIKE '%-type=txt http%'))
