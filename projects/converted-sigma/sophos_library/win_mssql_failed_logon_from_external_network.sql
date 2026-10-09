-- Title: MSSQL Server Failed Logon From External Network
-- ID: ebfe73c2-5bc9-4ed9-aaa8-8b54b2b4777d
-- Status: test
-- Level: medium
-- Author: j4son
-- Date: 2023-10-11
-- Tags: attack.credential-access, attack.t1110
-- Description: Detects failed logon attempts from clients with external network IP to an MSSQL server. This can be a sign of a bruteforce attack.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Provider_Name ILIKE '%MSSQL%' AND EventID = 18456) AND NOT (((Data ILIKE '%CLIENT: 10.%' OR Data ILIKE '%CLIENT: 172.16.%' OR Data ILIKE '%CLIENT: 172.17.%' OR Data ILIKE '%CLIENT: 172.18.%' OR Data ILIKE '%CLIENT: 172.19.%' OR Data ILIKE '%CLIENT: 172.20.%' OR Data ILIKE '%CLIENT: 172.21.%' OR Data ILIKE '%CLIENT: 172.22.%' OR Data ILIKE '%CLIENT: 172.23.%' OR Data ILIKE '%CLIENT: 172.24.%' OR Data ILIKE '%CLIENT: 172.25.%' OR Data ILIKE '%CLIENT: 172.26.%' OR Data ILIKE '%CLIENT: 172.27.%' OR Data ILIKE '%CLIENT: 172.28.%' OR Data ILIKE '%CLIENT: 172.29.%' OR Data ILIKE '%CLIENT: 172.30.%' OR Data ILIKE '%CLIENT: 172.31.%' OR Data ILIKE '%CLIENT: 192.168.%' OR Data ILIKE '%CLIENT: 127.%' OR Data ILIKE '%CLIENT: 169.254.%' OR Data ILIKE '%CLIENT: <local machine>%'))))
