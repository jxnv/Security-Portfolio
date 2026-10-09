-- Title: Suspicious Access to Sensitive File Extensions - Zeek
-- ID: 286b47ed-f6fe-40b3-b3a8-35129acd43bc
-- Status: test
-- Level: medium
-- Author: Samir Bousseaden, @neu5ron
-- Date: 2020-04-02
-- Tags: attack.collection
-- Description: Detects known sensitive file extensions via Zeek
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((name ILIKE '%.pst' OR name ILIKE '%.ost' OR name ILIKE '%.msg' OR name ILIKE '%.nst' OR name ILIKE '%.oab' OR name ILIKE '%.edb' OR name ILIKE '%.nsf' OR name ILIKE '%.bak' OR name ILIKE '%.dmp' OR name ILIKE '%.kirbi' OR name ILIKE '%.rdp'))
