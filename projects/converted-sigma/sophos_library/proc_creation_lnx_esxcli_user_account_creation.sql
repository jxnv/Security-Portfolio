-- Title: ESXi Account Creation Via ESXCLI
-- ID: b28e4eb3-8bbc-4f0c-819f-edfe8e2f25db
-- Status: test
-- Level: medium
-- Author: Cedric Maurugeon
-- Date: 2023-08-22
-- Tags: attack.persistence, attack.execution, attack.t1136, attack.t1059.012
-- Description: Detects user account creation on ESXi system via esxcli
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (Image ILIKE '%/esxcli' AND (CommandLine ILIKE '%system %' AND CommandLine ILIKE '%account %' AND CommandLine ILIKE '%add %'))
