-- Title: Setuid and Setgid
-- ID: c21c4eaa-ba2e-419a-92b2-8371703cbe21
-- Status: test
-- Level: low
-- Author: Ömer Günal
-- Date: 2020-06-16
-- Tags: attack.persistence, attack.privilege-escalation, attack.t1548.001
-- Description: Detects suspicious change of file privileges with chown and chmod commands
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '% chmod u+s%' OR CommandLine ILIKE '% chmod g+s%')) AND (CommandLine ILIKE '%chown root%'))
