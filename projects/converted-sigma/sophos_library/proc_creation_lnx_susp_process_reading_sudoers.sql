-- Title: Access of Sudoers File Content
-- ID: 0f79c4d2-4e1f-4683-9c36-b5469a665e06
-- Status: test
-- Level: medium
-- Author: Florian Roth (Nextron Systems)
-- Date: 2022-06-20
-- Tags: attack.reconnaissance, attack.t1592.004
-- Description: Detects the execution of a text-based file access or inspection utilities to read the content of /etc/sudoers in order to potentially list all users that have sudo rights.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((Image ILIKE '%/cat' OR Image ILIKE '%/ed' OR Image ILIKE '%/egrep' OR Image ILIKE '%/emacs' OR Image ILIKE '%/fgrep' OR Image ILIKE '%/grep' OR Image ILIKE '%/head' OR Image ILIKE '%/less' OR Image ILIKE '%/more' OR Image ILIKE '%/nano' OR Image ILIKE '%/tail') AND CommandLine ILIKE '% /etc/sudoers%')
