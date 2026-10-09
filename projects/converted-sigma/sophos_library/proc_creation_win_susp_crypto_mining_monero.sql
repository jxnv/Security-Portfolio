-- Title: Potential Crypto Mining Activity
-- ID: 66c3b204-9f88-4d0a-a7f7-8a57d521ca55
-- Status: stable
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-10-26
-- Tags: attack.impact, attack.t1496
-- Description: Detects command line parameters or strings often used by crypto miners
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '% --cpu-priority=%' OR CommandLine ILIKE '%--donate-level=0%' OR CommandLine ILIKE '% -o pool.%' OR CommandLine ILIKE '% --nicehash%' OR CommandLine ILIKE '% --algo=rx/0 %' OR CommandLine ILIKE '%stratum+tcp://%' OR CommandLine ILIKE '%stratum+udp://%' OR CommandLine ILIKE '%LS1kb25hdGUtbGV2ZWw9%' OR CommandLine ILIKE '%0tZG9uYXRlLWxldmVsP%' OR CommandLine ILIKE '%tLWRvbmF0ZS1sZXZlbD%' OR CommandLine ILIKE '%c3RyYXR1bSt0Y3A6Ly%' OR CommandLine ILIKE '%N0cmF0dW0rdGNwOi8v%' OR CommandLine ILIKE '%zdHJhdHVtK3RjcDovL%' OR CommandLine ILIKE '%c3RyYXR1bSt1ZHA6Ly%' OR CommandLine ILIKE '%N0cmF0dW0rdWRwOi8v%' OR CommandLine ILIKE '%zdHJhdHVtK3VkcDovL%')) AND NOT (((CommandLine ILIKE '% pool.c %' OR CommandLine ILIKE '% pool.o %' OR CommandLine ILIKE '%gcc -%'))))
