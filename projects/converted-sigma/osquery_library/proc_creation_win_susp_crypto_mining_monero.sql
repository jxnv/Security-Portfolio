-- Title: Potential Crypto Mining Activity
-- ID: 66c3b204-9f88-4d0a-a7f7-8a57d521ca55
-- Status: stable
-- Level: high
-- Author: Florian Roth (Nextron Systems)
-- Date: 2021-10-26
-- Tags: attack.impact, attack.t1496
-- Description: Detects command line parameters or strings often used by crypto miners
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM processes WHERE (((CommandLine LIKE '% --cpu-priority=%' OR CommandLine LIKE '%--donate-level=0%' OR CommandLine LIKE '% -o pool.%' OR CommandLine LIKE '% --nicehash%' OR CommandLine LIKE '% --algo=rx/0 %' OR CommandLine LIKE '%stratum+tcp://%' OR CommandLine LIKE '%stratum+udp://%' OR CommandLine LIKE '%LS1kb25hdGUtbGV2ZWw9%' OR CommandLine LIKE '%0tZG9uYXRlLWxldmVsP%' OR CommandLine LIKE '%tLWRvbmF0ZS1sZXZlbD%' OR CommandLine LIKE '%c3RyYXR1bSt0Y3A6Ly%' OR CommandLine LIKE '%N0cmF0dW0rdGNwOi8v%' OR CommandLine LIKE '%zdHJhdHVtK3RjcDovL%' OR CommandLine LIKE '%c3RyYXR1bSt1ZHA6Ly%' OR CommandLine LIKE '%N0cmF0dW0rdWRwOi8v%' OR CommandLine LIKE '%zdHJhdHVtK3VkcDovL%')) AND NOT (((CommandLine LIKE '% pool.c %' OR CommandLine LIKE '% pool.o %' OR CommandLine LIKE '%gcc -%'))))
