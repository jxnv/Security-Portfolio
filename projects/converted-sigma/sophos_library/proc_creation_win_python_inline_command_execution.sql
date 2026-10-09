-- Title: Python Inline Command Execution
-- ID: 899133d5-4d7c-4a7f-94ee-27355c879d90
-- Status: test
-- Level: medium
-- Author: Nasreddine Bencherchali (Nextron Systems)
-- Date: 2023-01-02
-- Tags: attack.execution, attack.t1059
-- Description: Detects execution of python using the "-c" flag. This is could be used as a way to launch a reverse shell or execute live python code.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE (((CommandLine ILIKE '% -c%') AND ((OriginalFileName = 'python.exe') OR ((Image ILIKE '%python.exe' OR Image ILIKE '%python3.exe' OR Image ILIKE '%python2.exe')))) AND NOT ((((ParentImage ILIKE 'C:\\Program Files\\Python%' OR ParentImage ILIKE 'C:\\Program Files (x86)\\Python%') AND ParentImage ILIKE '%\\python.exe' AND ParentCommandLine ILIKE '%-E -s -m ensurepip -U --default-pip%') OR ((ParentImage ILIKE 'C:\\Program Files\\Python%' OR ParentImage ILIKE 'C:\\Program Files (x86)\\Python%') AND (CommandLine ILIKE '%-W ignore::DeprecationWarning%' AND CommandLine ILIKE '%['install', '--no-cache-dir', '--no-index', '--find-links',%' AND CommandLine ILIKE '%'--upgrade', 'pip'%')))) AND NOT ((((CommandLine ILIKE '%<pip-setuptools-caller>%' AND CommandLine ILIKE '%exec(compile(%')) OR ((ParentImage ILIKE '%\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe') OR ((ParentImage = 'C:\\Program Files\\Microsoft VS Code\\Code.exe' OR ParentImage = 'C:\\Program Files (x86)\\Microsoft VS Code\\Code.exe'))))))
