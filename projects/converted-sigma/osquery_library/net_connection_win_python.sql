-- Title: Python Initiated Connection
-- ID: bef0bc5a-b9ae-425d-85c6-7b2d705980c6
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2021-12-10
-- Tags: attack.discovery, attack.t1046
-- Description: Detects a Python process initiating a network connection. While this often relates to package installation, it can also indicate a potential malicious script communicating with a C&C server.
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM file WHERE ((Initiated = 'true' AND (Image LIKE '%\\python%' AND Image LIKE '%.exe%')) AND NOT (((DestinationIp = '127.0.0.1' AND SourceIp = '127.0.0.1') OR ((CommandLine LIKE '%pip.exe%' AND CommandLine LIKE '%install%')))) AND NOT (((ParentImage = 'C:\\ProgramData\\Anaconda3\\Scripts\\conda.exe' AND (CommandLine LIKE '%:\\ProgramData\\Anaconda3\\Scripts\\conda-script.py%' AND CommandLine LIKE '%update%')) OR (ParentImage = 'C:\\ProgramData\\Anaconda3\\python.exe' AND CommandLine LIKE '%C:\\ProgramData\\Anaconda3\\Scripts\\jupyter-notebook-script.py%'))))
