-- Title: Shell Execution Of Process Located In Tmp Directory
-- ID: 2fade0b6-7423-4835-9d4f-335b39b83867
-- Status: test
-- Level: high
-- Author: Joseliyo Sanchez, @Joseliyo_Jstnk
-- Date: 2023-06-02
-- Tags: attack.execution
-- Description: Detects execution of shells from a parent process located in a temporary (/tmp) directory
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE (ParentImage ILIKE '/tmp/%' AND (Image ILIKE '%/bash' OR Image ILIKE '%/csh' OR Image ILIKE '%/dash' OR Image ILIKE '%/fish' OR Image ILIKE '%/ksh' OR Image ILIKE '%/sh' OR Image ILIKE '%/zsh'))
