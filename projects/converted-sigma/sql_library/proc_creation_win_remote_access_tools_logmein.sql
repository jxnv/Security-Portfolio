-- Title: Remote Access Tool - LogMeIn Execution
-- ID: d85873ef-a0f8-4c48-a53a-6b621f11729d
-- Status: test
-- Level: medium
-- Author: frack113
-- Date: 2022-02-11
-- Tags: attack.command-and-control, attack.t1219.002
-- Description: An adversary may use legitimate desktop support and remote access software, such as Team Viewer, Go2Assist, LogMein, AmmyyAdmin, etc, to establish an interactive command and control channel to target systems within networks.
-- These services are commonly used as legitimate technical support software, and may be allowed by application control within a target environment.
-- Remote access tools like VNC, Ammyy, and Teamviewer are used frequently when compared with other legitimate software commonly used by adversaries. (Citation: Symantec Living off the Land)
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM security_logs WHERE ((Description = 'LMIGuardianSvc') OR (Product = 'LMIGuardianSvc') OR (Company = 'LogMeIn, Inc.'))
