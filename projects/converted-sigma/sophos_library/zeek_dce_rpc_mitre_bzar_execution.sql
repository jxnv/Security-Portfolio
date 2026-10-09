-- Title: MITRE BZAR Indicators for Execution
-- ID: b640c0b8-87f8-4daa-aef8-95a24261dd1d
-- Status: test
-- Level: medium
-- Author: @neu5ron, SOC Prime
-- Date: 2020-03-19
-- Tags: attack.privilege-escalation, attack.persistence, attack.execution, attack.t1047, attack.t1053.002, attack.t1569.002
-- Description: Windows DCE-RPC functions which indicate an execution techniques on the remote system. All credit for the Zeek mapping of the suspicious endpoint/operation field goes to MITRE
-- Converted by: Sigma Universal SIEM/EDR CLI

SELECT * FROM process_journal WHERE ((endpoint = 'JobAdd' AND operation = 'atsvc') OR (endpoint = 'svcctl' AND operation = 'StartServiceW') OR (endpoint = 'ITaskSchedulerService' AND operation = 'SchRpcEnableTask') OR (endpoint = 'ITaskSchedulerService' AND operation = 'SchRpcRegisterTask') OR (endpoint = 'ITaskSchedulerService' AND operation = 'SchRpcRun') OR (endpoint = 'IWbemServices' AND operation = 'ExecMethod') OR (endpoint = 'IWbemServices' AND operation = 'ExecMethodAsync') OR (endpoint = 'svcctl' AND operation = 'CreateServiceA') OR (endpoint = 'svcctl' AND operation = 'CreateServiceW') OR (endpoint = 'svcctl' AND operation = 'StartServiceA'))
