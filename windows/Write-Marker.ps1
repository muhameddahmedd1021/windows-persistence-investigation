param([Parameter(Mandatory=$true)][ValidateSet('Task','Registry','WMI','Control')][string]$Case)
$ErrorActionPreference = 'Stop'
$root = 'C:\ProgramData\SocPersistenceLab'
if (-not (Test-Path "$root\state.json")) { throw 'Lab state missing; refusing to write.' }
$state = Get-Content "$root\state.json" -Raw | ConvertFrom-Json
$me = Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
$record = [ordered]@{
    utc = (Get-Date).ToUniversalTime().ToString('o')
    run_id = $state.run_id
    case = $Case
    user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    pid = $PID
    parent_pid = $me.ParentProcessId
    host_name = $env:COMPUTERNAME
    boot_utc = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
}
# Separate files avoid concurrent task, logon and WMI writers corrupting each other.
$record | ConvertTo-Json -Compress | Add-Content "$root\markers\$Case.jsonl" -Encoding UTF8
