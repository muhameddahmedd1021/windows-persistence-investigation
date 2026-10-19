# Requires an elevated Windows PowerShell 5.1 session on a disposable lab Windows VM.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('Prepare','Install','Trigger','Snapshot','Cleanup','RestoreAuditing')][string]$Phase,
      [string]$OutputDirectory='C:\ProgramData\SocPersistenceLab\exports')
$ErrorActionPreference = 'Stop'
$root = 'C:\ProgramData\SocPersistenceLab'
$public = 'C:\Users\Public\SOC-Lab'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run elevated in the lab VM.' }
function Invoke-Checked([string]$Program,[string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed: $LASTEXITCODE" }
}
function Get-LabState {
    if (-not (Test-Path "$root\state.json")) { throw 'Run Prepare first.' }
    Get-Content "$root\state.json" -Raw | ConvertFrom-Json
}
function Save-LabState($Value) { $Value | ConvertTo-Json -Depth 8 | Set-Content "$root\state.json" -Encoding UTF8 }
function Get-LabWmi([string]$Class) { Get-CimInstance -Namespace root/subscription -ClassName $Class }
function Test-LabWmiBinding($Binding) {
    # Binding references may be relative even when the referenced objects' __PATH
    # values are absolute. Match compound keys independently of object existence.
    $labReferences=@('__EventFilter.Name="SOC-Lab-WMI"','CommandLineEventConsumer.Name="SOC-Lab-WMI"')
    foreach($reference in @([string]$Binding.Filter,[string]$Binding.Consumer)) {
        $path=New-Object System.Management.ManagementPath($reference)
        if($path.RelativePath -in $labReferences) { return $true }
    }
    return $false
}
function Assert-NoExistingObjects {
    foreach($n in @('SOC-Lab-Task','SOC-Lab-Control')) {
        if(Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue) { throw "Task already exists: $n" }
    }
    if(Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'SOC-Lab-Run' -ErrorAction SilentlyContinue) { throw 'Run value already exists.' }
    foreach($c in @('__EventFilter','CommandLineEventConsumer')) {
        if(Get-LabWmi $c | Where-Object Name -eq 'SOC-Lab-WMI') { throw "WMI object already exists: $c" }
    }
}
function Export-LabEvidence {
    $s = Get-LabState
    New-Item $OutputDirectory -ItemType Directory -Force | Out-Null
    $channels = @('Security','Microsoft-Windows-Sysmon/Operational','Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-TaskScheduler/Operational','Microsoft-Windows-WMI-Activity/Operational')
    $coverage = @()
    $jsonPath = Join-Path $OutputDirectory 'events.jsonl'
    $writer = New-Object IO.StreamWriter($jsonPath,$false,(New-Object Text.UTF8Encoding($false)))
    try {
        foreach($channel in $channels) {
            $safe = $channel -replace '[/\\]','_'
            $filter = @{LogName=$channel;StartTime=[datetime]::Parse($s.started_utc)}
            if($channel -eq 'Security') { $filter.Id = @(4688,4698,4699,4700,4701,4702,4624) }
            $readErrors = @()
            $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue -ErrorVariable readErrors)
            $readFailures = @($readErrors | Where-Object { $_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*' })
            $coverage += [pscustomobject]@{channel=$channel;events=$events.Count;read_error=($readFailures.Count -gt 0);read_failure_messages=@($readFailures | ForEach-Object { $_.Exception.Message });collected_utc=(Get-Date).ToUniversalTime().ToString('o')}
            # Raw XML is the source of truth; normalized JSON is an ingestion convenience.
            $raw = New-Object IO.StreamWriter((Join-Path $OutputDirectory "$safe.xml"),$false,(New-Object Text.UTF8Encoding($false)))
            $raw.WriteLine('<Events>')
            foreach($event in $events | Sort-Object TimeCreated,RecordId) {
                $xmlText = $event.ToXml(); $raw.WriteLine($xmlText)
                [xml]$x = $xmlText
                $fields = [ordered]@{}
                foreach($d in $x.Event.EventData.Data) {
                    $name=[string]$d.Name
                    if($name) { $fields[$name]=[string]$d.'#text' }
                }
                $row = [ordered]@{utc=$event.TimeCreated.ToUniversalTime().ToString('o');run_id=$s.run_id;event_id=$event.Id;provider=$event.ProviderName;channel=$channel;computer=$event.MachineName;record_id=$event.RecordId;event_process_id=[string]$x.Event.System.Execution.ProcessID;event_thread_id=[string]$x.Event.System.Execution.ThreadID;event_user_sid=[string]$x.Event.System.Security.UserID;data=$fields}
                $writer.WriteLine(($row | ConvertTo-Json -Depth 12 -Compress))
            }
            $raw.WriteLine('</Events>');$raw.Dispose()
            & wevtutil.exe epl $channel (Join-Path $OutputDirectory "$safe.evtx") /ow:true
            if($LASTEXITCODE -ne 0) { Write-Warning "EVTX export failed: $channel" }
        }
    } finally { $writer.Dispose() }
    $coverage | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $OutputDirectory 'coverage.json') -Encoding UTF8
    [pscustomobject]@{captured_utc=(Get-Date).ToUniversalTime().ToString('o');path=$PSCommandPath;sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash} | ConvertTo-Json | Set-Content "$root\snapshots\exporter-source-hash.json" -Encoding UTF8
    Copy-Item "$root\state.json" $OutputDirectory -Force
    Copy-Item "$root\markers" (Join-Path $OutputDirectory 'markers') -Recurse -Force
    if(Test-Path "$root\snapshots") { Copy-Item "$root\snapshots" $OutputDirectory -Recurse -Force }
    $hashPath=Join-Path $OutputDirectory 'hashes.csv'
    $filesToHash=@(Get-ChildItem $OutputDirectory -File -Recurse | Where-Object FullName -ne $hashPath)
    $filesToHash | Get-FileHash -Algorithm SHA256 | Select-Object Path,Hash | Export-Csv $hashPath -NoTypeInformation
}
switch($Phase) {
 'Prepare' {
    if(Test-Path "$root\state.json") { throw 'Existing run found. Preserve it before creating another run.' }
    Assert-NoExistingObjects
    foreach($p in @($root,"$root\markers","$root\snapshots",$public)) { New-Item $p -ItemType Directory -Force | Out-Null }
    # The logon task can use a limited token; grant only its creator write access
    # to this lab's marker folder, rather than assuming elevation at trigger time.
    $markerAcl=Get-Acl "$root\markers"
    $markerRule=New-Object Security.AccessControl.FileSystemAccessRule($identity.User,'Modify','ContainerInherit,ObjectInherit','None','Allow')
    $markerAcl.AddAccessRule($markerRule)
    Set-Acl -LiteralPath "$root\markers" -AclObject $markerAcl
    $s=[ordered]@{run_id=[guid]::NewGuid().ToString();started_utc=(Get-Date).ToUniversalTime().ToString('o');host_name=$env:COMPUTERNAME;creator=$identity.Name;creator_sid=$identity.User.Value;initial_boot_utc=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o');cleanup_utc=$null;phase='prepared'}
    Save-LabState $s
    Invoke-Checked 'auditpol.exe' @('/backup',"/file:$root\audit-before.csv")
    Invoke-Checked 'auditpol.exe' @('/set','/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}','/success:enable')
    Invoke-Checked 'auditpol.exe' @('/set','/subcategory:{0CCE9227-69AE-11D9-BED3-505054503030}','/success:enable')
    $settings=@(
      @{path='HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit';name='ProcessCreationIncludeCmdLine_Enabled'},
      @{path='HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging';name='EnableScriptBlockLogging'})
    $backup=@()
    foreach($item in $settings) {
       $old=Get-ItemProperty -LiteralPath $item.path -Name $item.name -ErrorAction SilentlyContinue
       $backup += [pscustomobject]@{path=$item.path;name=$item.name;existed=($null -ne $old);value=if($old){$old.($item.name)}else{$null}}
       if(-not (Test-Path -LiteralPath $item.path)) { New-Item $item.path -Force | Out-Null }
       New-ItemProperty -LiteralPath $item.path -Name $item.name -PropertyType DWord -Value 1 -Force | Out-Null
    }
    $backup | ConvertTo-Json -Depth 5 | Set-Content "$root\registry-before.json" -Encoding UTF8
    Invoke-Checked 'wevtutil.exe' @('sl','Microsoft-Windows-TaskScheduler/Operational','/e:true')
    & auditpol.exe /get /category:* /r | Set-Content "$root\snapshots\audit-after.csv"
    if($LASTEXITCODE -ne 0) { throw 'Audit policy verification export failed.' }
    Copy-Item "$PSScriptRoot\Write-Marker.ps1" "$public\Write-Marker.ps1"
    Copy-Item "$PSScriptRoot\Write-Marker.ps1" "$root\Write-Marker.ps1"
    $osInfo=Get-CimInstance Win32_OperatingSystem
    [pscustomobject]@{WindowsProductName=$osInfo.Caption;WindowsVersion=$osInfo.Version;OsBuildNumber=$osInfo.BuildNumber;CsName=$env:COMPUTERNAME;OsLastBootUpTime=$osInfo.LastBootUpTime.ToUniversalTime().ToString("o")} | ConvertTo-Json | Set-Content "$root\snapshots\environment.json"
    $os=Get-CimInstance Win32_OperatingSystem
    [pscustomobject]@{computer=$env:COMPUTERNAME;user=$identity.Name;system_drive=$os.SystemDrive;windows_directory=$os.WindowsDirectory;user_profile=$env:USERPROFILE} | ConvertTo-Json | Set-Content "$root\snapshots\identity-and-paths.json"
    @($public,$root) | ForEach-Object { $acl=Get-Acl -LiteralPath $_; [pscustomobject]@{path=$_;owner=$acl.Owner;sddl=$acl.Sddl} } | ConvertTo-Json | Set-Content "$root\snapshots\directory-acls.json"

    Get-FileHash -Algorithm SHA256 -LiteralPath @("$PSScriptRoot\Invoke-Lab.ps1","$PSScriptRoot\Write-Marker.ps1","$PSScriptRoot\..\config\sysmon-lab.xml") | Select-Object Path,Algorithm,Hash | ConvertTo-Json | Set-Content "$root\snapshots\source-hashes.json" -Encoding UTF8
    $PSVersionTable.PSVersion.ToString() | Set-Content "$root\snapshots\powershell-version.txt"
    Write-Host "Prepared run $($s.run_id)" -ForegroundColor Green
 }
 'Install' {
    $s=Get-LabState
    if($s.phase -ne 'prepared') { throw "Unexpected phase: $($s.phase)" }
    Assert-NoExistingObjects
    $exe="$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $trigger=New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
    $principal=New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
    $settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $act=New-ScheduledTaskAction -Execute $exe -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+$public+'\Write-Marker.ps1" -Case Task')
    Register-ScheduledTask -TaskName 'SOC-Lab-Task' -Action $act -Trigger $trigger -Principal $principal -Settings $settings -Description 'Isolated SOC lab; writes only a marker.' | Out-Null
    $ctrl=New-ScheduledTaskAction -Execute $exe -Argument ('-NoProfile -ExecutionPolicy Bypass -File "'+$root+'\Write-Marker.ps1" -Case Control')
    Register-ScheduledTask -TaskName 'SOC-Lab-Control' -Action $ctrl -Trigger $trigger -Principal $principal -Settings $settings -Description 'Known lab inventory control.' | Out-Null
    if(-not (Test-Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')) { New-Item 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Force | Out-Null }
    New-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'SOC-Lab-Run' -PropertyType String -Value ('"'+$exe+'" -NoProfile -ExecutionPolicy Bypass -File "'+$public+'\Write-Marker.ps1" -Case Registry') | Out-Null
    $filter=Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{Name='SOC-Lab-WMI';EventNamespace='root\cimv2';QueryLanguage='WQL';Query="SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'whoami.exe'"}
    $consumer=Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{Name='SOC-Lab-WMI';ExecutablePath=$exe;CommandLineTemplate=('"'+$exe+'" -NoProfile -ExecutionPolicy Bypass -File "'+$public+'\Write-Marker.ps1" -Case WMI')}
    Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$filter;Consumer=$consumer} | Out-Null
    Export-ScheduledTask -TaskName 'SOC-Lab-Task' | Set-Content "$root\snapshots\task.xml" -Encoding Unicode
    Export-ScheduledTask -TaskName 'SOC-Lab-Control' | Set-Content "$root\snapshots\control-task.xml" -Encoding Unicode
    Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' | ConvertTo-Json | Set-Content "$root\snapshots\run-key.json"
    Get-LabWmi __EventFilter | Where-Object Name -eq 'SOC-Lab-WMI' | Select-Object Name,Query,EventNamespace | ConvertTo-Json | Set-Content "$root\snapshots\wmi-filter.json"
    $s.phase='installed';Save-LabState $s
    Write-Host 'Task, Run key and permanent WMI subscription registered. Registration is not proof of execution.' -ForegroundColor Yellow
 }
 'Trigger' {
    $s=Get-LabState
    if($s.phase -ne 'installed') { throw 'Only trigger installed cases.' }
    Start-ScheduledTask -TaskName 'SOC-Lab-Task'
    Start-ScheduledTask -TaskName 'SOC-Lab-Control'
    & "$env:SystemRoot\System32\whoami.exe" | Out-Host
    Write-Host 'Task requested manually; WMI condition generated. Logon cases need an actual new logon.'
 }
 'Snapshot' { Export-LabEvidence;Write-Host "Evidence exported to $OutputDirectory" -ForegroundColor Green }
 'Cleanup' {
    $s=Get-LabState
    if($identity.User.Value -ne $s.creator_sid) { throw 'Cleanup must run as original creator (HKCU ownership).' }
    # Remove bindings first, including orphan references from an interrupted cleanup.
    $filterObjects=@(Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='SOC-Lab-WMI'")
    $consumerObjects=@(Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='SOC-Lab-WMI'")
    foreach($binding in Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding) {
       if(Test-LabWmiBinding $binding) { $binding | Remove-WmiObject }
    }
    $consumerObjects | Remove-WmiObject
    $filterObjects | Remove-WmiObject
    foreach($name in @('SOC-Lab-Task','SOC-Lab-Control')) { Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue }
    Remove-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'SOC-Lab-Run' -ErrorAction SilentlyContinue
    $left=@{
       tasks=@('SOC-Lab-Task','SOC-Lab-Control' | ForEach-Object { Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue }).Count
       wmi_filters=@(Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='SOC-Lab-WMI'").Count
       wmi_consumers=@(Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='SOC-Lab-WMI'").Count
       wmi_bindings=@(Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { Test-LabWmiBinding $_ }).Count
       run_value=[bool](Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'SOC-Lab-Run' -ErrorAction SilentlyContinue)
    }
    $left | ConvertTo-Json | Set-Content "$root\snapshots\cleanup.json"
    @((Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding) | Select-Object Filter,Consumer) | ConvertTo-Json -Depth 5 | Set-Content "$root\snapshots\cleanup-wmi-bindings.json"
    if($left.tasks -or $left.wmi_filters -or $left.wmi_consumers -or $left.wmi_bindings -or $left.run_value) { throw 'Cleanup incomplete; inspect cleanup.json.' }
    $s.phase='cleaned';$s.cleanup_utc=(Get-Date).ToUniversalTime().ToString('o');Save-LabState $s
    Write-Host 'Lab triggers removed. Keep marker scripts until post-cleanup verification finishes.' -ForegroundColor Green
 }
 'RestoreAuditing' {
    $s=Get-LabState
    if($s.phase -ne 'cleaned') { throw 'Cleanup first.' }
    Invoke-Checked 'auditpol.exe' @('/restore',"/file:$root\audit-before.csv")
    foreach($item in (Get-Content "$root\registry-before.json" -Raw | ConvertFrom-Json)) {
      if($item.existed) { Set-ItemProperty $item.path -Name $item.name -Value $item.value }
      else { Remove-ItemProperty $item.path -Name $item.name -ErrorAction SilentlyContinue }
    }
    Write-Host 'Original audit policy and two registry settings restored. Sysmon uninstall is separate.'
 }
}
