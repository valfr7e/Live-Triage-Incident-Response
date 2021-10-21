# Live-Triage-Incident-Response
Constantly updating with useful scripts and one liners to conduct live triage / incident response. Blue/Purple teaming.
Also adding some individual response scripts in the files section.
 
 ## Basics / Persistence common locations
 Basic triage and common persistence search
 
 
 
 ### Get services with powershell
 ```reg query HKLM\SYSTEM\CurrentControlSet\Services /s /v "ImagePath"
 gwmi win32_service | FL Name,PathName | Out-String 
 ```
 ### Get scheduled tasks
 ``` schtasks -v (*output in verbose mode*)```
 
 ### Export scheduled tasks
```$taskPath = "*"
$outcsv = "c:\tasksdetail.csv"
Get-ScheduledTask -TaskPath $taskPath | ForEach-Object { [pscustomobject]@{
Name = $_.TaskName
Path = $_.TaskPath
LastResult = $(($_ | Get-ScheduledTaskInfo).LastTaskResult)
NextRun = $(($_ | Get-ScheduledTaskInfo).NextRunTime)
Status = $_.State
Command = $_.Actions.execute
Arguments = $_.Actions.Arguments }} |
Export-Csv -Path $outcsv -NoTypeInformation 
```
### Get Processes
``` Get-Process winword, explorer | Format-List *
Get-Process | Select-Object StartTime, ProcessName, ID, path
Get-CimInstance win32_Process | Select-Object Name, CreationDate, ProcessName, ProcessID, CommandLine, ParentProcessId 
 ```
### Get Windows Firewall Rules
```netsh advfirewall firewall show rule name=all ```

### Get installed programs
```
Get-CimInstance win32_product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, Localpackage
   Get-ItemProperty “HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\”
 ```
### Persistent startup items
```Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\"
wmic startup list full
wmic startup list brief
Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | FL | Out-string
```
### Current opened files
```openfiles /local on ```

### Current opened explorer windows
```reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "DesktopProcess" /t REG_DWORD /d "0" /f
Get-Process | Where-Object {$_.mainWindowTitle} | Format-Table Id, Name, mainWindowtitle -AutoSize
```
### DLL search order hijacking

```“HKEY_LOCAL_MACHINE\Software\Classes\AppID\{BD07DDB9-1C61-4DCE-9202-A2BA1757CDB2}”```

*Replace with process id/CID*

### COM hijacking
```
reg query "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID" /s /f "{3AD05575-8857-4850-9277-11B85BDB8E09}”
reg query "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{3AD05575-8857-4850-9277-11B85BDB8E09}" /s
reg query "HKLM\SOFTWARE\Classes\AppID\{3AD05575-8857-4850-9277-11B85BDB8E09}"
Reg query HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{3AD05575-8857-4850-9277-11B85BDB8E09} /v AppID /t REG_SZ /d {3AD05575-8857-4850-9277-11B85BDB8E09}
Reg query HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Classes\AppID\{3AD05575-8857-4850-9277-11B85BDB8E09}
```
 ## Search and Destroy
 How to search files easily and remove common persistence
 
 
 
 ### Search by hash
```Get-ChildItem “C:\Windows\ -Recurse | Get-FileHash -Algorithm SHA256 | Where-Object hash -eq 26aa1b557e3bc6e91dc92345c6b982fed98276f082549159dfb0d39770e7c827 | Select path```

 ### Search by filename
``` Get-ChildItem -Path “C:” -Recurse | Where-Object { !$PsIsContainer -and [System.IO.Path]::GetFileNameWithoutExtension($_.Name) -eq “MozillaFirefox” } | % { $_.FullName } ```

 ### Search by file extension 
 ```
Get-ChildItem -Path "C:\code\" -Filter *.bat -r | % { $_.Name.Replace( “.bat”,””) } 
```
 ### Or simply use wildcards and Get-childItem on Powershell
 
 ```
 ex. Get-ChildItem "c:\windows\*.bat"
        Get-ChildItem "c:\windows\temp.*"
        Get-ChildItem "c:\users\*\appdata\localtemp\*.bat" 
```
 ### Search for files without extensions

```Get-ChildItem -Path C:\Users\[user]\AppData -Recurse -Exclude *.* -File -Force -ea SilentlyContinue``
 
 ### Delete registry Key
 
 ```reg delete 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\' /v Malicious /f```
 
 ### Give full permission to files to remove them later
```
$acl = Get-Acl "C:\ProgramData\path\filepath"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("everyone","FullControl","Allow")
$acl.SetAccessRule($accessRule)
$acl | Set-Acl "C:\ProgramData\path\filepath"
```
 ### Uninstall software

```
Get-CimInstance win32_product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, Localpackage
$MyApp = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "CrowdStrike Firmware Analysis"}
$MyApp.Uninstall(“CrowdStrike Firmware Analysis”)
```

 ### Clean scheduled tasks cache

```reg delete `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\*´ ```
 
 ### Stop process and remove the file that is using it (Unkillable process)

```
$allProcesses = Get-Process
foreach ($process in $allProcesses) 
{$process.Modules | where {$_.FileName -eq "malicious.bat"} | Stop-Process}
Remove-Item "malicious.bat" -force -recurse
```

### Delete cached credentials

```$Credentials = (cmdkey /list | Where-Object {$_ -like “*Target=*"})
Foreach ($Target in $Credentials) {
    $Target = ($Target -split (":", 2) | Select-Object -Skip 1).substring(1)
    $Argument = "/delete:" + $Target
    Start-Process Cmdkey -ArgumentList $Argument -NoNewWindow -RedirectStandardOutput $False
```
### kill tasks

```taskkill /f /t /im malicious.exe```

### Delete files

```del "C:\Program Files\RealVNC\VNC Server\vncserver.exe" -force -recurse
Remove-Item "C:\Program Files\RealVNC\VNC Server\vncserver.exe" -force -recurse
```
*Can use force / recurse parameters*

### Delete scheduled tasks

```
schtasks /delete /tn Malicious /F
```

### List eventlogs
``` Get-WinEvent -LogName "Windows Powershell"
Get-EventLog -list
Get-WinEvent -Listlog * | Select RecordCount,LogName 
Get-WinEvent -Listlog *operational | Select RecordCount,LogName
wmic nteventlog list brief

Get-EventLog Application | Select -Unique Source
Get-WinEvent -FilterHashtable @{ LogName='Application'; ProviderName='Outlook'}
Get-WinEvent -FilterHashtable @{ LogName='OAlerts';} | FL TimeCreated, Message ```

```
