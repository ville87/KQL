# KQL
KQL queries for Defender and Sentinel

# Sentinel
## PowerShell Related
Get all PowerShell execution with downloads:   
```
union DeviceProcessEvents, DeviceNetworkEvents, DeviceEvents
| where TimeGenerated > ago(7d)
| where FileName in~ ("powershell.exe", "powershell_ise.exe")
| where ProcessCommandLine has_any("WebClient", "DownloadFile", "DownloadData", "DownloadString", "WebRequest", "Shellcode", "http", "https")
| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, RemoteIP, RemoteUrl, RemotePort, RemoteIPType
| extend IPCustomEntity = RemoteIP
| extend URLCustomEntity = RemoteUrl
| extend HostCustomEntity = DeviceName
```
Source: https://github.com/rod-trent/SentinelKQL/blob/master/PowerShellExecutionwithDownload.txt   

# Defender Advanced Hunting
Any ps1 in command line:   
```
DeviceProcessEvents
| where TimeGenerated > ago(2h)
| where DeviceName == "2nslt-pf49ybw8"
| where ProcessCommandLine contains ".ps1"  // Filtering for scripts
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```