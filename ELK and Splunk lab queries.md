# ELK queries

## A hunt for well-known PowerShell Offensive Frameworks and commands

```
winlog.event_data.ScriptBlockText:(PowerUp OR Mimikatz OR NinjaCopy OR Get-ModifiablePath OR AllChecks OR AmsiBypass OR PsUACme OR Invoke-DLLInjection OR Invoke-ReflectivePEInjection OR Invoke-Shellcode OR Get-GPPPassword OR Get-Keystrokes OR Get-TimedScreenshot OR PowerView)
```
<br>

## A hunt for suspicious parent process spawning PowerShell

we'll look into Sysmon's Process creation events, event id 1:

```
winlog.event_data.ParentImage:(*mshta.exe OR *rundll32.exe OR *regsvr32.exe OR *services.exe OR *winword.exe OR *wmiprvse.exe OR *powerpnt.exe OR *excel.exe OR *msaccess.exe OR *mpub.exe OR *visio.exe OR *outlook.exe OR *chrome.exe OR *iexplorer.exe OR *sqlserver.exe) AND winlog.event_data.Image : *powershell.exe
```
<br>

## Perform a hunt for renamed PowerShell.exe

```
winlog.event_data.Description:*PowerShell AND NOT (winlog.event_data.Image:*powershell.exe OR winlog.event_data.Image:*powershell_ise.exe)
```
<br>

## Perform a hunt for base64-encoded PowerShell commands

```
(winlog.event_data.Description:*PowerShell OR  winlog.event_data.Image:*powershell.exe) AND winlog.event_data.CommandLine:*-e*
```
<br>

## Perform a hunt for execution of an assembly from file by PowerShell

```
winlog.event_data.ScriptBlockText:((*Load*) AND (*ReadAllBytes* OR *LoadFile*))
```
<br>

## Perform a hunt for PowerShell commands downloading content

```
winlog.event_data.ScriptBlockText:(*WebClient* OR *DownloadData* OR *DownloadFile* OR *DownloadString* OR *OpenRead* OR *WebRequest* OR *curl* OR *wget* OR *RestMethod* OR *WinHTTP* OR *InternetExplorer.Application* OR *Excel.Application* OR *Word.Application* OR *Msxml2.XMLHTTP* OR *MsXML2.ServerXML* OR *System.XML.XMLDocument* OR *BitsTransfer*)
```
<br>

## Hunt for malicious use of rundll32

```
process.name:rundll32.exe AND (process.args:pcwutl.dll AND process.args:LaunchApplication)
```
<br>

## Hunt for UAC Bypass

filtering for Sysmon's Event ID 7 -- Image loaded.

```
event.id:7 AND (process.name:cliconfg.exe AND file.path:NTWDBLIB.dll)
```
<br>

## Hunt for UAC Bypass #2

```
event.id:13 AND registry_key_path:"shell\\runas\\command\\isolatedCommand"
```
<br>

## Hunt for RDP Settings tampering

```
event.id:1 AND (process.name:netsh.exe AND (process.args:localport=3389 AND process.args:action=allow))
```
<br>

## Hunt for DCSync

```
event.id:4662 AND NOT (user.name:*$ OR user.name:AUTHORITY OR user.name:Window) AND (object.properties:1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 OR object.properties:Replicating)
```
<br>

## Hunt for Remote WMI Usage

![alt text](image.png)

```
event.id:4648 AND process.executable:WMIC.exe
```
<br>

## Hunt for LOLBAS openurl

```
process.executable:rundll32.exe AND process.args:(url.dll OR ieframe.dll OR shdocvw.dll)
```
<br>

## Hunt for persistence through scheduled Tasks

The detection is based on Sysmon Event ID 1 - Process Creation.

```
event.id:1 AND ((process.executable:schtasks.exe AND process.args:create) OR process.executable:at.exe)
```

Once the query is executed, we'll get the following match:
![alt text](image-1.png)