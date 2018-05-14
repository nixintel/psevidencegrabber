#Live Forensic Powershell Script

# The script gathers data in the order of volatility, with the most volatile elements being gathered first.
# Please note the data is gathered in order of volatility, but not presented in order of volatility.

# Acknowledgements:
#
# Phil Chapman of Firebrand Training (www.firebrandtraining.co.uk) who came up with the original volatile data script. 
# The WLAN password gathering command in this script is from Phil's original.
#
# This script is provided "as is" and may be used, edited, shared, or modified in any way provided acknowledgement is given.


#Start of script

# Ensures running as admin, exit if not:

if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit } 


$Logo = @"

 ___  ___     ___     _    _                  ___          _    _             
 | _ \/ __|___| __|_ _(_)__| |___ _ _  __ ___ / __|_ _ __ _| |__| |__  ___ _ _ 
 |  _/\__ \___| _|\ V / / _` / -_) ' \/ _/ -_) (_ | '_/ _` | '_ \ '_ \/ -_) '_|
 |_|  |___/   |___|\_/|_\__,_\___|_||_\__\___|\___|_| \__,_|_.__/_.__/\___|_|  
                                                                               

"@





Write-Host""
Write-Host "Welcome to Powershell Evidence Grabber v 1.0.1!"
Write-Host ""
Write-Host "PS Evidence Grabber is a Powershell Script designed to collect volatile data for live forensic examinations."
Write-Host "The script is designed to run on 64-bit Windows Systems only."
Write-Host ""
Write-Host "Script designed by Steven Harris https://github.com/ipversion7"
Write-Host ""
Write-Host ""
Write-Host ""



#Get user defined variables for appending to the final report

$drive  = Read-Host -Prompt 'Input the Harvest Drive Letter'

$filename = Read-Host -Prompt "Enter Filename"

$operator = Read-Host -Prompt "Enter Investigator Name"

$case = Read-Host -Prompt "Enter Case Reference"

$exhibit = Read-Host -Prompt "Enter Exhibit Reference"

$location = Read-Host -Prompt "Enter examination location"

$description = Read-Host -Prompt "Enter description of device e.g. 'Asus Laptop'"

$currenttime = Get-Date -Format "dd'-'MM'-'yyyy HH':'mm':'ss"

#Output file destination

$OutputDest = "${drive}:\${filename}.html"

Write-host ""
Write-host "Script is running. This may take several minutes...."

##################################################
# Network Information and Settings               #
##################################################

#Information about network devices and settings

Write-host ""
Write-host "Gathering Network Information..."


#Gets DNS cache. Replaces ipconfig /dislaydns

$DNSCache = Get-DnsClientCache | select Entry,Name, Status, TimeToLive, Data | ConvertTo-Html -fragment

$NetworkAdapter = Get-WmiObject -class Win32_NetworkAdapter  | Select-Object -Property AdapterType,ProductName,Description,MACAddress,Availability,NetconnectionStatus,NetEnabled,PhysicalAdapter | ConvertTo-Html -Fragment


#Replaces ipconfig:

 
$IPConfiguration = Get-WmiObject Win32_NetworkAdapterConfiguration |  select Description, @{Name='IpAddress';Expression={$_.IpAddress -join '; '}}, @{Name='IpSubnet';Expression={$_.IpSubnet -join '; '}}, MACAddress, @{Name='DefaultIPGateway';Expression={$_.DefaultIPGateway -join '; '}}, DNSDomain, DNSHostName, DHCPEnabled, ServiceName | convertTo-Html -fragment
$NetIPAddress = Get-NetIPaddress | select InterfaceAlias, IPaddress, EnabledState, OperatingStatus | ConvertTo-Html -fragment 
$NetConnectProfile = Get-NetConnectionProfile | select Name, InterfaceAlias, NetworkCategory, IPV4Connectivity, IPv6Connectivity | ConvertTo-Html -fragment 
$NetAdapter = Get-NetAdapter | select Name, InterfaceDescription, Status, MacAddress, LinkSpeed | ConvertTo-Html -fragment

#Replaces arp -a:

$NetNeighbor = Get-NetNeighbor | select InterfaceAlias, IPAddress, LinkLayerAddress | ConvertTo-Html -fragment

#Replaces netstat commands

$NetTCPConnect = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}| ConvertTo-Html -Fragment


#Get Wi-fi Names and Passwords

$WlanPasswords = netsh.exe wlan show profiles | Select-String "\:(.+)$" | %{$wlanname=$_.Matches.Groups[1].Value.Trim(); $_} | %{(netsh wlan show profile name="$wlanname" key=clear)}  | Select-String "Key Content\W+\:(.+)$" | %{$wlanpass=$_.Matches.Groups[1].Value.Trim(); $_} | %{[PSCustomObject]@{ PROFILE_NAME=$wlanname;PASSWORD=$wlanpass }} | ConvertTo-Html -fragment

#Get Firewall Information. Replaces netsh firewall show config

$FirewallRule = Get-NetFirewallRule | select-object Name, DisplayName, Description, Direction, Action, EdgeTraversalPolicy, Owner, EnforcementStatus | ConvertTo-Html -fragment 


#Display active samba sessions (servers only - Win 2012 onwards)

$SMBSessions = Get-SMBSession -ea silentlycontinue | convertTo-Html -fragment


#Display active samba shares

$SMBShares = Get-SMBShare | select description, path, volume | convertTo-Html -fragment

##################################################
# User & Account Info                            #
##################################################


#Gets information about user accounts

Write-host ""
Write-host "Gathering User and Account Information..."

$currentuser = Get-WMIObject -class Win32_ComputerSystem | select username | ConvertTo-Html -Fragment
$systemname = Get-WmiObject -Class Win32_ComputerSystem | select Name, DNSHostName, Domain, Manufacturer, Model, PrimaryOwnerName, TotalPhysicalMemory, Workgroup   | ConvertTo-Html -Fragment 
$useraccounts = Get-WmiObject -Class Win32_UserAccount  | Select-Object -Property AccountType,Domain,LocalAccount,Name,PasswordRequired,SID,SIDType | ConvertTo-Html -fragment
$logonsession = Get-WmiObject -Class Win32_LogonSession | Select-Object -Property LogonID,LogonType,StartTime,  @{Name='Start Time';Expression={$_.ConvertToDateTime($_.starttime)}}  | ConvertTo-Html -fragment
$userprofiles = Get-WmiObject -Class Win32_UserProfile | Select-object -property Caption, LocalPath, SID, @{Name='Last Used';Expression={$_.ConvertToDateTime($_.lastusetime)}} | ConvertTo-Html -Fragment 

##################################################
# System Info                                    #
##################################################

#Gets information the device and OS

Write-host ""
Write-host "Gathering Device and Operating System Information..."

#Environment Settings
$env = Get-ChildItem ENV: | select name, value | convertto-html -fragment 

#System Info
$systeminfo = Get-WmiObject -Class Win32_ComputerSystem  | Select-Object -Property Name,Caption,SystemType,Manufacturer,Model,DNSHostName,Domain,PartOfDomain,WorkGroup,CurrentTimeZone,PCSystemType,HyperVisorPresent | ConvertTo-Html -Fragment 

#OS Info
$OSinfo = Get-WmiObject -Class Win32_OperatingSystem   | Select-Object -Property Name, Description,Version,BuildNumber,InstallDate,SystemDrive,SystemDevice,WindowsDirectory,LastBootupTime,Locale,LocalDateTime,NumberofUsers,RegisteredUser,Organization,OSProductSuite | ConvertTo-Html -Fragment

#Hotfixes
$Hotfixes = Get-Hotfix | Select-Object -Property CSName, Caption,Description, HotfixID, InstalledBy, InstalledOn | ConvertTo-Html -fragment 

#Logical drives (current session)
$LogicalDrives = get-wmiobject win32_logicaldisk | select DeviceID, DriveType, FreeSpace, Size, VolumeName | ConvertTo-Html -fragment



##################################################
# Live Running Processes                         #
##################################################

#Captures all live running processes

Write-host ""
Write-host "Gathering Running Process Information..."

$Processes = Get-Process | Select Handles, StartTime, PM, VM, SI, id, ProcessName, Path, Product, FileVersion | ConvertTo-Html -Fragment 

#Items set to run on startup

$StartupProgs = Get-WmiObject Win32_StartupCommand | select Command, User, Caption | ConvertTo-Html -fragment 

##################################################
# Settings from the Registry					 #
##################################################

Write-host ""
Write-host "Gathering Key Registry Settings..."

#Gets list of USB devices

$USBDevices = Get-ItemProperty -Path HKLM:\System\CurrentControlSet\Enum\USB*\*\* | select FriendlyName, Driver, mfg, DeviceDesc | ConvertTo-Html -fragment  

#Gets list of installed applications and devices


#Identifies any connected/previously connected webcams
$Imagedevice = Get-PnpDevice  -class 'image' -EA SilentlyContinue |  ConvertTo-Html -Fragment

#All currently connected PNP devices
$UPNPDevices = Get-PnpDevice -PresentOnly -class 'USB', 'DiskDrive', 'Mouse', 'Keyboard', 'Net', 'Image', 'Media', 'Monitor' | ConvertTo-Html -Fragment

#All previously connected disk drives not currently accounted for. Useful if target computer has had drive replaced/hidden
$UnknownDrives = Get-PnpDevice  -class 'diskdrive' -status 'unknown' | ConvertTo-Html -Fragment

#Installed Applications
$InstalledApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | ConvertTo-Html -Fragment

#Gets all link files created in last 180 days. Perhaps export this as a separate CSV and make it keyword searchable?

$LinkFiles = Get-WmiObject Win32_ShortcutFile | select Filename, Caption, @{NAME='CreationDate';Expression={$_.ConvertToDateTime($_.CreationDate)}}, @{Name='LastAccessed';Expression={$_.ConvertToDateTime($_.LastAccessed)}}, @{Name='LastModified';Expression={$_.ConvertToDateTime($_.LastModified)}}, Target | Where-Object {$_.LastModified -gt ((Get-Date).AddDays(-180)) } | sort LastModified -Descending | ConvertTo-Html -Fragment 

#Gets last 100 days worth of Powershell History

$PSHistory = Get-History -count 100 | select id, commandline, startexecutiontime, endexecutiontime | ConvertTo-Html -fragment

#All items in Downloads folder

$Downloads = Get-ChildItem C:\Users\*\Downloads\* -recurse  |  select  PSChildName, Root, Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes  | ConvertTo-Html -Fragment

#End time date stamp

$endtimecheck = Get-Date -Format "dd'-'MM'-'yyyy HH':'mm':'ss"

Write-host ""
Write-host "Compiling Final Report..."

# Popup message upon completion

(New-Object -ComObject wscript.shell).popup("Script Completed. Please check the HTML file before continuing.")


#Styles the HTML output for obtained data. Future versions of PSEG will have better styled HTML!

$head = '<style> 
BODY{font-family:calibri; background-color: #ffffff;}
TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;} 
TH{font-size:1.1em; border-width: 1px;padding: 2px;border-style: solid;border-color: black;background-color: #53fb26} 
TD{border-width:1px;padding: 2px;border-style: solid;border-color: black;background-color:white} 
</style>'

#Determines header appearance on first page of report

ConvertTo-Html -Head $head -Title "Live Forensic Script Output For $description $exhibit"  >$OutputDest

#Case information

"<center>">> $OutputDest
"<h2> Case reference: $case </h2><br>" >> $outputdest

"<h2> Examiner Name: $operator </h2><br>" >> $OutputDest

"<h2>Exhibit reference: $exhibit Device: $description Examination Location: $location </h2><br>" >> $OutputDest


"<h3> Current Time and Date: $currenttime </h3><br>" >>$OutputDest
"</center>">> $OutputDest

#I need to tidy up the HTML in the code and the final output. These anchors will function as shortcuts to the relevant data but they don't work yet.

#"<h3><u>Shortcuts</u></h3><br>">>$OutputDest
#"<h4><a href="#users">User & Account Information</a></h4><br>" >>$OutputDest
#"<h4><a href="#system">System Information</a></h4><br>" >>$OutputDest
#"<h4><a href="#network">Network Information</a></h4><br>" >>$OutputDest
#"<h4><a href="#processes">Running & Startup Processes</a></h4><br>" >>$OutputDest
#"<h4><a href="#devices">Linked Device Information</a></h4><br>" >>$OutputDest
#"<h4><a href="#end">End of document</a></h4><br>" >>$OutputDest



"<h2><u>User and Account Information</u></h2>" >> $OutputDest
"<h3>Current Logged On User</h3><table>$CurrentUser</table><br>" >> $OutputDest
"<h3>Computer Information</h3><table>$SystemName</table><br>" >> $OutputDest
"<h3>User Account Information</h3><table>$UserAccounts</table><br>" >> $OutputDest
"<h3>Logon Session History</h3><table>$LogonSession</table><br>" >> $OutputDest
"<h3>Associated User Profiles</h3><table>$UserProfiles</table><br>" >> $OutputDest

"<br><br>">> $OutputDest


"<h2><u>Device and Operating System Information</u></h2>" >> $OutputDest
"<h3>Computer Environment Settings</h3><table>$env</table>" >> $OutputDest
"<h3>System and Domain Information<h3><table>$SystemInfo</table><br>" >> $OutputDest
"<h3>Operating System Information</h3><table>$OSInfo</table><br>" >> $OutputDest
"<h3>Disk Drives (Logical, Current Session)</h3><table>$LogicalDrives</table><br>" >> $OutputDest
"<h3>Hotfix History</h3><table>$Hotfixes</table><br>" >> $OutputDest


"<br><br>">> $OutputDest


"<h2><u>Network Information</u></h2>" >> $OutputDest
"<h3>Network Adapter Information</h3><table>$NetworkAdapter</table><br>" >> $OutputDest
"<h3>Current IP Configuration</h3><table>$IPConfiguration</table><br>" >> $OutputDest
"<h3>Network Adapter IP Addresses - IPv4 and v6</h3><table>$NetIPaddress</table><br>" >> $OutputDest
"<h3>Current Connection Profiles</h3><table>$NetConnectProfile</table><br>" >> $OutputDest
"<h3>Associated WiFi Networks and Passwords</h3><table>$WlanPasswords</table><br>" >> $OutputDest
"<h3>Address Resolution Protocol Cache</h3><table>$NetNeighbor</table><br>" >> $OutputDest
"<h3>Current TCP Connections and Associated Processes</h3><table>$NetTCPConnect</table><br>" >> $OutputDest
"<h3>DNS Cache</h3><table>$DNSCache</table><br>" >> $OutputDest
"<h3>Current Firewall Rules</h3><table>$FirewallProfile</table><br>" >> $OutputDest
"<h3>Active SMB sessions (if this device is a server) </h3><table>$SMBSessions</table><br>" >> $OutputDest
"<h3>Active SMB Shares on this device </h3><table>$SMBShares</table><br>" >> $OutputDest


"<br><br>">> $OutputDest


"<h2><u>Running Processes</u></h2>" >> $OutputDest
"<h3>Current Running Processes</h3><table>$Processes</table><br>" >> $OutputDest
"<h3>Programmes Set To Run At Startup</h3><table>$StartupProgs</table><br>" >> $OutputDest
"<h3>All Installed Apps</h3><table>$InstalledApps</table><br>" >> $OutputDest
"<h3>Link files (Created in Last 180 Days)</h3><table>$LinkFiles</table><br>" >> $OutputDest
"<h3>Powershell Command History (last 50 commands by default, blank if none stored or recovered)</h3><table>$PSHistory</table><br>" >> $OutputDest
"<h3>Contents of C:/Users/Downloads</h3><table>$Downloads</table><br>" >> $OutputDest
"<br><br>" >> $OutputDest



"<h2><u>Connected Device Information</u></h2>" >> $OutputDest
"<h3>Current Connected Devices(Hardware & Logical)</h3><table>$UPNPDevices</table><br>" >> $OutputDest
"<h3>USB Device History</h3><table>$USBDevices</table><br>" >> $OutputDest
"<h3>Image-capable Devices e.g. Webcams (connected and historic - blank if none detected)</h3><table>$ImageDevice</table><br>" >> $OutputDest
"<h3>Previously Associated Disk Drives (not currently active and/or connected)</h3><table>$UnknownDrives</table><br>" >> $OutputDest


"<br><br>" >> $OutputDest

#Footer

"<center>" >> $OutputDest
"<h3> Evidence gathered from  $description ($exhibit)  by  $operator at: $Endtimecheck </h3>" >>$OutputDest
"</center>" >> $OutputDest


Write-host ""
Write-host "Script completed. Please check the final report before continuing."
