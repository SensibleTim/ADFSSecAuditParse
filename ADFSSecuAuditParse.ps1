#File name in evtx format, username, othercriteria, $filepath
PARAM ($SearchCriteria, $PastDays = 1, $PastHours)
#************************************************
# ADFSSecAuditParse.ps1
# Version 1.0
# Date: 2-2-2016
# Author: Tim Springston
# Description: This script will parse an ADFS Security event log file (EVTX)
#  and search for audit events related to a specific user or other criteria.
#  The script will work for the each ADFS login instance for a given criteria during a stated time frame.
#  If you need to locate a second then filter and save the event log to focus in.
# Return an array of initial instance IDs with the criteria, run the search function against each and output
# a unique text file for each.
#************************************************

cls
if ($PastHours -gt 0)
	{
	$PastPeriod = (Get-Date).AddHours(-($PastHours))
	}
	else
		{$PastPeriod = $PastDays}
	
$CS = get-wmiobject -class win32_computersystem
$Hostname = $CS.Name + '.' + $CS.Domain
$Instances = @()
Get-Winevent -ComputerName $Hostname -LogName Security  | Where-Object {(($_.ID -eq 501) `
-and ($_.Properties.Value -contains $SearchCriteria) -and ($_.TimeCreated -gt $PastPeriod))} | % { $Instances += $_.Properties[0].Value}

function FindADFSAuditEvents		{ 
	param ($valuetomatch, $counter, $instance, $PastPeriod)
		$Results = $pwd.Path + "\" + $SearchCriteria + "-ADFSSecAudit" + '-' + $Counter + ".txt"	
		$SearchString = $SearchCriteria + ", source AD FS Auditing, event ID 501 and instance " + $Instance + " in Security event log."
		"Security Audit Events which match $SearchString" | Out-File $Results -Encoding UTF8 
		Get-WinEvent -ComputerName $Hostname -LogName Security  -WarningAction SilentlyContinue | `
		#Where-Object -ErrorAction SilentlyContinue {($_.TimeCreated -gt $PastPeriod) -and (($_.ID -eq 501) -or ($_.ID -eq 500) -or ($_.ID -eq 299) -or ($_.ID -eq 400)) -and (($_.Properties -contains $ValueToMatch) -or ($_.Properties[0].Value -match $Instance))}  | % {
		Where-Object -ErrorAction SilentlyContinue {($_.TimeCreated -gt $PastPeriod) -and (($_.Properties -contains $ValueToMatch) -or ($_.Properties[0].Value -match $Instance))}  | % {
		$Event = New-object PSObject
		add-member -inputobject $Event -membertype noteproperty -name "Event ID" -value $_.ID
		add-member -inputobject $Event -membertype noteproperty -name "Provider" -value $_.ProviderName
		add-member -inputobject $Event -membertype noteproperty -name "Machine Name" -value $_.MachineName
		add-member -inputobject $Event -membertype noteproperty -name "User ID" -value $_.UserID
		add-member -inputobject $Event -membertype noteproperty -name "Time Created " -value $_.TimeCreated		
		$Event | FL *
		$Event | Out-File $Results -Encoding UTF8  -Append
		$_.Properties | FL *
		$_.Properties | Out-File $Results -Encoding UTF8  -Append
		$DateTimeExport = $_.TimeCreated
		}
	$DateTime = (($DateTimeExport.ToShortDateString()).Replace('/','-') + '@' + (($DateTimeExport.ToShortTimeString()).Replace(' ','')))
	$DateTime = $DateTime.Replace(':','')
	$Results2 = $pwd.Path + "\" + $SearchCriteria + '-' + $DateTime + "-ADFSSecAudit" + $Counter + ".txt"
	Rename-Item -Path $Results -NewName $Results2
	}	

$Counter = 1
foreach ($instance in $Instances)
	{
	FindADFSAuditEvents -ValueToMatch $SearchCriteria  -Instance $Instance -PastPeriod $PastPeriod -Counter $Counter
	$Counter++
	}
