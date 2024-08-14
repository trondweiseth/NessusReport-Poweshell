<#
.SYNOPSIS
    Nessus script
.DESCRIPTION
    Script to download single nessusreport(s) or in bulk and parse through them all.
.PARAMETER Get-NessusReports
    [-List] [-AddAPIKeys] [-Folder <int32>] [-SelectScans] [-Format [csv|html](Default:csv)] [-RotateReports(Default:Yes)]
.PARAMETER NessusQuery
    [[-CVEScore] <string[]>] [[-CVE] <string[]>] [[-Risk] <string[]>] [[-HostName] <string[]>] [[-Description] <string[]>] [[-Name] <string[]>] 
    [[-PluginOutput] <string[]>] [[-Solution] <string[]>] [[-Synopsis] <string[]>] [[-Protocol] <string[]>] [[-PluginID] <string[]>] [[-Exclude] <string[]>] 
    [[-Sort] <string[]>] [-OutputFull]
.PARAMETER Nessus-Diff
    None
.PARAMETER Export-Nessusreports
    [[-Path] <path[]>] [Default($HOME)]] [[-File] <string[]>]
.INPUTS
    None
.OUTPUTS
    None
.NOTES
    Version:        1.0
    Author:         Trond Weiseth
    Creation Date:  29.08.2022
    Purpose/Change: Initial script development
.EXAMPLE
    None
#>

# Setting variable for scipt path
$Global:scriptpath = $PSScriptRoot

Function Get-NessusReports {
    param
    (
        [Parameter(Mandatory=$false)]
        [switch]$List,

        [Parameter(Mandatory=$false)]
        [string]$Folder,

        [Parameter(Mandatory=$false)]
        [switch]$SelectScans,

        [Parameter(Mandatory=$false)]
        [string[]]$Id,

        [Parameter(Mandatory=$false)]
        [validateset('csv','html')]
        [string[]]$Format = 'csv',

        [Parameter(Mandatory=$false)]
        [string]$SaveTo,

        [Parameter(Mandatory=$false)]
        [validateset('Yes','No')]
        [string]$RotateReports = 'Yes',

        [Parameter(Mandatory=$false)]
        [switch]$AddAPIkeys,

        [Parameter(Mandatory=$false)]
        [string[]]$ServerName = ('NESSUS_SERVER_ADDRESS'),

        [Parameter(Mandatory=$false)]
        [validateset('vuln_by_host','vuln_hosts_summary','vuln_by_plugin','remediations')]
        [string]$Chapter = 'vuln_hosts_summary'
    )

# Disable ssl validation
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3, [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12

    # Global parameters
    $Global:FileFormat = $Format
    $Global:BasePath   = "$HOME\NessusReports"
    $Global:prevpath   = "$BasePath\PreviousNessusScan"
    if ($SaveTo) {$Global:path = $SaveTo}
    else {$Global:path = "$BasePath\CurrentNessusScan"}

    # File structuring for diff comparison
    if ($RotateReports -eq 'Yes') {
        if (!$List -and $Format -ne 'html' -and !$AddAPIkeys) {
            if (!(Test-Path $BasePath)) {[void](New-Item -Path $HOME -Name NessusReports -ItemType Directory)}
            if (!(Test-Path $BasePath\CurrentNessusScan)) {[void](New-Item -Path $BasePath -Name CurrentNessusScan -ItemType Directory)}
            if (!(Test-Path $BasePath\PreviousNessusScan)) {[void](New-Item -Path $BasePath -Name PreviousNessusScan -ItemType Directory)}
            [void](Remove-Item -Path $BasePath\PreviousNessusScan\* -Force -Recurse)
            [void](Move-Item $BasePath\CurrentNessusScan\* -Destination $BasePath\PreviousNessusScan -Force)
        }
    }

    # Fetching Nessus scan(s)
    function scans {
        $error.Clear()
        # Parameters
        $scans                 = @{
            "Uri"              = "$Base_URL/scans"
            "Method"           = "GET"
            "Headers"          = @{
                "Accept"       = "application/json"
                "Content-Type" = "application/json"
                "X-ApiKeys"    = "accessKey=$($AccessKey); secretKey=$($SecretKey)"

            }
        }
        try {
            $scansres = Invoke-WebRequest @scans -ErrorAction Stop -UseBasicParsing
            while ($null -eq $scansres) {Start-Sleep 1}
            $Json = $scansres | ConvertFrom-Json
            if ($SelectScans) {
                $Json.scans | Select-Object folder_id,name,status,id | Where-Object {$_.status -ne 'empty'} | Out-GridView -PassThru
            }
            else {
                $Json.scans | Select-Object folder_id,name,status,id | Where-Object {$_.status -ne 'empty'}
            }
        }
        catch {
            if ($Error[0] -imatch 'Invalid Credentials') {
                Write-Host -ForegroundColor Red -BackgroundColor Black "Wrong credentials! Run Add-NessusAPIkeys to generate new key pair"
            }
            else {
                Write-Output $Error[0]
            }
        }
    }
    
    # Create ScriptBlock for export and download functions
    $scriptBlock = {
        param($ScanID, $FileFormat, $Chapter, $AccessKey, $SecretKey, $path, $Base_URL)

        # Exporting Nessus scan(s)
        function export {
            $error.Clear()
            # Parameters
            $BodyParams   = @{
                "format"  ="$f"
                "chapters"="$Chapter"
                } | ConvertTo-Json
            $export                = @{
                "Uri"              = "$Base_URL/scans/$ScanID/export"
                "Method"           = "POST"
                "Headers"          = @{
                    "format"       = "$f"
                    "Accept"       = "application/json"
                    "Content-Type" = "application/json"
                    "X-ApiKeys"    = "accessKey=$($AccessKey); secretKey=$($SecretKey)"
                }
            }
            try {
                $exportres = Invoke-WebRequest @export -Body $BodyParams -UseBasicParsing
                $Json = $exportres | ConvertFrom-Json
                $Global:FileID = $Json.file
            }
            catch {
                if ($error[0] -imatch "The requested file was not found") {return}
                else {$error[0];return}
            }
        }

        # Downloads Nessus scan(s)
        function download {
            $error.Clear()
            $download           = @{
                "Uri"           = "$Base_URL/scans/$ScanID/export/$FileID/download"
                "Method"        = "GET"
                "Headers"       = @{
                    "Accept"    = "application/octet-stream"
                    "X-ApiKeys" = "accessKey=$($AccessKey); secretKey=$($SecretKey)"
                }
            }
            try {
                $download = Invoke-WebRequest @download -ErrorAction Stop -UseBasicParsing
                $content  = [System.Net.Mime.ContentDisposition]::new($download.Headers["Content-Disposition"])
                $Global:fileName = $content.FileName
                $fullPath = Join-Path -Path $path -ChildPath $fileName
                $file     = [System.IO.FileStream]::new($fullPath, [System.IO.FileMode]::Create)
                $file.Write($download.Content, 0, $download.RawContentLength)
                $file.Close()
                Write-Output "Download for $fileName completed" 
            }
            catch {
                if ($error[0] -imatch "Report is still being generated") {Start-Sleep 2;download}
                if ($error[0] -imatch "The requested file was not found") {return}
                else {$error[0];return}
            }
        }

        # Export and download scan(s)
        foreach ($Global:f in $FileFormat) {
            export
            download
        }
    }

    # Adding nessus API keys for the script to use
    function Add-APIkeys {
        $key    = Read-Host -Prompt "Accesskey for $Server" -AsSecureString
        $key    | ConvertFrom-SecureString > $scriptpath\${server}_key.txt
        $secret = Read-Host -Prompt "Secret for $Server" -AsSecureString
        $secret | ConvertFrom-SecureString > $scriptpath\${server}_secret.txt
    }

    # Main execution
    $ServerName | % {

        $Global:Server     = $_
        $Global:Base_URL   = "https://${Server}:8834"
        $Global:success=$false

        if ($AddAPIkeys) {
            Add-APIkeys
            return
        }
        if (!(Test-Path $scriptpath\${server}_key.txt) -or !(Test-Path $scriptpath\${server}_secret.txt)) {
            Write-Host -ForegroundColor Red -BackgroundColor Black "Missing Nessus API keys! Use parameter -AddAPIkeys to add new pair for $Server."
            return
        }

        # Nessus key pair
        $Global:AccessKey = $($key = get-content $scriptpath\${server}_key.txt       | ConvertTo-SecureString ; [pscredential]::new('user',$key).GetNetworkCredential().Password)
        $Global:SecretKey = $($secret = get-content $scriptpath\${server}_secret.txt | ConvertTo-SecureString ; [pscredential]::new('user',$secret).GetNetworkCredential().Password)
        
        if ($list) {scans}
        else {
            if ($Folder) {
                Write-Host -ForegroundColor Yellow "Downloading report(s) from $Server to $path"
                $ScanIDs = (scans | ? {$_.folder_id -eq $Folder}).id
                # Create RunspacePool
                $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, [int]$ScanIDs.Count)
                $RunspacePool.ApartmentState = "STA"
                $RunspacePool.Open()

                # Create and execute Runspace for each scan
                $Runspaces = foreach ($ScanID in $ScanIDs) {
                    $Runspace = [PowerShell]::Create().AddScript($scriptBlock).AddParameter("ScanID", $ScanID).AddParameter("FileFormat", $FileFormat).AddParameter("Chapter", $Chapter).AddParameter("AccessKey", $AccessKey).AddParameter("SecretKey", $SecretKey).AddParameter("path", $path).AddParameter("Base_URL", $Base_URL)
                    $Runspace.RunspacePool = $RunspacePool
                    $Handle = $Runspace.BeginInvoke()
                    [PSCustomObject] @{
                        Runspace = $Runspace
                        Handle = $Handle
                    }
                }

                # Wait for all Runspaces to complete and store the results in an array
                $Results = foreach ($Runspace in $Runspaces) {
                    $Runspace.Runspace.EndInvoke($Runspace.Handle)
                }

                # Returning output from srciptblock
                $results | where {$_ -imatch 'pss'} | % {Write-Host -f Green $_}

                # Clean up RunspacePool
                $RunspacePool.Close()
                $RunspacePool.Dispose()
                }
            else {
                Write-Host -ForegroundColor Yellow "Downloading report(s) from $Server to $path"
                if ($Id) { $ScanIDs = $Id }
                else { $ScanIDs = (scans).id }
                # Create RunspacePool
                $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, [int]$ScanIDs.Count)
                $RunspacePool.ApartmentState = "STA"
                $RunspacePool.Open()

                # Create and execute Runspace for each scan
                $Runspaces = foreach ($ScanID in $ScanIDs) {
                    $Runspace = [PowerShell]::Create().AddScript($scriptBlock).AddParameter("ScanID", $ScanID).AddParameter("FileFormat", $FileFormat).AddParameter("Chapter", $Chapter).AddParameter("AccessKey", $AccessKey).AddParameter("SecretKey", $SecretKey).AddParameter("path", $path).AddParameter("Base_URL", $Base_URL)
                    $Runspace.RunspacePool = $RunspacePool
                    $Handle = $Runspace.BeginInvoke()
                    [PSCustomObject] @{
                        Runspace = $Runspace
                        Handle = $Handle
                    }
                }

                # Wait for all Runspaces to complete and store the results in an array
                $Results = foreach ($Runspace in $Runspaces) {
                    $Runspace.Runspace.EndInvoke($Runspace.Handle)
                }

                # Returning output from srciptblock
                return $results | where {$_ -imatch 'pss'}

                # Clean up RunspacePool
                $RunspacePool.Close()
                $RunspacePool.Dispose()

                }
        }
    }
}

# Importing downloaded nessus scan(s) to funtion Nessusreport
Function Import-NessusReports {
    param
    (
        [string]$File,
        [switch]$Previous
    )
    $path                                = "$HOME\NessusReports\CurrentNessusScan"
    $prevpath                            = "$HOME\NessusReports\PreviousNessusScan"
    if ($File) {$Global:NessusReports = Import-Csv $File}
    if($Previous) {$Global:NessusReports = Import-Csv -Path $prevpath (Get-ChildItem -Path $path -Filter '*.csv').FullName}
    else {$Global:NessusReports          = Import-Csv -Path (Get-ChildItem -Path $path -Filter '*.csv').FullName}
    Write-Host -ForegroundColor Cyan 'Nessusreports imported to function Nessusreport'
}

# Output nessusreport(s)
Function Nessusreport {
    if (!$NessusReports) { Import-NessusReports }
    Write-Output $NessusReports
}

# Predefined parsing through nessus report(s)
$Global:SortValidSet = @('Host', 'Name', 'Title', 'risk', 'CVE', "'CVSS v2.0 Base Score'")
$Global:RiskValidateSet = @('Critical', 'High', 'Medium', 'Low', 'None')
Function NessusQuery {
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [String[]]$CVEScore,

        [Parameter()]
        [String[]]$CVE,

        [Parameter()]
        [ArgumentCompleter( {
                param ( $commandName,
                    $parameterName,
                    $wordToComplete,
                    $commandAst,
                    $fakeBoundParameters )
                $ValidRiskSet = $RiskValidateSet | Where-Object -FilterScript { $_ -imatch $wordToComplete }
                return $ValidRiskSet
            } )]
        [String[]]$Risk,

        [Parameter()]
        [String[]]$HostName,

        [Parameter()]
        [String[]]$Description,

        [Parameter()]
        [String[]]$Name,

        [Parameter()]
        [String[]]$PluginOutput,

        [Parameter()]
        [String[]]$Solution,

        [Parameter()]
        [String[]]$Synopsis,

        [Parameter()]
        [String[]]$Protocol,

        [Parameter()]
        [String[]]$PluginID,

        [Parameter()]
        [switch]$FixedVersion,

        [Parameter()]
        [String[]]$Exclude = '!#¤%&/()=',

        [Parameter()]
        [ArgumentCompleter( {
                param ( $commandName,
                    $parameterName,
                    $wordToComplete,
                    $commandAst,
                    $fakeBoundParameters )
                $ValidSortSet = $SortValidSet | Where-Object -FilterScript { $_ -imatch $wordToComplete }
                return $ValidSortSet
            } )]
        [string[]]$Sort = 'CVSS v2.0 Base Score',
        
        [Parameter()]
        [switch]$OutputFull
    )

    $parameters = @('CVEScore', 'CVE', 'Risk', 'HostName', 'Description', 'Name', 'Exclude', 'Sort', 'PluginOutput', 'Solution', 'Synopsis', 'Protocol', 'PluginID')
    $parameters | % {
        $paramvalues = Get-Variable $_ -ValueOnly
        if ($paramvalues.count -gt 1) {
            $paramvalues | % {
                $value += $_ + '|'
            }
            $paramvalues = $value -replace ".$"
            Set-Variable -Name $_ -Value $paramvalues
            Clear-Variable value
        }
    }

    $res = Nessusreport | 
    Where-Object { $_.description -imatch "$Description" -and $_.host -imatch $HostName -and $_.name -imatch "$Name" -and [decimal]$_.'CVSS v2.0 Base Score' -ge [int]"$CVEScore" `
            -and $_.cve -imatch $CVE -and $_.risk -imatch $Risk -and $_.'Plugin output' -imatch "$PluginOutput" -and $_.Solution -imatch "$Solution" `
            -and $_.Synopsis -imatch "$Synopsis" -and $_.Protocol -imatch "$Protocol" -and $_.'plugin id' -imatch "$PluginID" -and $_ -notmatch "$Exclude" }
    
    if ($FixedVersion) {
            $res | Select-Object -ExpandProperty 'plugin output' -Unique
        }
    elseif ($OutputFull) {
        $res
    }
    else {
        $res | Select-Object Host, Name, Title, CVE, 'CVSS v2.0 Base Score', risk -Unique | Sort-Object $sort -Descending
    }
}

# Comparing previous downloaded report(s) with last.
Function Nessus-Diff {

    $oldCsv = Get-ChildItem -Path "$HOME\NessusReports\PreviousNessusScan" -Filter *.csv | ForEach-Object { Import-Csv $_.FullName }
    $newCsv = Get-ChildItem -Path "$HOME\NessusReports\CurrentNessusScan" -Filter *.csv | ForEach-Object { Import-Csv $_.FullName }

    Compare-Object $oldCsv $newCsv -Property Host,name,cve,'CVSS v2.0 Base Score',Risk -PassThru |
        Select-Object @{Name='Change';Expression={if($_.SideIndicator -eq '<='){ 'Removed' } elseif($_.SideIndicator -eq '=>') { 'Added' } else { 'Changed' }}}, Host, name, cve, 'CVSS v2.0 Base Score', Risk

}

# Exporting all nessus reports in to one single CSV file.
Function Export-Nessusreports {
    param([string]$Path = "$HOME")
    $date = get-date -Format "dd_MM_yyyy"
    if (!$NessusReports) { Import-NessusReports }
    $NessusReports | Export-Csv $Path\fullreport_$date.csv
}
