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
    Version:        2.0
    Author:         Trond Weiseth
    Creation Date:  29.08.2022
    Purpose/Change: Initial script development
.EXAMPLE
    None
#>

# Setting variable for scipt path
$Global:scriptpath = $PSScriptRoot
$Global:Server     = "NESSUS_SERVER # Change the defaul server name to your liking or add multiple servers separated with a comma
$Global:Base_URL   = "https://${Server}:8834"
$Global:BasePath   = "c:" # Change this path to alter where the scans and file structure will be saved
$Global:rootpath   = "$BasePath\NessusReports"
$Global:prevpath   = "$rootpath\PreviousNessusScan"
$Global:currpath   = "$rootpath\CurrentNessusScan"

Function Show-Message {
    $msg = @"
 ______                             _____                    _                 _               
|  ___ \                           (____ \                  | |               | |              
| |   | | ____  ___  ___ _   _  ___ _   \ \ ___  _ _ _ ____ | | ___   ____  _ | | ____  ____   
| |   | |/ _  )/___)/___) | | |/___) |   | / _ \| | | |  _ \| |/ _ \ / _  |/ || |/ _  )/ ___)  
| |   | ( (/ /|___ |___ | |_| |___ | |__/ / |_| | | | | | | | | |_| ( ( | ( (_| ( (/ /| |      
|_|   |_|\____|___/(___/ \____(___/|_____/ \___/ \____|_| |_|_|\___/ \_||_|\____|\____)_|      
                                                                                               
+------------------------+
| Author : Trond Weiseth |
+------------------------+
"@
    # Display the message
    Write-Host -ForegroundColor Yellow -BackgroundColor Black $msg

    # Wait for 3 seconds
    Start-Sleep -Seconds 3
    cls
}

# Call the function
cls
Show-Message



Function Fetch-api-keys {
# Nessus key pair
    $Global:AccessKey = $($key = get-content c:\users\$env:USERNAME\NessusAPIkeys\${server}_key.txt       | ConvertTo-SecureString ; [pscredential]::new('user',$key).GetNetworkCredential().Password)
    $Global:SecretKey = $($secret = get-content c:\users\$env:USERNAME\NessusAPIkeys\${server}_secret.txt | ConvertTo-SecureString ; [pscredential]::new('user',$secret).GetNetworkCredential().Password)
}

Fetch-api-keys

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
        [validateset('Yes','No')]
        [string]$RotateReports = 'Yes',

        [Parameter(Mandatory=$false)]
        [switch]$AddAPIkeys,

        [Parameter(Mandatory=$false)]
        [string[]]$ServerName = $server,

        [Parameter(Mandatory=$false)]
        [validateset('vuln_by_host','vuln_hosts_summary','vuln_by_plugin','remediations')]
        [string]$Chapter = 'vuln_hosts_summary'
    )

    $Global:FileFormat =  "$Format"

    # File structuring for diff comparison
    if ($RotateReports -eq 'Yes') {
        if (!$List -and $Format -ne 'html' -and !$AddAPIkeys) {
            if ($false -eq (Test-Path $rootpath)) {[void](New-Item -Path $BasePath -Name NessusReports -ItemType Directory)}
            if ($false -eq (Test-Path $currpath)) {[void](New-Item -Path $rootpath -Name CurrentNessusScan -ItemType Directory)}
            if ($false -eq (Test-Path $prevpath)) {[void](New-Item -Path $rootpath -Name PreviousNessusScan -ItemType Directory)}
            [void](Remove-Item -Path $prevpath\* -Force -Recurse)
            [void](Move-Item $currpath\* -Destination $prevpath -Force)
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
        if ($(test-path c:\users\$env:USERNAME\NessusAPIkeys) -eq $false) {new-Item -ItemType Directory -name NessusAPIkeys}
        $key    = Read-Host -Prompt "Accesskey for $Server" -AsSecureString
        $key    | ConvertFrom-SecureString > c:\users\$env:USERNAME\NessusAPIkeys\${server}_key.txt
        $secret = Read-Host -Prompt "Secret for $Server" -AsSecureString
        $secret | ConvertFrom-SecureString > c:\users\$env:USERNAME\NessusAPIkeys\${server}_secret.txt
        Fetch-api-keys
    }

    # Main execution
    $ServerName | % {

        $Global:Server     = $_
        $Global:success=$false

        if ($AddAPIkeys) {
            Add-APIkeys
            return
        }
        if (!(Test-Path c:\users\$env:USERNAME\NessusAPIkeys\${server}_key.txt) -or !(Test-Path c:\users\$env:USERNAME\NessusAPIkeys\${server}_secret.txt)) {
            Write-Host -ForegroundColor Red -BackgroundColor Black "Missing Nessus API keys! Use parameter -AddAPIkeys to add new pair for $Server."
            return
        }
        
        if ($list) {scans}
        else {
            if ($Folder) {
                Write-Host -ForegroundColor Yellow "Downloading report(s) from $Server to $currpath"
                $ScanIDs = (scans | ? {$_.folder_id -eq $Folder}).id
                # Create RunspacePool
                $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, [int]$ScanIDs.Count)
                $RunspacePool.ApartmentState = "STA"
                $RunspacePool.Open()

                # Create and execute Runspace for each scan
                $Runspaces = foreach ($ScanID in $ScanIDs) {
                    $Runspace = [PowerShell]::Create().AddScript($scriptBlock).AddParameter("ScanID", $ScanID).AddParameter("FileFormat", $FileFormat).AddParameter("Chapter", $Chapter).AddParameter("AccessKey", $AccessKey).AddParameter("SecretKey", $SecretKey).AddParameter("path", $currpath).AddParameter("Base_URL", $Base_URL)
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
                Write-Host -ForegroundColor Yellow "Downloading report(s) from $Server to $currpath"
                if ($Id) { $ScanIDs = $Id }
                else { $ScanIDs = (scans).id }
                # Create RunspacePool
                $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, [int]$ScanIDs.Count)
                $RunspacePool.ApartmentState = "STA"
                $RunspacePool.Open()

                # Create and execute Runspace for each scan
                $Runspaces = foreach ($ScanID in $ScanIDs) {
                    $Runspace = [PowerShell]::Create().AddScript($scriptBlock).AddParameter("ScanID", $ScanID).AddParameter("FileFormat", $FileFormat).AddParameter("Chapter", $Chapter).AddParameter("AccessKey", $AccessKey).AddParameter("SecretKey", $SecretKey).AddParameter("path", $currpath).AddParameter("Base_URL", $Base_URL)
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

    if ($File) {$Global:NessusReports = Import-Csv $File}
    if($Previous) {$Global:NessusReports = Import-Csv (Get-ChildItem -Path $prevpath -Filter '*.csv').FullName}
    else {$Global:NessusReports          = Import-Csv (Get-ChildItem -Path $currpath -Filter '*.csv').FullName}
    #Write-Host -ForegroundColor Cyan 'Nessusreports imported to function Nessusreport'
}

# Output nessusreport(s)
Function Nessusreport {
    if (!$NessusReports) { Import-NessusReports }
    Write-Output $NessusReports
}

# Predefined parsing through nessus report(s)
$Global:SortValidSet = @('Host', 'Name', 'risk', 'CVE', "'CVSS v2.0 Base Score'")
$Global:RiskValidateSet = @('Critical', 'High', 'Medium', 'Low', 'None')

Function NessusQuery {
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [decimal]$CVEScore_greater = 0.0,  # Greater than this score

        [Parameter()]
        [decimal]$CVEScore_less = 10.0,  # Less than this score (or set a higher default)

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
        [String[]]$Port,

        [Parameter()]
        [switch]$LogFixedVersion,

        [Parameter()]
        [switch]$FixedVersion,

        [Parameter()]
        [switch]$clip,

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
        [string[]]$Sort = 'name',
        
        [Parameter()]
        [switch]$OutputFull
    )

    $parameters = @('CVEScore_greater', 'CVEScore_less', 'CVE', 'Risk', 'HostName', 'Description', 'Name', 'Exclude', 'Sort', 'PluginOutput', 'Solution', 'Synopsis', 'Protocol', 'PluginID','Port')
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

    # Convert the array of strings into a regex pattern
    $pattern = ($Exclude -join '|')

    $res = Nessusreport | 
    Where-Object { 
        ($_.description -imatch "$Description"-or $_.description -eq "$Description") -and
        ($_.host -imatch "$HostName") -and
        ($_.name -imatch "$Name" -or $_.name -eq "$Name") -and
        ([decimal]$_.'CVSS v2.0 Base Score' -ge [decimal]$CVEScore) -and
        ([decimal]$_.'CVSS v2.0 Base Score' -gt $CVEScore_greater -or $CVEScore_greater -eq 0.0) -and
        ([decimal]$_.'CVSS v2.0 Base Score' -lt $CVEScore_less -or $CVEScore_less -eq 10.0) -and
        ($_.cve -imatch "$CVE") -and
        ($_.risk -imatch "$Risk") -and
        ($_.'Plugin output' -imatch "$PluginOutput") -and
        ($_.Solution -imatch "$Solution") -and
        ($_.Synopsis -imatch "$Synopsis") -and
        ($_.Protocol -imatch "$Protocol") -and
        ($_.'plugin id' -imatch "$PluginID") -and
        ($_.Port -imatch "$Port") -and
        ($_ -notmatch "$pattern")
    }

    if ($FixedVersion) {
        # Clear the clipboard first
        Set-Clipboard $null
        $res | Sort-Object -Property name, host -Unique | ForEach-Object {

            # Write colored output to console
            $nameLine = $_.name
            $hostLine = $_.host

            # Write-Host for color output in console (using different colors)
            Write-Host $nameLine -ForegroundColor Cyan
            Write-Host "-------------------------------" -ForegroundColor White
            Write-Host $hostLine -ForegroundColor Yellow

            # Prepare full output for logging or additional output
            $fullOutput = @(
                $nameLine
                "-------------------------------"
                $hostLine
            )

            # Expand 'plugin output'
            $pluginOutput = $_ | Select-Object -ExpandProperty 'plugin output'

            # Check if pluginOutput is valid
            if ($pluginOutput) {
                # Filter lines for relevant patterns
                $filteredOutput = $pluginOutput | Select-String -Pattern "Remote package installed :", "Should be :", "Path :", "Installed version :", "Fixed version :", "Remote version :"

                # Check if 'Fixed version' is present in the filtered output
                if ($filteredOutput -and ($filteredOutput -match "Fixed version")) {
                    # Process each matching line, filter out 'NOTE' and display it
                    $filteredOutput | ForEach-Object {
                        if ($_.Line -notmatch "NOTE") {
                            Write-Host $_.Line # Append filtered output to console
                            $fullOutput += $_.Line # Append filtered output to log
                        }
                    }
                } else {
                    # No 'Fixed version' found, output the full plugin output instead
                    Write-Host $pluginOutput # Display the full plugin output
                    $fullOutput += $pluginOutput # Append full plugin output to log
                }
            } else {
                Write-Host "No plugin output available for ${nameLine}." -ForegroundColor Yellow
            }

            # Optionally write full output to a file (append mode)
            if ($LogFixedVersion) {
                $logFile = "fixedversion.txt"
                $fullOutput | Out-File -Append -FilePath "$BasePath\$logFile"
            }

            # Append full output to clipboard if -clip switch is used
            if ($clip) {
                $currentClip = Get-Clipboard -ErrorAction SilentlyContinue
                $newClipContent = if ($currentClip) { $currentClip + $fullOutput } else { $fullOutput }
                Set-Clipboard -Value $newClipContent
            }
        }
    }
    elseif ($OutputFull) {
        $res
    }
    else {
        $res | Select-Object Host, Name, CVE, 'CVSS v2.0 Base Score', risk, 'Plugin ID' -Unique | Sort-Object $sort -Descending
    }
}

<# Comparing previous downloaded report(s) with last.
Function Nessus-Diff {

    $oldCsv = Get-ChildItem -Path $prevpath -Filter *.csv | ForEach-Object { Import-Csv $_.FullName }
    $newCsv = Get-ChildItem -Path $currpath -Filter *.csv | ForEach-Object { Import-Csv $_.FullName }

    Compare-Object $oldCsv $newCsv -Property Host,name,cve,'CVSS v2.0 Base Score',Risk -PassThru |
        Select-Object @{Name='Change';Expression={if($_.SideIndicator -eq '<='){ 'Removed' } elseif($_.SideIndicator -eq '=>') { 'Added' } else { 'Changed' }}}, Host, name, cve, 'CVSS v2.0 Base Score', Risk

} #>



function Nessus-Diff {
    param (
        [string]$prevpath = "$rootpath\PreviousNessusScan",
        [string]$currpath = "$rootpath\CurrentNessusScan"
    )

    # Check if paths exist
    if (-not (Test-Path $prevpath)) {
        Write-Host "The previous path does not exist: $prevpath" -ForegroundColor Red
        return
    }

    if (-not (Test-Path $currpath)) {
        Write-Host "The current path does not exist: $currpath" -ForegroundColor Red
        return
    }

    # Get list of CSV files in both folders
    $prevFiles = Get-ChildItem -Path $prevpath -Filter *.csv
    $currFiles = Get-ChildItem -Path $currpath -Filter *.csv

    # Create a list to hold all rows from previous and current CSVs
    $allPrevCsvData = @()
    $allCurrCsvData = @()

    # Import CSV data from previous files
    foreach ($file in $prevFiles) {
        if ($file -and (Test-Path $file.FullName)) {
            $csvData = Import-Csv -Path $file.FullName
            $allPrevCsvData += $csvData
        } else {
            Write-Host "Warning: File not found or is empty: $($file.FullName)" -ForegroundColor Yellow
        }
    }

    # Import CSV data from current files
    foreach ($file in $currFiles) {
        if ($file -and (Test-Path $file.FullName)) {
            $csvData = Import-Csv -Path $file.FullName
            $allCurrCsvData += $csvData
        } else {
            Write-Host "Warning: File not found or is empty: $($file.FullName)" -ForegroundColor Yellow
        }
    }

    # Compare the imported data
    $differences = Compare-Object -ReferenceObject $allPrevCsvData -DifferenceObject $allCurrCsvData -Property Host, name, cve, 'CVSS v2.0 Base Score', Risk -PassThru

    # Check if there are differences and output them
    if ($differences) {
        # Create an array to hold formatted differences
        $formattedDifferences = @()

        foreach ($difference in $differences) {
            $changeType = if ($difference.SideIndicator -eq '<=') { 'Removed' } elseif ($difference.SideIndicator -eq '=>') { 'Added' } else { 'Changed' }
            
            # Prepare a custom object for each difference
            $formattedDifferences += [PSCustomObject]@{
                ChangeType             = $changeType
                Host                   = $difference.Host
                Name                   = $difference.name
                CVE                    = $difference.cve
                'CVSS v2.0 Base Score' = $difference.'CVSS v2.0 Base Score'
                Risk                   = $difference.Risk
            }
        }

        # Output formatted differences to Out-GridView
        $formattedDifferences

    } else {
        Write-Host "No differences found between the previous and current scans." -ForegroundColor Green
    }
}

# Exporting all nessus reports in to one single CSV file.
Function Export-Nessusreports {
    param([string]$Path = "$BasePath")
    $date = get-date -Format "dd_MM_yyyy"
    if (!$NessusReports) { Import-NessusReports }
    $NessusReports | Export-Csv $Path\fullreport_$date.csv
}

Function Get-PluginDetails() {
    param
    (
    [int]$plugin_id
    )

    $Global:pluginid = $plugin_id
    plugindetails
}

    # Function to fetch plugin details
    function plugindetails {
        param
        (
            [int]$pluginid
        )

        $error.Clear()
        $ProgressPreference = 'SilentlyContinue'
        
        # Define the API call parameters
        $pluginids = @{
            "Uri"              = "$Base_URL/plugins/plugin/$plugin_id"
            "Method"           = "GET"
            "Headers"          = @{
                "Accept"       = "application/json"
                "Content-Type" = "application/json"
                "X-ApiKeys"    = "accessKey=$($AccessKey); secretKey=$($SecretKey)"
            }
        }

        try {
            # Fetch the plugin details from the API
            $pluginres = Invoke-WebRequest @pluginids -ErrorAction Stop -UseBasicParsing
        
            # Parse the JSON response
            $Json = $pluginres.Content | ConvertFrom-Json
        
            # Create a hashtable to store the attributes
            $parsedAttributes = @{}

            foreach ($attribute in $Json.attributes) {
                # Create dynamic properties with attribute_name as the key and attribute_value as the value
                $parsedAttributes[$attribute.attribute_name] = $attribute.attribute_value
            }
            
            # Convert the hashtable to a PowerShell object
            $parsedObject = [pscustomobject]$parsedAttributes

            # Return the parsed object for further filtering in the pipeline
            return $parsedObject
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

Function PluginQuery {
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [String[]]$cvss_temporal_vector,

        [Parameter()]
        [ValidateSet("local", "remote", "combined", "Settings", "Summary", "Third-Party", "Reputation")]
        [String[]]$plugin_type,

        [Parameter()]
        [String[]]$description,

        [Parameter()]
        [String[]]$cvss_base_score,

        [Parameter()]
        [String[]]$cvss_score_source,

        [Parameter()]
        [String[]]$cvss3_vector,

        [Parameter()]
        [String[]]$CVE,

        [Parameter()]
        [String[]]$solution,

        [Parameter()]
        [String[]]$cvss3_temporal_score,

        [Parameter()]
        [String[]]$script_version,

        [Parameter()]
        [decimal]$cvss3_base_score_greater = 0.0,  # Greater than this score

        [Parameter()]
        [decimal]$cvss3_base_score_less = 10.0,  # Less than this score (or set a higher default)

        [Parameter()]
        [String[]]$rhsa,

        [Parameter()]
        [String[]]$required_key,

        [Parameter()]
        [String[]]$vuln_publication_date,

        [Parameter()]
        [String[]]$cvss_temporal_score,

        [Parameter()]
        [String[]]$see_also,

        [Parameter()]
        [ValidateSet("Very Low", "Low", "Medium", "High" , "Very High")]
        [String[]]$threat_intensity_last_28,

        [Parameter()]
        [String[]]$cpe,

        [Parameter()]
        [String[]]$age_of_vuln,

        [Parameter()]
        [String[]]$synopsis,

        [Parameter()]
        [ValidateSet( "Info" , "Low", "Medium", "High" , "Critical")]
        [String[]]$risk_factor,

        [Parameter()]
        [String[]]$dependency,

        [Parameter()]
        [String[]]$cvss_vector,

        [Parameter()]
        [String[]]$script_copyright,

        [Parameter()]
        [ValidateSet("false", "true")]
        [String[]]$exploit_available,

        [Parameter()]
        [String[]]$vendor_severity,

        [Parameter()]
        [ValidateSet("Low", "Medium", "High" , "Very High")]
        [String[]]$product_coverage,

        [Parameter()]
        [String[]]$vpr_score,

        [Parameter()]
        [String[]]$plugin_publication_date,

        [Parameter()]
        [String[]]$cvssV3_impactScore,

        [Parameter()]
        [String[]]$threat_sources_last_28,

        [Parameter()]
        [String[]]$exploitability_ease,

        [Parameter()]
        [String[]]$generated_plugin,

        [Parameter()]
        [String[]]$fname,

        [Parameter()]
        [String[]]$xref,

        [Parameter()]
        [String[]]$plugin_modification_date,

        [Parameter()]
        [String[]]$cvss3_temporal_vector,

        [Parameter()]
        [ValidateSet("High", "Functional", "PoC", "Unproven")]
        [String[]]$exploit_code_maturity,

        [Parameter()]
        [String[]]$cwe,

        [Parameter()]
        [String[]]$patch_publication_date,

        [Parameter()]
        [ValidateSet("true")]
        [String[]]$unsupported_by_vendor,

        [Parameter()]
        [String[]]$plugin_name,

        [Parameter()]
        [String[]]$threat_recency,

        [Parameter()]
        [string[]]$Exclude = '!#¤%&/()=',

        [Parameter()]
        [string[]]$Sort = 'plugin_name',

        [Parameter()]
        [switch]$OutputFull,

        [Parameter()]
        [switch]$CVSScalc,

        [Parameter()]
        [switch]$hosts,

        [Parameter()]
        [int]$daysback = 0,

        [Parameter()]
        [int]$OlderThanDays = 0,

        [Parameter()]
        [ValidateSet("patch_publication_date", "plugin_publication_date", "plugin_modification_date", "vuln_publication_date")]
        [string]$DateField = "vuln_publication_date",  # Default to vuln_publication_date
        
        [Parameter()]
        [switch]$FormatDates,

        [Parameter()]
        [switch]$LinkToPlugin
    )
 
    Begin {
        if ($(Test-Path $BasePath\NessusReports\plugindetails.txt) -eq $false) {write-host -ForegroundColor yellow "Missing report. Run 'Export-Plugindetails'" ; break}
        $jcontent = Get-Content $BasePath\NessusReports\plugindetails.txt -Raw
        $plugindetails = $jcontent | ConvertFrom-Json

        # Convert the array of strings into a regex pattern
        $pattern = ($Exclude -join '|')
    }

    Process {
        # Define parameters to include in the filtering
        $parameters = @('cvss_temporal_vector', 'plugin_type', 'description', 'cvss_base_score', 'cvss_score_source', 'cvss3_vector', 'CVE', 'solution', 
                        'cvss3_temporal_score', 'script_version', 'cvss3_base_score_greater', 'cvss3_base_score_less' , 'rhsa', 'required_key', 'vuln_publication_date', 'cvss_temporal_score',
                        'see_also', 'threat_intensity_last_28', 'cpe', 'age_of_vuln', 'synopsis', 'risk_factor', 'dependency', 'cvss_vector', 
                        'script_copyright', 'exploit_available', 'vendor_severity', 'product_coverage', 'vpr_score', 'plugin_publication_date', 
                        'cvssV3_impactScore', 'threat_sources_last_28', 'exploitability_ease', 'generated_plugin', 'fname', 'xref', 'plugin_modification_date', 
                        'cvss3_temporal_vector', 'exploit_code_maturity', 'cwe', 'patch_publication_date', 'plugin_name', 'threat_recency', 'Exclude', 'unsupported_by_vendor')

        # Process parameters for multiple values, concatenate with pipes (|)
        $parameters | ForEach-Object {
            $paramvalues = Get-Variable $_ -ValueOnly
            if ($paramvalues.count -gt 1) {
                $value = ""
                $paramvalues | ForEach-Object {
                    $value += $_ + '|'
                }
                $paramvalues = $value -replace "\|$"  # Remove trailing pipe
                Set-Variable -Name $_ -Value $paramvalues
                Clear-Variable value
            }
        }

        # Escape the variables used with -imatch
        $plugin_name = [regex]::Escape($plugin_name)
        $description = [regex]::Escape($description)
        $solution = [regex]::Escape($solution)

        # Query the plugins based on the provided parameters
        $res = $plugindetails | 
        Where-Object { 
            ($_.plugin_name -imatch "$plugin_name" -or $_.plugin_name -eq "$plugin_name") -and
            ($_.CVE -imatch "$CVE" -or $_.CVE -eq "$CVE") -and
            ($_.plugin_type -imatch "$plugin_type" -or $_.plugin_type -eq "$plugin_type") -and
            ($_.vpr_score -imatch "$vpr_score" -or -not $vpr_score -or $_.vpr_score -eq "$vpr_score") -and
            ($_.cvssV3_impactScore -imatch "$cvssV3_impactScore" -or $_.cvssV3_impactScore -eq "$cvssV3_impactScore") -and
            # Handle the cvss3_base_score greater condition
            ([decimal]$_.cvss3_base_score -gt $cvss3_base_score_greater -or $cvss3_base_score_greater -eq 0.0) -and
            # Handle the cvss3_base_score less condition
            ([decimal]$_.cvss3_base_score -lt $cvss3_base_score_less -or $cvss3_base_score_less -eq 10.0) -and
            ($_.description -imatch "$description" -or $_.description -eq "$description") -and
            ($_.solution -imatch "$solution" -or $_.solution -eq "$solution") -and
            ($_.synopsis -imatch "$synopsis" -or $_.synopsis -eq "$synopsis") -and
            ($_.plugin_publication_date -imatch "$plugin_publication_date" -or $_.plugin_publication_date -eq "$plugin_publication_date") -and
            ($_.plugin_modification_date -imatch "$plugin_modification_date" -or $_.plugin_modification_date -eq "$plugin_modification_date") -and
            ($_.exploit_available -imatch "$exploit_available" -or $_.exploit_available -eq "$exploit_available") -and
            ($_.risk_factor -imatch "$risk_factor" -or $_.risk_factor -eq "$risk_factor") -and
            ($_.cvss_temporal_vector -imatch "$cvss_temporal_vector" -or $_.cvss_temporal_vector -eq "$cvss_temporal_vector") -and
            ([int]$_.cvss_base_score -ge $cvss_base_score -or $_.cvss_base_score -eq $cvss_base_score) -and
            ($_.cvss_score_source -imatch "$cvss_score_source" -or $_.cvss_score_source -eq "$cvss_score_source") -and
            ($_.cvss3_vector -imatch "$cvss3_vector" -or $_.cvss3_vector -eq "$cvss3_vector") -and
            ([decimal]$_.cvss3_temporal_score -ge $cvss3_temporal_score -or $_.cvss3_temporal_score -eq $cvss3_temporal_score) -and
            ($_.script_version -imatch "$script_version" -or $_.script_version -eq "$script_version") -and
            ($_.rhsa -imatch "$rhsa" -or $_.rhsa -eq "$rhsa") -and
            ($_.required_key -imatch "$required_key" -or $_.required_key -eq "$required_key") -and
            ($_.vuln_publication_date -imatch "$vuln_publication_date" -or $_.vuln_publication_date -eq "$vuln_publication_date") -and
            ($_.see_also -imatch "$see_also" -or $_.see_also -eq "$see_also") -and
            ($_ -notmatch "$pattern")
        }

        # Filter based on $daysback and $OlderThanDays conditions
        if ($daysback -gt 0) {
            $dateThreshold = (Get-Date).AddDays(-$daysback)
            # Filter results newer than $daysback
            $res = $res | Where-Object {
                try {
                    $vulnDate = [datetime]::ParseExact($_.$DateField, 'yyyy/MM/dd', $null)
                    $vulnDate -ge $dateThreshold
                } catch {
                    $false
                }
            }
        }

        if ($OlderThanDays -gt 0) {
            $olderDateThreshold = (Get-Date).AddDays(-$OlderThanDays)
            # Filter results older than $OlderThanDays
            $res = $res | Where-Object {
                try {
                    $vulnDate = [datetime]::ParseExact($_.$DateField, 'yyyy/MM/dd', $null)
                    $vulnDate -lt $olderDateThreshold
                } catch {
                    $false
                }
            }
        }

        # Output the results based on the $OutputFull flag
        if ($OutputFull) {
            $res
        } else {
            $formattedResults = $res | Select-Object plugin_name, 
                                                   CVE, 
                                                   cvss3_base_score, 
                                                   risk_factor, 
                                                   exploit_available, 
                                                   exploit_code_maturity, 
                                                   @{Name="patch_publication_date"; Expression={ 
                                                        if ($FormatDates) {
                                                            [datetime]::ParseExact($_.patch_publication_date, 'yyyy/MM/dd', $null).ToString("d MMMM yyyy")
                                                        } else {
                                                            $_.patch_publication_date
                                                        }
                                                   }},
                                                   @{Name="plugin_publication_date"; Expression={ 
                                                        if ($FormatDates) {
                                                            [datetime]::ParseExact($_.plugin_publication_date, 'yyyy/MM/dd', $null).ToString("d MMMM yyyy")
                                                        } else {
                                                            $_.plugin_publication_date
                                                        }
                                                   }},
                                                   @{Name="plugin_modification_date"; Expression={ 
                                                        if ($FormatDates) {
                                                            [datetime]::ParseExact($_.plugin_modification_date, 'yyyy/MM/dd', $null).ToString("d MMMM yyyy")
                                                        } else {
                                                            $_.plugin_modification_date
                                                        }
                                                   }},
                                                   @{Name="vuln_publication_date"; Expression={ 
                                                        if ($FormatDates) {
                                                            [datetime]::ParseExact($_.vuln_publication_date, 'yyyy/MM/dd', $null).ToString("d MMMM yyyy")
                                                        } else {
                                                            $_.vuln_publication_date
                                                        }
                                                   }} | 
                                           Sort-Object $Sort -Descending
            $formattedResults
        }

        # Calculate the date threshold if daysback is specified and greater than 0
        if ($daysback -gt 0) {
            $dateThreshold = (Get-Date).AddDays(-$daysback)

            # Filter results based on the publication date threshold
            $res = $res | Where-Object {
                $vulnDateString = $_.$DateField
                echo $vulnDateString
                echo $DateField
                # Attempt to parse the vuln_publication_date and handle any errors
                try {
                    # Use the original format 'yyyy/MM/dd' for parsing
                    $vulnDate = [datetime]::ParseExact($vulnDateString, 'yyyy/MM/dd', $null)

                    # Compare with the date threshold; keep entries newer than or equal to the threshold
                    $isRecent = $vulnDate -ge $dateThreshold
                    $isRecent
                } catch {
                    # Skip this entry if the date is invalid
                    $false
                }
            }
        }

        # Calculate the older date threshold if OlderThanDays is specified and greater than 0
        if ($OlderThanDays -gt 0) {
            $olderDateThreshold = (Get-Date).AddDays(-$OlderThanDays)

            # Filter results based on the vuln_publication_date threshold
            $res = $res | Where-Object {
                $vulnDateString = $_.$DateField
                echo $DateField
                echo $vulnDateString

                # Attempt to parse the vuln_publication_date and handle any errors
                try {
                    # Use the original format 'yyyy/MM/dd' for parsing
                    $vulnDate = [datetime]::ParseExact($vulnDateString, 'yyyy/MM/dd', $null)

                    # Compare with the older date threshold; keep entries older than the threshold
                    $isOlder = $vulnDate -lt $olderDateThreshold
                    $isOlder
                } catch {
                    # Skip this entry if the date is invalid
                    $false
                }
            }
        }

        if ($CVSScalc) {
            $vector_URL = 'https://www.first.org/cvss/calculator/3.0#'
            $res | sort cve -Unique | % {
                if ($_.cvss3_vector) {  # Check if 'cvss3_vector' is present
                    $cve = $_.cve
                    $vector = $_.cvss3_vector  # Directly access 'cvss3_vector'
                    $vector_link = "${vector_URL}$vector"
                    Write-Output "Link to CVSS calculator for ${cve} : $vector_link"
                }
            }
            Write-Host ""  # Blank line for readability
        }

        if ($LinkToPlugin) {
            $plugin_URL = 'https://www.tenable.com/plugins/nessus/'
            $res | sort cve -Unique | % {
                if ($_.cve) {  # Check if 'cve' is present
                    $cve = $_.cve
                    $pluginID = $(NessusQuery -Name $_.plugin_name | sort name -Unique | select -ExpandProperty 'plugin id' -ErrorAction SilentlyContinue)
                    if ($pluginID) {  # Check if 'plugin id' is present
                        $plugin_link = "${plugin_URL}$pluginID"
                        Write-Output "Link to nessus plugin for ${cve} : $plugin_link"
                    }
                }
            }
            Write-Host ""  # Blank line for readability
        }

        # Ensure you run this in a clean environment with necessary context
        if ($hosts) {
            # Collect results for output later
            $output = @()

            # Select unique CVE and plugin names
            $res | Select-Object -Property cve, plugin_name -Unique | sort plugin_name | ForEach-Object {
                $CVEcode    = $_.cve
                $pluginName = $_.plugin_name

                # Query for hosts based on plugin name and CVE conditions
                $h = Nessusreport | Where-Object {
                    $_.name -eq $pluginName -and 
                    ($_.cve -eq $CVEcode -or -not $CVEcode) -and
                    ($_ -notmatch "$pattern")
                    #($_.host -notmatch "c1w")
                } | Select-Object -ExpandProperty host -Unique

                # Prepare output for plugins with CVEs
                if ($CVEcode) {
                    $output += "Affected hosts for '$pluginName' : $CVEcode"
                } else {
                    $output += "Affected hosts for '$pluginName'"
                }

                # Check if there are affected hosts
                if ($h.Count -eq 0) {
                    $output += " - No affected hosts found."
                } else {
                    # List each affected host with a preceding dash
                    foreach ($hostname in $h) {
                        $output += " - $hostname"  # Prepend with dash and space for formatting
                    }
                }

                $output += ""  # Blank line for readability
            }

            # Output the results after processing
            $output | ForEach-Object { Write-Host $_ }
        }

    }

    End {
        # Final block if needed
    }
}

Function Export-Plugindetails() {
    write-host -ForegroundColor green "Downloading plugin details. Please wait.."
    $pluginoutput = $($ids = Nessusreport | select -ExpandProperty 'plugin id' -Unique;$ids | % {Get-PluginDetails $_})
    $pluginoutput | ConvertTo-Json | Set-Content -Path "$BasePath\NessusReports\plugindetails.txt"
    write-host -ForegroundColor green "Done"
}

Function Format-VulnList {
    param (
        [Parameter(ValueFromPipeline = $true)]
        $InputObject,
         
        [switch]$Clip  # Switch to control clipboard output
    )
 
    # Array to hold all incoming objects
    begin {
        $data = @()
    }
 
    # Collect each piped object in the array
    process {
        $data += $InputObject
    }
 
    # Output all objects at once with headers applied to each row
    end {
        # Capture formatted table output with headers
        $formattedData = ($data | Format-Table | Out-String).Split("`n")
         
        # Extract header and separator lines (first 3 lines in the table output)
        $header = $formattedData | Select-Object -First 3
 
        # Format data without headers
        $dataObjects = ($data | Format-Table -HideTableHeaders | Out-String).Split("`n") |
                       Where-Object { $_.Trim() -ne "" }  # Remove any blank lines
 
        # Conditional formatting based on -Clip switch
        if ($Clip) {
            # Create compact output for clipboard
            $result = $dataObjects | ForEach-Object {
                # Concatenate without extra newlines between blocks
                ($header + $_ + "#") -join "`n"
            }
             
            # Send compact result to clipboard
            $result | Out-String | clip.exe
        }
        else {
            # Console output with regular spacing
            $result = $dataObjects | ForEach-Object {
                # Standard format with newline between each entry
                $header + $_ + "#"
            }
 
            # Output result to console
            $result | ForEach-Object { Write-Output $_ }
        }
    }
}
