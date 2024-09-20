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
$Global:Server = "<NESSUS SERVER FQDN>"
$Global:Base_URL   = "https://${Server}:8834"
$Global:BasePath   = "$HOME\NessusReports"
$Global:prevpath   = "$BasePath\PreviousNessusScan"

# Nessus key pair
$Global:AccessKey = $($key = get-content $scriptpath\${server}_key.txt       | ConvertTo-SecureString ; [pscredential]::new('user',$key).GetNetworkCredential().Password)
$Global:SecretKey = $($secret = get-content $scriptpath\${server}_secret.txt | ConvertTo-SecureString ; [pscredential]::new('user',$secret).GetNetworkCredential().Password)

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
        [string]$SaveTo,

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

    # Global parameters
    $Global:FileFormat = $Format
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
        $Global:success=$false

        if ($AddAPIkeys) {
            Add-APIkeys
            return
        }
        if (!(Test-Path $scriptpath\${server}_key.txt) -or !(Test-Path $scriptpath\${server}_secret.txt)) {
            Write-Host -ForegroundColor Red -BackgroundColor Black "Missing Nessus API keys! Use parameter -AddAPIkeys to add new pair for $Server."
            return
        }
        
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
$Global:SortValidSet = @('Host', 'Name', 'risk', 'CVE', "'CVSS v2.0 Base Score'")
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
        [String[]]$Port,

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


    $parameters = @('CVEScore', 'CVE', 'Risk', 'HostName', 'Description', 'Name', 'Exclude', 'Sort', 'PluginOutput', 'Solution', 'Synopsis', 'Protocol', 'PluginID','Port')
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
    Where-Object { 
        ($_.description -imatch "$Description") -and
        ($_.host -imatch "$HostName") -and
        ($_.name -imatch "$Name") -and
        ([decimal]$_.'CVSS v2.0 Base Score' -ge [int]$CVEScore) -and
        ($_.cve -imatch "$CVE") -and
        ($_.risk -imatch "$Risk") -and
        ($_.'Plugin output' -imatch "$PluginOutput") -and
        ($_.Solution -imatch "$Solution") -and
        ($_.Synopsis -imatch "$Synopsis") -and
        ($_.Protocol -imatch "$Protocol") -and
        ($_.'plugin id' -imatch "$PluginID") -and
        ($_.Port -imatch "$Port") -and
        ($_ -notmatch "$Exclude")
    }

    if ($FixedVersion) {
            $res | sort -Unique name,host | foreach  { Write-Host -f yellow $_.host ; $_ | Select-Object -ExpandProperty 'plugin output' }
        }
    elseif ($OutputFull) {
        $res
    }
    else {
        $res | Select-Object Host, Name, CVE, 'CVSS v2.0 Base Score', risk, 'Plugin ID' -Unique | Sort-Object $sort -Descending
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
            $pluginres = Invoke-WebRequest @pluginids -ErrorAction Stop 
        
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
        [ValidateSet("local", "remote")]
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
        [String[]]$cvss3_base_score,

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
        [String[]]$risk_factor,

        [Parameter()]
        [String[]]$dependency,

        [Parameter()]
        [String[]]$cvss_vector,

        [Parameter()]
        [String[]]$script_copyright,

        [Parameter()]
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
        [String[]]$plugin_name,

        [Parameter()]
        [String[]]$threat_recency,

        [Parameter()]
        [string[]]$Exclude = '!#¤%&/()=',

        [Parameter()]
        [string[]]$Sort = 'cvss_base_score',

        [Parameter()]
        [switch]$OutputFull
    )

    Begin {
        $jcontent = Get-Content $HOME\NessusReports\plugindetails.txt -Raw
        $plugindetails = $jcontent | ConvertFrom-Json
    }

    Process {
        # Define parameters to include in the filtering
        $parameters = @('cvss_temporal_vector', 'plugin_type', 'description', 'cvss_base_score', 'cvss_score_source', 'cvss3_vector', 'CVE', 'solution', 
                        'cvss3_temporal_score', 'script_version', 'cvss3_base_score', 'rhsa', 'required_key', 'vuln_publication_date', 'cvss_temporal_score',
                        'see_also', 'threat_intensity_last_28', 'cpe', 'age_of_vuln', 'synopsis', 'risk_factor', 'dependency', 'cvss_vector', 
                        'script_copyright', 'exploit_available', 'vendor_severity', 'product_coverage', 'vpr_score', 'plugin_publication_date', 
                        'cvssV3_impactScore', 'threat_sources_last_28', 'exploitability_ease', 'generated_plugin', 'fname', 'xref', 'plugin_modification_date', 
                        'cvss3_temporal_vector', 'exploit_code_maturity', 'cwe', 'patch_publication_date', 'plugin_name', 'threat_recency', 'Exclude')

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

        # Query the plugins based on the provided parameters
        $res = $plugindetails | 
        Where-Object { 
            ($_.plugin_name -imatch "$plugin_name") -and
            ($_.CVE -imatch "$CVE") -and
            ($_.plugin_type -imatch "$plugin_type") -and
            ($_.vpr_score -imatch "$vpr_score" -or !$vpr_score) -and
            ($_.cvssV3_impactScore -imatch "$cvssV3_impactScore") -and
            ([decimal]$_.cvss3_base_score -ge [int]"$cvss3_base_score") -and
            ($_.description -imatch "$description") -and
            ($_.solution -imatch "$solution") -and
            ($_.synopsis -imatch "$synopsis") -and
            ($_.plugin_publication_date -imatch "$plugin_publication_date") -and
            ($_.plugin_modification_date -imatch "$plugin_modification_date") -and
            ($_.exploit_available -imatch "$exploit_available") -and
            ($_.risk_factor -imatch "$risk_factor") -and
            ($_.cvss_temporal_vector -imatch "$cvss_temporal_vector") -and
            ([int]$_.cvss_base_score -ge [int]"$cvss_base_score") -and
            ($_.cvss_score_source -imatch "$cvss_score_source") -and
            ($_.cvss3_vector -imatch "$cvss3_vector") -and
            ([decimal]$_.cvss3_temporal_score -ge [int]"$cvss3_temporal_score") -and
            ($_.script_version -imatch "$script_version") -and
            ($_.rhsa -imatch "$rhsa") -and
            ($_.required_key -imatch "$required_key") -and
            ($_.vuln_publication_date -imatch "$vuln_publication_date") -and
            ([decimal]$_.cvss_temporal_score -ge [int]"$cvss_temporal_score") -and
            ($_.see_also -imatch "$see_also") -and
            ($_.threat_intensity_last_28 -imatch "$threat_intensity_last_28") -and
            ($_.cpe -imatch "$cpe") -and
            ($_.age_of_vuln -imatch "$age_of_vuln") -and
            ($_.dependency -imatch "$dependency") -and
            ($_.cvss_vector -imatch "$cvss_vector") -and
            ($_.script_copyright -imatch "$script_copyright") -and
            ($_.vendor_severity -imatch "$vendor_severity") -and
            ($_.product_coverage -imatch "$product_coverage") -and
            ($_.threat_sources_last_28 -imatch "$threat_sources_last_28") -and
            ($_.exploitability_ease -imatch "$exploitability_ease") -and
            ($_.generated_plugin -imatch "$generated_plugin") -and
            ($_.fname -imatch "$fname") -and
            ($_.xref -imatch "$xref") -and
            ($_.cvss3_temporal_vector -imatch "$cvss3_temporal_vector") -and
            ($_.exploit_code_maturity -imatch "$exploit_code_maturity") -and
            ($_.cwe -imatch "$cwe") -and
            ($_.patch_publication_date -imatch "$patch_publication_date") -and
            ($_.threat_recency -imatch "$threat_recency") -and
            ($_ -notmatch "$Exclude")
        }

        # Output the filtered results
        if ($OutputFull) {
            $res
        } else {
            $res | Select-Object plugin_name, CVE, cvss3_base_score, plugin_publication_date, plugin_modification_date, exploit_available, risk_factor, exploit_code_maturity -Unique | Sort-Object $Sort -Descending
        }
    }

    End {
        # Final block if needed
    }
}


Function Export-Plunindetails() {
    $pluginoutput = $($ids = Nessusreport | select -ExpandProperty 'plugin id' -Unique;$ids | % {Get-PluginDetails $_})
    $pluginoutput | ConvertTo-Json | Set-Content -Path $HOME\\NessusReports\plugindetails.txt
}
