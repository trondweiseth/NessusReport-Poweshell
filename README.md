# Nessus_report_downloader_PowerShell
Powershell script to download and parse through nessus report(s)

A short script to bulk download nessus report(s) and parse through them with PowerShell.
Remember to generate an API key for the user that is going to be used for this task if not already done.
PS! Do not generate new keys without checking if it's already in pwrepo or being used.
If you generate new keys and there are keys in use, existing API keys will be overwritten and rendered useless for anyone using them.

Edit NessusReports.ps1

  [1] Edit the path you want the reports to download to: $Global:BasePath   = "$HOME\NessusReports"
  
  [2] Edit the server address to point to nessus server(s): [string[]]$ServerName = ('SERVERNAME')
        
        You can add multiple nessus servers separated with a comma: ('srv1','srv2')
  
  [3] Get the API key and secret for each server and run Get-NessusReports -AddAPIkeys

Edit Mail_Reports.ps1
  
  [1] Set mail variables
  
  [2] Edit the nessusquery and header texts to your preference
  
# Examples
    -To view a list over available scan(s) completed
        $> Get-NessusReports -list
        
    -To download all reports from scan(s) in folder 3 and keep exising report(s) in the current folder so it dosent get rotated to previous scans folder.
        $> Get-NessusReports -Folder 3 -RotateReports No
        
    -Select individual scan(s) to download report(s)from in out-gridview
        $> Get-NessusReports -SelectScans
        
    -Addin new API keys for nessus server(s)
        $> Get-NessusReports -AddAPIkeys
        
    -Parsing through nessus report(s) for any CVE score grater than 7.9 and a risk of Critical with august in it's name for missing windows patches.
        $> NessusQuery -CVEScore 7.9 -Risk Critical -Name August
        
    -Comparing previous downloaded reports with current to see any changes are present. In this case only added changes.
        $> Nessus-Diff -Added
        
    -Exporting all downloaded CVS reports in to one single CVS. Handy for exporting to excel.
        $> Export-Nessusreports -Path $HOME\Downloads


# Syntax
    
    # Download nessus scans (if parameter switch -SelectScans is not present, it will download all scan(s) available that is not empty)
    # If parameter -Format is not present it defaults to CSV
    # Modify the -ServerName parameter  to set a default nessus host instead of using the parameter.
    
        Get-NessusReports
            [-List] [-AddAPIkeys] [-Folder <int32>] [-SelectScans] [-Format [csv|html](Default:csv)] [-ServerName <nessusserver>] [-RotateReports(Default:Yes)]
    
    # PS! Only CSV. Collects all CSV reports available in the folder and writes it to console and makes them parsable with powershell
    
        NessusQuery 
            [[-CVEScore] <string[]>] [[-CVE] <string[]>] [[-Risk] <string[]>] [[-HostName] <string[]>] [[-Description] <string[]>] [[-Name] <string[]>] 
            [[-PluginOutput] <string[]>] [[-Solution] <string[]>] [[-Synopsis] <string[]>] [[-Protocol] <string[]>] [[-PluginID] <string[]>] 
            [[-Exclude] <string[]>] [[-Sort] <string[]>] [-OutputFull]
               
    # Get differences between current reports and last reports
    
        Nessus-Diff [-Added] [-Removed]
    
    # Exports all nessus reports in to one signle CSV
    
        Export-Nessusreports
            [[-Path] <path[]>] [Default($HOME)]] [[-File] <string[]>]
