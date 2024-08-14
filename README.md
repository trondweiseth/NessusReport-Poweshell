# NessusReport-Poweshell-Module
Powershell module for downloading nessus reports

Edit NessusReports.ps1
  [1] Edit the path you want the reports to download to: $Global:BasePath   = "$HOME\NessusReports"
  [2] Edit the server address to point to nessus server(s): [string[]]$ServerName = ('NESSUS_SERVER_ADDRESS')
        You can add multiple nessus servers separated with a comma: ('srv1','srv2')
  [3] Get the API key for each server and run Get-NessusReports -AddAPIkeys

Edit Mail_Reports.ps1
  [1] Set mail variables
  [2] Edit the nessusquery and header texts to your preference
  
