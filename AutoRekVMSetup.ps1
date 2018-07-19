# The Main function which is executed once all functions are declared.
#   -  All steps should go here
Function Main 
{
DebugOutput

# create user
$password = ConvertTo-SecureString "Password@123"  -AsPlainText -Force
New-LocalUser `
   -AccountNeverExpires `
   -Name "svc1" `
   -Password $password `
   -PasswordNeverExpire

# add to logon as service local policy
GrantServiceLogon -username  ("{0}\{1}" -f $env:COMPUTERNAME, "svc1")
 
# set clr to sql
Invoke-Sqlcmd -Query "EXEC sp_configure 'show advanced option', '1'; RECONFIGURE; EXEC sp_configure 'clr strict security', '1';RECONFIGURE; EXEC sp_configure; " -Username "sa" -Password "Password@123"

# Configure IIS
Import-Module Servermanager 
Get-WindowsFeature -Name *Http*
Install-WindowsFeature Web-Windows-Auth, Web-Net-Ext45, Web-Asp-Net45, NET-WCF-HTTP-Activation45, NET-Framework-45-ASPNET

}
# End of Main function


# Declare additional functions
Function GrantServiceLogon {
[cmdletbinding()]
Param (
  [string] $username = ("{0}\{1}" -f $env:COMPUTERNAME, $env:USERNAME)
   ) 
# End of Parameters
Process {
  $tempPath = [System.IO.Path]::GetTempPath()
  $import = Join-Path -Path $tempPath -ChildPath "import.inf"
  if(Test-Path $import) { Remove-Item -Path $import -Force }
  $export = Join-Path -Path $tempPath -ChildPath "export.inf"
  if(Test-Path $export) { Remove-Item -Path $export -Force }
  $secedt = Join-Path -Path $tempPath -ChildPath "secedt.sdb"
  if(Test-Path $secedt) { Remove-Item -Path $secedt -Force }
  try {
    Write-Host ("Granting SeServiceLogonRight to user account: {0}." -f $username)
    $sid = ((New-Object System.Security.Principal.NTAccount($username)).Translate([System.Security.Principal.SecurityIdentifier])).Value

    Write-Host ("The Sid is {0}" -f $sid)
    secedit /export /cfg $export
    $sids = (Select-String $export -Pattern "SeServiceLogonRight").Line
    Write-Host ("The Sids are {0}" -f $sids)
    foreach ($line in @("[Unicode]", "Unicode=yes", "[System Access]", "[Event Audit]", "[Registry Values]", "[Version]", "signature=`"`$CHICAGO$`"", "Revision=1", "[Profile Description]", "Description=GrantLogOnAsAService security template", "[Privilege Rights]", "SeServiceLogonRight = *$sids,*$sid")){
      Add-Content $import $line
        Write-Host ("Add line {1} to {0}" -f $import, $line)
    }
    secedit /import /db $secedt /cfg $import
    secedit /configure /db $secedt
    gpupdate /force
    Remove-Item -Path $import -Force
    Remove-Item -Path $export -Force
    Remove-Item -Path $secedt -Force
  } catch {
    Write-Host ("Failed to grant SeServiceLogonRight to user account: {0}." -f $username)
    $error[0]
  }
}
}

Function DebugOutput {
   Write-Host ("[Environment]::UserName  {0}" -f [Environment]::UserName)
   Write-Host ("$ env:username  {0}" -f $env:username)
   Write-Host ("[System.Security.Principal.WindowsIdentity]::GetCurrent().Name  {0}" -f [System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
   Write-Host ("$ (Get-WMIObject -class Win32_ComputerSystem | select username).username  {0}" -f $(Get-WMIObject -class Win32_ComputerSystem | select username).username)

}

# Execute the Main function
Main
# Done

