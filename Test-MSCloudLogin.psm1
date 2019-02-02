<#
.SYNOPSIS
    The Test-CloudLogin function is used to assist with logging in to various Microsoft Cloud services, such as Azure, SharePoint Online, and SharePoint PnP.
.EXAMPLE
    Test-CloudLogin -Platform AzureAD -UseMFA
.EXAMPLE
    Test-CloudLogin -Platform PnP
.PARAMETER Platform
    The Platform parameter specifies which cloud service for which we are testing the login state. Possible values are Azure, AzureAD, SharePointOnline, ExchangeOnline, MSOnline, and PnP.
.PARAMETER UseMFA
    The UseMFA switch specifies that we already know the credentials we are logging in with require Multi-Factor Authentication so we won't even bother prompting for Windows-style credentials.
.NOTES
    Created & maintained by Brian Lalancette (@brianlala), 2019.
.LINK
    https://github.com/brianlala/Test-MSCloudLogin
    #>

function Test-CloudLogin
{
    [CmdletBinding()]
    param
        (
            [Parameter(Mandatory=$true)]
            [ValidateSet("Azure","AzureAD","SharePointOnline","ExchangeOnline","MSOnline","PnP")]
            $Platform,
            [Parameter(Mandatory=$false)]
            [switch]
            $UseMFA
        )
    switch ($Platform)
    {
        "Azure" {$testCmdlet = "Get-AzResource"; $exceptionStringMFA = "AADSTS50079"; $connectCmdlet = "Connect-AzAccount"; $variablePrefix = "az"}
        "AzureAD" {$testCmdlet = "Get-AzureADUser"; $exceptionStringMFA = "AADSTS"; $connectCmdlet = "Connect-AzureAD"; $connectCmdletArgs = "-Credential `$global:o365Credentials"; $variablePrefix = "aad"}
        "SharePointOnline" {Get-SPOAdminUrl; $testCmdlet = "Get-SPOSite"; $exceptionStringMFA = "sign-in name or password does not match one in the Microsoft account system"; $connectCmdlet = "Connect-SPOService"; $connectCmdletArgs = "-Url $global:AdminUrl -Credential `$global:o365Credentials"; $variablePrefix = "spo"}
        "ExchangeOnline" {$testCmdlet = "Get-Mailbox"; $exceptionStringMFA = "AADSTS"; $connectCmdlet = "Connect-AzureAD"; $connectCmdletArgs = "-Credential `$global:o365Credentials"; $variablePrefix = "exo"}
        "MSOnline" {$testCmdlet = "Get-MsolUser"; $exceptionStringMFA = "AADSTS"; $connectCmdlet = "Connect-MsolService"; $connectCmdletArgs = "-Credential `$global:o365Credentials"; $variablePrefix = "msol"}
        "PnP" {Get-SPOAdminUrl; $testCmdlet = "Get-PnPSite"; $exceptionStringMFA = "sign-in name or password does not match one in the Microsoft account system"; $connectCmdlet = "Connect-PnPOnline"; $connectCmdletArgs = "-Url $(($global:AdminUrl).Replace('-admin','')) -Credentials `$global:o365Credentials"; $variablePrefix = "pnp"}
    }

    New-Variable -Name $variablePrefix"LoginSucceeded" -Value $false -Scope Global -Option AllScope -Force
    Write-Debug -Message `$$variablePrefix"LoginSucceeded is $(Get-Variable -Name $($variablePrefix+"LoginSucceeded") -ValueOnly -Scope Global -ErrorAction SilentlyContinue)."
    try
    {
        Write-Verbose -Message " - Checking $Platform login..."
        # Run a simple command to check if we are logged in
        Invoke-Expression "$testCmdlet -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null"
        if ($? -eq $false)
        {
            throw
        }
        else
        {
            Write-Verbose -Message " - You are already logged in to $Platform."
        }
    }
    catch
    {
        if ($_.Exception -like "*$connectCmdlet*")
        {
            try
            {
                # Only prompt for Windows-style credentials if we haven't explicitly specified multi-factor authentication
                if (($null -eq $global:o365Credentials) -and (!$UseMFA))
                {
                    $global:o365Credentials = Get-O365Credentials
                    Write-Verbose -Message " - Will attempt to use credential for `"$($global:o365Credentials.UserName)`"..."
                }
                Write-Host -ForegroundColor Cyan " - Prompting for $Platform credentials..."
                Write-Verbose -Message " - Running '$connectCmdlet -ErrorAction Stop $connectCmdletArgs -ErrorVariable `$err'"
                Invoke-Expression "$connectCmdlet -ErrorAction Stop $connectCmdletArgs -ErrorVariable `$err" # | Out-Null"
                if ($? -eq $false -or $err)
                {
                    throw
                }
                else
                {
                    New-Variable -Name $variablePrefix"LoginSucceeded" -Value $true -Scope Global -Option AllScope -Force
                    Write-Debug -Message `$$variablePrefix"LoginSucceeded is $(Get-Variable -Name $($variablePrefix+"LoginSucceeded") -ValueOnly -Scope Global -ErrorAction SilentlyContinue)."
                }
            }
            catch
            {
                if ($_.Exception -like "*User canceled authentication*")
                {
                    throw "User canceled authentication"
                }
                elseif ($_.Exception -like "*The user name or password is incorrect*")
                {
                    throw  "Bad credentials were supplied"
                }
                elseif ($_.Exception -like "*$exceptionStringMFA*" -or $_.Exception -like "*Sequence contains no elements*")
                {
                    Write-Verbose -Message " - Using existing credentials failed (possibly due to MFA or Live ID); prompting for fresh credentials..."
                    try
                    {
                        # Remove the credential info from the arguments string and try again
                        $connectCmdletArgs = $connectCmdletArgs.Replace('-Credential $global:o365Credentials','')
                        Write-Debug -Message "`$connectCmdletArgs is $connectCmdletArgs"
                        Invoke-Expression "$connectCmdlet -ErrorAction Stop $connectCmdletArgs | Out-Null"
                        if ($? -eq $false)
                        {
                            throw
                        }
                        else
                        {
                            New-Variable -Name $variablePrefix"LoginSucceeded" -Value $true -Scope Global -Option AllScope -Force
                            Write-Debug $variablePrefix"LoginSucceeded is $(Get-Variable -Name $($variablePrefix+"LoginSucceeded") -ValueOnly -Scope Global -ErrorAction SilentlyContinue)."
                        }
                    }
                    catch
                    {
                        Write-Host -ForegroundColor Red $_.Exception
                        throw "No/invalid credentials were provided, or another error occurred logging on to $Platform."
                    }
                }
                else
                {
                    Write-Host -ForegroundColor Red $_.Exception
                    throw "No/invalid credentials were provided, or another error occurred logging on to $Platform."
                }
            }
        }
        elseif ($_.Exception -like "*Unable to acquire token for tenant*")
        {
           Write-Host -ForegroundColor Red $_.Exception
        }
        elseif ($_.Exception -like "*null array*")
        {
            # Do nothing
        }
        else
        {
            Write-Host -ForegroundColor Red $_.Exception
        }
    }
    finally
    {
        if (Get-Variable -Name $variablePrefix"LoginSucceeded" -ValueOnly -Scope "Global")
        {
            Write-Host -ForegroundColor Green " - Successfully logged in to $Platform."
        }
    }
}
function Test-AzureADLogin
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$false)]
        [switch]
        $UseMFA
    )
    if ($UseMFA)
    {
        $UseMFASwitch = @{UseMFA = $true}
    }
    else
    {
        $UseMFASwitch = @{}
    }
    Write-Debug -Message "`$aadLoginSucceeded is $(Get-Variable -Name aadLoginSucceeded -ValueOnly -Scope Global -ErrorAction SilentlyContinue)."
    if (!$aadLoginSucceeded)
    {
        Test-CloudLogin -platform "AzureAD" @useMFASwitch
    }
    else
    {
        Write-Verbose -Message "Already logged into Azure AD."
    }
}

# Checks to see if we can run a simple Az command or if we get an exception about "Run Login-AzAccount to login"
function Test-AzLogin
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$false)]
        [switch]
        $UseMFA
    )
    if ($UseMFA)
    {
        $UseMFASwitch = @{UseMFA = $true}
    }
    else
    {
        $UseMFASwitch = @{}
    }
    Write-Debug -Message "`$azLoginSucceeded is $(Get-Variable -Name azLoginSucceeded -ValueOnly -Scope Global -ErrorAction SilentlyContinue)."
    $checkForMultiSubscriptions = $true
    if (!$azLoginSucceeded)
    {
        Test-CloudLogin -Platform "Azure" @useMFASwitch
    }
    else
    {
        Write-Verbose -Message " - Already logged into Azure."
        $checkForMultiSubscriptions = $false
    }
    if ($azLoginSucceeded -and $checkForMultiSubscriptions)
    {
        Write-Verbose -Message " - Successfully logged in to Azure."
        [array]$subscriptions = Get-AzSubscription -WarningAction Continue
        # Prompt for a subscription in case we have more than one
        if ($subscriptions.Count -gt 1)
        {
            Write-Host -ForegroundColor Cyan " - Prompting for subscription..."
            $global:subscriptionDetails = Get-AzSubscription -WarningAction SilentlyContinue | Sort-Object Name | Out-GridView -Title "Select ONE subscription..." -PassThru
            if ($null -eq $subscriptionDetails)
            {
                throw " - A subscription must be selected."
            }
            elseif ($subscriptionDetails.Count -gt 1)
            {
                throw " - Please select *only one* subscription."
            }
            Write-Host -ForegroundColor White " - Setting active subscription to '$($global:subscriptionDetails.Name)'..."
            Set-AzContext -Subscription $global:subscriptionDetails.Id
        }
    }
}

function Get-O365Credentials
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$false)]
        [String]$Username
    )
    if (!([string]::IsNullOrEmpty($Username)))
    {
        $userNameParameter = @{Username = $Username}
    }
    Write-Host -ForegroundColor Cyan " - Prompting for O365 credentials..."
    $global:o365Credentials = Get-Credential -Message "Please enter your credentials for Office 365" @userNameParameter
    return $global:o365Credentials
}
function Get-SPOAdminUrl
{
    [CmdletBinding()]
    param ()
    Test-AzureADLogin
    Write-Verbose -Message "Getting SharePoint Online admin URL..."
    $defaultDomain = Get-AzureADDomain | Where-Object {$_.Name -like "*.onmicrosoft.com" -and $_.IsInitial -eq $true} # We don't use IsDefault here because the default could be a custom domain
    $global:tenantName = $defaultDomain[0].Name -replace ".onmicrosoft.com",""
    $global:AdminUrl = "https://$global:tenantName-admin.sharepoint.com"
    Write-Verbose -Message "SharePoint Online admin URL is $global:AdminUrl"
}