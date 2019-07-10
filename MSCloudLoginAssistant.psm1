<#
.SYNOPSIS
    The Test-MSCloudLogin function is used to assist with logging in to various Microsoft Cloud services, such as Azure, SharePoint Online, and SharePoint PnP.
.EXAMPLE
    Test-MSCloudLogin -Platform AzureAD -Verbose
.EXAMPLE
    Test-MSCloudLogin -Platform PnP
.PARAMETER Platform
    The Platform parameter specifies which cloud service for which we are testing the login state. Possible values are Azure, AzureAD, SharePointOnline, ExchangeOnline, MSOnline, and PnP.
.NOTES
    Created & maintained by Brian Lalancette (@brianlala), 2019.
.LINK
    https://github.com/brianlala/MSCloudLoginAssistant
#>

function Test-MSCloudLogin
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [ValidateSet("Azure","AzureAD","SharePointOnline","ExchangeOnline","SecurityComplianceCenter","MSOnline","PnP","MicrosoftTeams")]
        [System.String]
        $Platform,

        [Parameter()]
        [System.String]
        $ConnectionUrl,

        [Parameter()]
        [System.Management.Automation.PSCredential]
        $O365Credential
    )
    switch ($Platform)
    {
        'Azure'
        {
            $testCmdlet = "Get-AzResource";
            $exceptionStringMFA = "AADSTS";
            $connectCmdlet = "Connect-AzAccount";
            $connectCmdletArgs = "-Credential `$o365Credential";
            $connectCmdletMfaRetryArgs = "";
            $variablePrefix = "az"
        }
        'AzureAD'
        {
            $testCmdlet = "Get-AzureADUser";
            $exceptionStringMFA = "AADSTS";
            $connectCmdlet = "Connect-AzureAD";
            $connectCmdletArgs = "-Credential `$O365Credential";
            $connectCmdletMfaRetryArgs = "-AccountId `$O365Credential.UserName"
            $variablePrefix = "aad"
        }
        'SharePointOnline'
        {
            if ($null -eq $ConnectionUrl)
            {
                $global:spoAdminUrl = Get-SPOAdminUrl;
            }
            else
            {
                $global:spoAdminUrl = $ConnectionUrl
            }
            $testCmdlet = "Get-SPOSite";
            $exceptionStringMFA = "sign-in name or password does not match one in the Microsoft account system";
            $connectCmdlet = "Connect-SPOService";
            $connectCmdletArgs = "-Url $global:spoAdminUrl -Credential `$O365Credential";
            $connectCmdletMfaRetryArgs = ""
            $variablePrefix = "spo"
        }
        'ExchangeOnline'
        {
            $testCmdlet = "Get-Mailbox";
            $exceptionStringMFA = "AADSTS";
            $connectCmdlet = "Connect-EXOPSSession";
            $connectCmdletArgs = "-Credential `$o365Credential";
            $connectCmdletMfaRetryArgs = "-UserPrincipalName `$o365Credential.UserName";
            $variablePrefix = "exo"
        }
        'SecurityComplianceCenter'
        {
            # TODO!
            $testCmdlet = "Get-RetentionCompliancePolicy";
            $exceptionStringMFA = "AADSTS";
            $connectCmdlet = "Connect-IPPSSession";
            $connectCmdletArgs = "-Credential `$o365Credential";
            $connectCmdletMfaRetryArgs = "-UserPrincipalName `$o365Credential.UserName";
            $variablePrefix = "scc"
        }
        'MSOnline'
        {
            $testCmdlet = "Get-MsolUser";
            $exceptionStringMFA = "AADSTS";
            $connectCmdlet = "Connect-MsolService";
            $connectCmdletArgs = "-Credential `$O365Credential";
            $connectCmdletMfaRetryArgs = "";
            $variablePrefix = "msol"
        }
        'PnP'
        {
            $testCmdlet = "Get-PnPSite";
            $exceptionStringMFA = "sign-in name or password does not match one in the Microsoft account system";
            $connectCmdlet = "Connect-PnPOnline";
            $connectCmdletArgs = "-Url $ConnectionUrl -Credentials `$O365Credential";
            $connectCmdletMfaRetryArgs = ""
            $variablePrefix = "pnp"
        }
        'MicrosoftTeams'
        {
            # Need to force-import this for some reason as of 1.0.0
            Import-Module MicrosoftTeams -Force
            $testCmdlet = "Get-Team";
            $exceptionStringMFA = "AADSTS";
            $connectCmdlet = "Connect-MicrosoftTeams";
            $connectCmdletArgs = "-Credential `$o365Credential";
            $variablePrefix = "teams"
        }
    }

    New-Variable -Name $variablePrefix"LoginSucceeded" -Value $false -Scope Global -Option AllScope -Force
    Write-Debug -Message `$$variablePrefix"LoginSucceeded is '$(Get-Variable -Name $($variablePrefix+"LoginSucceeded") -ValueOnly -Scope Global -ErrorAction SilentlyContinue)'."
    try
    {
        Write-Verbose -Message "Checking $Platform login..."
        # Run a simple command to check if we are logged in
        Invoke-Expression "$testCmdlet -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null"
        if ($? -eq $false)
        {
            throw
        }
        elseif ($Platform -eq "PnP")
        {
            $CurrentPnPConnection = (Get-PnPConnection).Url
            if ($ConnectionUrl -ne $CurrentPnPConnection)
            {
                throw "PnP requires you to reconnect to new location using $connectCmdlet"
            }
            else
            {
                Write-Verbose -Message "You are already logged in to $Platform."
            }
        }
        else
        {
            Write-Verbose -Message "You are already logged in to $Platform."
        }
    }
    catch
    {
        if ($_.Exception -like "*$connectCmdlet*")
        {
            try
            {
                Write-Verbose -Message "Running '$connectCmdlet -ErrorAction Stop $connectCmdletArgs -ErrorVariable `$err'"
                Invoke-Expression "$connectCmdlet -ErrorAction Stop $connectCmdletArgs -ErrorVariable `$err" # | Out-Null"
                if ($? -eq $false -or $err)
                {
                    throw
                }
                else
                {
                    New-Variable -Name $variablePrefix"LoginSucceeded" -Value $true -Scope Global -Option AllScope -Force
                    Write-Debug -Message `$$variablePrefix"LoginSucceeded is now '$(Get-Variable -Name $($variablePrefix+"LoginSucceeded") -ValueOnly -Scope Global -ErrorAction SilentlyContinue)'."
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
                    Write-Verbose -Message "The specified user is using Multi-Factor Authentication. You are required to re-enter credentials."
                    Write-Host -ForegroundColor Green "    Prompting for credentials with MFA for $Platform"
                    try
                    {
                        Write-Debug -Message "Replacing `$connectCmdletArgs with '$connectCmdletMfaRetryArgs'"
                        Invoke-Expression "$connectCmdlet -ErrorAction Stop $connectCmdletMfaRetryArgs | Out-Null"
                        if ($? -eq $false)
                        {
                            throw
                        }
                        else
                        {
                            New-Variable -Name $variablePrefix"LoginSucceeded" -Value $true -Scope Global -Option AllScope -Force
                            Write-Debug $variablePrefix"LoginSucceeded is now '$(Get-Variable -Name $($variablePrefix+"LoginSucceeded") -ValueOnly -Scope Global -ErrorAction SilentlyContinue)'."
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
            Write-Verbose -Message " - Successfully logged in to $Platform."
        }
    }
}

# Checks to see if we can run a simple Az command or if we get an exception about "Run Login-AzAccount to login"
function Test-AzLogin
{
    [CmdletBinding()]
    param
    (
    )
    Write-Debug -Message "`$azLoginSucceeded is '$(Get-Variable -Name azLoginSucceeded -ValueOnly -Scope Global -ErrorAction SilentlyContinue)'."
    $checkForMultiSubscriptions = $true
    if (!$azLoginSucceeded)
    {
        Test-MSCloudLogin -Platform Azure
    }
    else
    {
        Write-Verbose -Message "Already logged into Azure."
        $checkForMultiSubscriptions = $false
    }
    if ($azLoginSucceeded -and $checkForMultiSubscriptions)
    {
        Write-Verbose -Message "Successfully logged in to Azure."
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

function Get-O365Credential
{
    [CmdletBinding()]
    param
    (
    )
    Write-Host -ForegroundColor Cyan " - Prompting for MS Online credentials..."
    $o365Credential = Get-Credential -Message "Please enter your credentials for MS Online Services"
    return $o365Credential
}

function Get-SPOAdminUrl
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
    )

    Write-Verbose -Message "Connection to Azure AD is required to automatically determine SharePoint Online admin URL..."
    Test-MSCloudLogin -Platform AzureAD
    Write-Verbose -Message "Getting SharePoint Online admin URL..."
    $defaultDomain = Get-AzureADDomain | Where-Object {$_.Name -like "*.onmicrosoft.com" -and $_.IsInitial -eq $true} # We don't use IsDefault here because the default could be a custom domain
    $tenantName = $defaultDomain[0].Name -replace ".onmicrosoft.com",""
    $spoAdminUrl = "https://$tenantName-admin.sharepoint.com"
    Write-Verbose -Message "SharePoint Online admin URL is $spoAdminUrl"
    return $spoAdminUrl
}
