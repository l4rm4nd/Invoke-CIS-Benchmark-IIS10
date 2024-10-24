<#
.SYNOPSIS
    This script audits a Microsoft IIS 10 web server against the CIS Benchmark.
    It provides checks for various security settings as per the CIS Microsoft IIS 10 Benchmark v1.2.1.

.DESCRIPTION
    This script performs audits based on the specified benchmark items, allowing for individual 
    checks and the option to save outputs for later review.

.AUTHOR
    [LRVT] https://github.com/l4rm4nd
#>

# ----------------------
# 1.1 (L1) Ensure 'Web content' is on non-system partition (Manual) [Basic Configurations]
# ----------------------
Write-Host ""
Write-Host "1.1 (L1) Ensure 'Web content' is on non-system partition (Manual)" -ForegroundColor Cyan
# Get all websites and their physical paths
$websites = Get-Website | Select-Object Name, PhysicalPath

# Get the system partition (usually C:)
$systemPartition = (Get-PSDrive C).Root

# Loop through each website and check the partition
foreach ($site in $websites) {
    $physicalPath = $site.PhysicalPath

    # Get the partition (drive letter) of the physical path
    $sitePartition = [System.IO.Path]::GetPathRoot($physicalPath)

    # Check if the site is on the system partition
    if ($sitePartition -eq $systemPartition) {
        Write-Host "Website '$($site.Name)' is on the system partition ($systemPartition)."
    } else {
        Write-Host "Website '$($site.Name)' is on a different partition ($sitePartition)." -ForegroundColor Green
    }
}

# ----------------------
# 1.2 (L1) Ensure 'Host headers' are on all sites (Automated) [Basic Configurations]
# ----------------------
Write-Host ""
Write-Host "1.2 (L1) Ensure 'Host headers' are on all sites (Automated)" -ForegroundColor Cyan

# ----------------------
# 1.3 (L1) Ensure 'Directory browsing' is set to Disabled (Automated)[Basic Configurations]
# ----------------------
# Check Directory Browsing Configuration
$directoryBrowsing = Get-WebConfigurationProperty -Filter system.webServer/directoryBrowse -PSPath iis:\ -Name Enabled

if ($directoryBrowsing.Value -eq $false) {
    Write-Host "Directory Browsing is DISABLED (Good)" -ForegroundColor Green
} else {
    Write-Host "Directory Browsing is ENABLED (Bad)" -ForegroundColor Red
}
# ----------------------
# 1.4 (L1) Ensure 'application pool identity' is configured for all application pools (Automated) [Basic Configurations]
# ----------------------
# Get Application Pools and check their identity type
$appPools = Get-ChildItem -Path IIS:\AppPools\

foreach ($pool in $appPools) {
    if ($pool.processModel.identityType -eq "ApplicationPoolIdentity") {
        Write-Host "Application Pool: $($pool.Name) - Identity Type is ApplicationPoolIdentity (Good)" -ForegroundColor Green
    } else {
        Write-Host "Application Pool: $($pool.Name) - Identity Type is NOT ApplicationPoolIdentity (Bad)" -ForegroundColor Red
    }
}
# ----------------------
# 1.5 (L1) Ensure 'unique application pools' is set for sites (Automated)[Basic Configurations]
# ----------------------
Write-Host ""
Write-Host "1.5 (L1) Ensure 'unique application pools' is set for sites (Automated)" -ForegroundColor Cyan
# Get websites and their application pools
$websites = Get-Website | Select-Object Name, ApplicationPool

# Group by Application Pool and check for uniqueness
$grouped = $websites | Group-Object ApplicationPool

# Check and display results
foreach ($group in $grouped) {
    if ($group.Group.Count -gt 1) {
        Write-Host "Application Pool: $($group.Name) is used by multiple sites:" -ForegroundColor Red
        foreach ($site in $group.Group) {
            Write-Host " - $($site.Name)"
        }
    } else {
        Write-Host "Application Pool: $($group.Name) is unique to site: $($group.Group[0].Name)" -ForegroundColor Green
    }
}
# ----------------------
# 1.6 (L1) Ensure 'application pool identity' is configured for anonymous user identity (Automated)[Basic Configurations]
# ----------------------
Write-Host ""
Write-Host "1.6 (L1) Ensure 'application pool identity' is configured for anonymous user identity (Automated)" -ForegroundColor Cyan

Get-WebConfiguration system.webServer/security/authentication/anonymousAuthentication -Recurse | 
Where-Object { $_.enabled -eq $true } | 
Select-Object location, @{Name='userName'; Expression={ $_.userName }}

Get-WebConfiguration system.webServer/security/authentication/anonymousAuthentication -Recurse | 
Where-Object { $_.enabled -eq $true } | 
ForEach-Object {
    if ($_.userName -eq "") {
        Write-Host "Anonymous Authentication is enabled at location '$($_.location)' with userName set to blank (Good)" -ForegroundColor Green
    } else {
        Write-Host "Anonymous Authentication is enabled at location '$($_.location)' but userName is NOT blank (Bad)" -ForegroundColor Red
    }
}

# ----------------------
# 1.7 (L1) Ensure' WebDav' feature is disabled (Automated)[Basic Configurations]
# ----------------------
Write-Host ""
Write-Host "1.7 (L1) Ensure 'WebDAV' feature is disabled (Automated)" -ForegroundColor Cyan

# Check if the WebDAV feature is installed
$webDavFeature = Get-WindowsFeature -Name Web-DAV-Publishing

if ($webDavFeature.Installed) {
    Write-Host "WebDAV feature is installed (Warning)." -ForegroundColor Yellow
    
    # Get all websites
    $websites = Get-Website

    foreach ($site in $websites) {
        # Handle special characters and spaces in site names
        $siteName = $site.Name
        
        # Use Get-WebConfigurationProperty to check WebDAV authoring settings
        $webDavAuthoringEnabled = Get-WebConfigurationProperty -PSPath "IIS:\Sites\$($siteName)" -Filter "system.webServer/webdav/authoring" -Name "enabled" -ErrorAction SilentlyContinue

        if ($webDavAuthoringEnabled -and $webDavAuthoringEnabled.Value -eq $true) {
            Write-Host "Website: '$siteName' - WebDAV is ENABLED (Bad)" -ForegroundColor Red
        } else {
            Write-Host "Website: '$siteName' - WebDAV is NOT enabled (Good)" -ForegroundColor Green
        }
    }
} else {
    Write-Host "WebDAV feature is NOT installed (Good)" -ForegroundColor Green
}

# ----------------------
# 2.1 (L1) Ensure 'global authorization rule' is set to restrict access (Manual) [Configure Authentication and Authorization]
# ----------------------
Write-Host ""
Write-Host "2.1 (L1) Ensure 'global authorization rule' is set to restrict access (Manual)" -ForegroundColor Cyan

# Get authorization rules
$authRules = Get-WebConfiguration -pspath 'IIS:\' -filter 'system.webServer/security/authorization'

# Check if the correct authorization rules are set
$allowedUsers = @()
$deniedUsers = @()

foreach ($rule in $authRules.authorization) {
    if ($rule.allow -and $rule.users -eq "BUILTIN\Administrators") {
        $allowedUsers += $rule.users
    }
    if ($rule.deny -and $rule.users -eq "*") {
        $deniedUsers += $rule.users
    }
}

if ($allowedUsers.Count -gt 0 -and $deniedUsers.Count -gt 0) {
    Write-Host "Authorization rules are correctly set:" -ForegroundColor Green
    Write-Host "Allowed Users: $($allowedUsers -join ', ')" -ForegroundColor Green
    Write-Host "Denied Users: $($deniedUsers -join ', ')" -ForegroundColor Green
} else {
    Write-Host "Authorization rules are NOT set, allowing all user access (Bad)." -ForegroundColor Red
}

# ----------------------
# 2.2 (L1) Ensure access to sensitive site features is restricted to authenticated principals only (Manual)[Configure Authentication and Authorization]
# ----------------------
Write-Host ""
Write-Host "2.2 (L1) Ensure access to sensitive site features is restricted to authenticated principals only (Manual)" -ForegroundColor Cyan

# Get all websites
$websites = Get-Website

# Get the authentication settings for each website
foreach ($site in $websites) {
    $siteName = $site.Name
    
    # Check Anonymous Authentication
    $anonymousAuth = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter 'system.webServer/security/authentication/anonymousAuthentication' -name 'enabled' -ErrorAction SilentlyContinue
    
    # Check Windows Authentication
    $windowsAuth = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter 'system.webServer/security/authentication/windowsAuthentication' -name 'enabled' -ErrorAction SilentlyContinue

    # Determine authentication status
    if ($anonymousAuth -and $anonymousAuth.Value -eq $true) {
        Write-Host "Site: '$siteName' - Authentication: Anonymous (Yellow)" -ForegroundColor Yellow
    } elseif ($windowsAuth -and $windowsAuth.Value -eq $true) {
        Write-Host "Site: '$siteName' - Authentication: Windows (Green)" -ForegroundColor Green
    } else {
        Write-Host "Site: '$siteName' - Authentication: Other or Not Configured (Red)" -ForegroundColor Red
    }
}

# ----------------------
# 2.3 (L1) Ensure 'forms authentication' require SSL (Automated) [Configure Authentication and Authorization]
# ----------------------
Write-Host ""
Write-Host "2.3 (L1) Ensure 'forms authentication' require SSL (Automated)" -ForegroundColor Cyan

# Get all websites
$websites = Get-Website

foreach ($site in $websites) {
    $siteName = $site.Name
    
    # Construct the path for the site's configuration
    $psPath = "MACHINE/WEBROOT/APPHOST/$siteName"
    
    # Check requireSSL property for forms authentication
    $requireSSL = Get-WebConfigurationProperty -pspath $psPath -filter 'system.web/authentication/forms' -name 'requireSSL' -ErrorAction SilentlyContinue
    
    if ($requireSSL) {
        if ($requireSSL -eq 'True') {
            Write-Host "Site: '$siteName' - requireSSL is set to True (Good)" -ForegroundColor Green
        } else {
            Write-Host "Site: '$siteName' - requireSSL is NOT set to True (Bad)" -ForegroundColor Red
        }
    } else {
        Write-Host "Site: '$siteName' - Forms Authentication configuration not found (Check manually)." -ForegroundColor Yellow
    }
}

# ----------------------
# 2.4 (L2) Ensure 'forms authentication' is set to use cookies (Automated)[Configure Authentication and Authorization]
# ----------------------
Write-Host ""
Write-Host "2.4 (L2) Ensure 'forms authentication' is set to use cookies (Automated)" -ForegroundColor Cyan

# Get all websites
$websites = Get-Website

foreach ($site in $websites) {
    $siteName = $site.Name
    
    # Check the cookieless property for forms authentication
    $cookieless = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$siteName" -filter 'system.web/authentication/forms' -name 'cookieless' -ErrorAction SilentlyContinue
    
    if ($cookieless) {
        if ($cookieless -eq 'UseCookies') {
            Write-Host "Site: '$siteName' - Cookieless is set to UseCookies (Good)" -ForegroundColor Green
        } else {
            Write-Host "Site: '$siteName' - Cookieless is NOT set to UseCookies but to $cookieless (Bad)" -ForegroundColor Red
        }
    } else {
        Write-Host "Site: '$siteName' - Forms Authentication configuration not found (Check manually)." -ForegroundColor Yellow
    }
}

# ----------------------
# 2.5 (L1) Ensure 'cookie protection mode' is configured for forms authentication (Automated)[Configure Authentication and Authorization]
# ----------------------
Write-Host ""
Write-Host "2.5 (L1) Ensure 'cookie protection mode' is configured for forms authentication (Automated)" -ForegroundColor Cyan
# Get all websites
$websites = Get-Website

foreach ($site in $websites) {
    $siteName = $site.Name
    
    # Check the protection property for forms authentication
    $protection = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$siteName" -filter 'system.web/authentication/forms' -name 'protection' -ErrorAction SilentlyContinue
    
    if ($protection) {
        if ($protection -eq 'All') {
            Write-Host "Site: '$siteName' - Protection is set to All (Good)" -ForegroundColor Green
        } else {
            Write-Host "Site: '$siteName' - Protection is NOT set to All (Bad)" -ForegroundColor Red
        }
    } else {
        Write-Host "Site: '$siteName' - Forms Authentication configuration not found (Check manually)." -ForegroundColor Yellow
    }
}

# ----------------------
# 2.6 (L1) Ensure transport layer security for 'basic authentication' is configured (Automated)[Configure Authentication and Authorization]
# ----------------------
Write-Host ""
Write-Host "2.6 (L1) Ensure transport layer security for 'basic authentication' is configured (Automated)" -ForegroundColor Cyan
# Get all websites
$websites = Get-Website

foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the sslFlags setting for each website
        $sslFlags = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -location $siteName -filter 'system.webServer/security/access' -name 'sslFlags'

        # Check the value of sslFlags
        $sslFlagsValue = $sslFlags.Value

        if ($sslFlagsValue -eq 0) {
            # sslFlags is 0, which is bad
            Write-Host "Website: '$siteName' - SslFlags: $sslFlagsValue; Transport layer security not enforced for basic authentication! (Bad)" -ForegroundColor Red
        } else {
            # sslFlags is properly configured
            Write-Host "Website: '$siteName' - SslFlags: $sslFlagsValue; Transport layer security is enforced for basic authentication! (Good) " -ForegroundColor Green
        }
    } catch {
        # Handle cases where sslFlags might not be configured
        Write-Host "Website: '$siteName' - SslFlags: Not Configured or Error (Please check the configuration)" -ForegroundColor Red
    }
}

# ----------------------
# 2.7 (L1) Ensure 'passwordFormat' is not set to clear (Automated) [Configure Authentication and Authorization]
# ----------------------
Write-Host ""
Write-Host "2.7 (L1) Ensure 'passwordFormat' is not set to clear (Automated)" -ForegroundColor Cyan
# Get all websites
$websites = Get-Website

foreach ($site in $websites) {
    $siteName = $site.Name
    
    # Check for the presence of the credentials element
    $credentials = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$siteName" -filter 'system.web/authentication/forms/credentials' -name 'passwordFormat' -ErrorAction SilentlyContinue

    if ($credentials) {
        Write-Host "Site: '$siteName' - Credentials element is present; $credentials is used (Bad)" -ForegroundColor Red
    } else {
        Write-Host "Site: '$siteName' - Credentials element is NOT present (Good)" -ForegroundColor Green
    }
}
# ----------------------
# 2.8 (L2) Ensure 'credentials' are not stored in configuration files (Automated) [Configure Authentication and Authorization]
# ----------------------
Write-Host ""
Write-Host "2.8 (L2) Ensure 'credentials' are not stored in configuration files (Automated)" -ForegroundColor Cyan
# Get all websites
$websites = Get-Website

foreach ($site in $websites) {
    $siteName = $site.Name
    
    # Check for the presence of the credentials element
    $credentials = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$siteName" -filter 'system.web/authentication/forms/credentials' -name 'passwordFormat' -ErrorAction SilentlyContinue

    if ($credentials) {
        Write-Host "Site: '$siteName' - Credentials are stored in config files via $credentials (Bad)" -ForegroundColor Red
    } else {
        Write-Host "Site: '$siteName' - Credentials element is NOT present (Good)" -ForegroundColor Green
    }
}

# ----------------------
# 3.1 (L1) Ensure 'deployment method retail' is set (Manual)[ASP.NET Configuration Recommendations]
# ----------------------
Write-Host ""
Write-Host "3.1 (L1) Ensure 'deployment method retail' is set (Manual)" -ForegroundColor Cyan
# Path to the machine.config file
$machineConfigPath = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config" # Adjust path based on your environment

# Load the XML from the machine.config file
[xml]$config = Get-Content $machineConfigPath

# Check for the deployment setting
$deploymentSetting = $config.configuration.'system.web'.deployment

if ($deploymentSetting -and $deploymentSetting.retail -eq "true") {
    Write-Host "<deployment retail='true' /> is set correctly (Good)" -ForegroundColor Green
} else {
    Write-Host "<deployment retail='true' /> is NOT set correctly (Bad)" -ForegroundColor Red
}

# ----------------------
# 3.2 (L2) Ensure 'debug' is turned off (Automated) [ASP.NET Configuration Recommendations]
# ----------------------
Write-Host ""
Write-Host "3.2 (L2) Ensure 'debug' is turned off (Automated)" -ForegroundColor Cyan
# Get all websites
$websites = Get-Website

# Loop through each website and extract the debug setting from the compilation section
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the debug setting for the website's compilation section
        $debugSetting = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$siteName" -filter "system.web/compilation" -name "debug"

        # Check if the value is explicitly set or inherited
        if ($debugSetting.Value -ne $null) {
            # Explicit value found
            $result = $debugSetting.Value
            $inherited = "No"
        } else {
            # No explicit value, get the inherited value
            $inheritedDebugSetting = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.web/compilation" -name "debug"
            $result = $inheritedDebugSetting.Value
            $inherited = "Yes"
        }

        # Color output based on the debug value
        if ($result -eq $true) {
            Write-Host "Website: '$siteName' - Debug: $result; Debugging Enabled (Bad)" -ForegroundColor Red
        } else {
            Write-Host "Website: '$siteName' - Debug: $result; Debugging Disabled (Good)" -ForegroundColor Green
        }
    } catch {
        # Handle cases where the debug setting might not be configured or if there's an error
        $inheritedDebugSetting = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.web/compilation" -name "debug"
        Write-Host "Website: '$siteName' - Debug: Not Configured (Inherited: Yes) - Error or Not Configured (Bad)" -ForegroundColor Red
    }
}

# ----------------------
# 3.3 (L2) Ensure custom error messages are not off (Automated) [ASP.NET Configuration Recommendations]
# ----------------------
Write-Host ""
Write-Host "3.3 (L2) Ensure custom error messages are not off (Automated)" -ForegroundColor Cyan

# Get all websites
$websites = Get-Website

foreach ($site in $websites) {
    $siteName = $site.Name
    
    # Check the customErrors configuration
    $customErrors = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$siteName" -filter "system.web/customErrors" -name "mode" -ErrorAction SilentlyContinue

    if ($customErrors) {
        if ($customErrors -eq 'On' -or $customErrors -eq 'RemoteOnly') {
            Write-Host "Site: '$siteName' - customErrors mode is set to '$($customErrors)' (Good)" -ForegroundColor Green
        } else {
            Write-Host "Site: '$siteName' - customErrors mode is set to '$($customErrors)' (Bad)" -ForegroundColor Red
        }
    } else {
        Write-Host "Site: '$siteName' - customErrors configuration not found (Check manually)." -ForegroundColor Yellow
    }
}

# ----------------------
# 3.4 (L1) Ensure IIS HTTP detailed errors are hidden from displaying remotely (Automated)[ASP.NET Configuration Recommendations]
# ----------------------
Write-Host ""
Write-Host "3.4 (L1) Ensure IIS HTTP detailed errors are hidden from displaying remotely (Automated)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and extract httpErrors errorMode setting
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the errorMode setting for the website
        $errorMode = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$siteName" -filter "system.webServer/httpErrors" -name "errorMode"

        # If the value is not explicitly set, retrieve the inherited (parent) value
        if ($errorMode -eq $null -or $errorMode -eq "") {
            $inheritedErrorMode = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/httpErrors" -name "errorMode"
            $errorMode = $inheritedErrorMode
            $inherited = "Yes"
        } else {
            $inherited = "No"
        }

        # Color-coded output based on the errorMode value
        if ($errorMode -eq "Detailed") {
            # Detailed error mode is considered bad in production
            Write-Host "Website: $siteName - ErrorMode: $($errorMode) (Bad, Inherited: $inherited)" -ForegroundColor Red
        } elseif ($errorMode -eq "Custom" -or $errorMode -eq "DetailedLocalOnly") {
            # Custom or DetailedLocalOnly is considered good
            Write-Host "Website: $siteName - ErrorMode: $($errorMode) (Good, Inherited: $inherited)" -ForegroundColor Green
        } else {
            # If errorMode is set to an unknown value or empty, treat it as unhandled or empty
            Write-Host "Website: $siteName - ErrorMode: Not Set or Unhandled Value ($($errorMode)) (Inherited: $inherited)" -ForegroundColor Red
        }
    } catch {
        # Handle cases where httpErrors might not be configured or there's an error
        $inheritedErrorMode = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/httpErrors" -name "errorMode"

        # If inherited value is DetailedLocalOnly, print in green; otherwise, in red
        if ($inheritedErrorMode.Value -eq "DetailedLocalOnly") {
            Write-Host "Website: $siteName - ErrorMode: $($inheritedErrorMode.Value) (Inherited: Yes, Good)" -ForegroundColor Green
        } else {
            Write-Host "Website: $siteName - ErrorMode: $($inheritedErrorMode.Value) (Inherited: Yes, Not Configured or Error)" -ForegroundColor Red
        }
    }
}
# ----------------------
# 3.5 (L2) Ensure ASP.NET stack tracing is not enabled (Automated)[ASP.NET Configuration Recommendations]
# ----------------------
Write-Host ""
Write-Host "3.5 (L2) Ensure ASP.NET stack tracing is not enabled (Automated)" -ForegroundColor Cyan
# Get all websites
$websites = Get-Website

foreach ($site in $websites) {
    $siteName = $site.Name
    
    # Check the customErrors configuration
    $customErrors = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$siteName" -filter 'system.web/customErrors' -name 'mode' -ErrorAction SilentlyContinue

    if ($customErrors) {
        if ($customErrors -eq 'RemoteOnly' -or $customErrors -eq 'On') {
            Write-Host "Site: '$siteName' - customErrors mode is set to '$($customErrors)' (Good)" -ForegroundColor Green
        } else {
            Write-Host "Site: '$siteName' - customErrors mode is set to '$($customErrors)' (Bad)" -ForegroundColor Red
        }
    } else {
        Write-Host "Site: '$siteName' - customErrors configuration not found (Check manually)." -ForegroundColor Yellow
    }
}

# ----------------------
# 3.6 (L2) Ensure 'httpcookie' mode is configured for session state (Automated)[ASP.NET Configuration Recommendations]
# ----------------------
Write-Host ""
Write-Host "3.6 (L2) Ensure 'httpcookie' mode is configured for session state (Automated)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and extract sessionState cookieless setting
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the cookieless attribute of the sessionState configuration
        $cookielessSetting = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$siteName" -filter "system.web/sessionState" -name "cookieless"

        # Check if the cookieless setting is properly configured
        if ($cookielessSetting -eq "UseCookies") {
            Write-Host "Website: $siteName - SessionState cookieless is set to $cookielessSetting. (Good)" -ForegroundColor Green
        } else {
            Write-Host "Website: $siteName - SessionState cookieless is not set to UseCookies (Bad)" -ForegroundColor Yellow
        }
    } catch {
        # Handle cases where sessionState might not be configured or there's an error
        Write-Host "Website: $siteName - SessionState cookieless not configured or error occurred." -ForegroundColor Red
    }
}

# ----------------------
# 3.7 (L1) Ensure 'cookies' are set with HttpOnly attribute (Automated)[ASP.NET Configuration Recommendations]
# ----------------------
Write-Host ""
Write-Host "3.7 (L1) Ensure 'cookies' are set with HttpOnly attribute (Automated)" -ForegroundColor Cyan
# Get all websites
$websites = Get-Website

foreach ($site in $websites) {
    $siteName = $site.Name
    $physicalPath = $site.PhysicalPath

    # Construct the path to the web.config file
    $webConfigPath = Join-Path $physicalPath 'web.config'

    # Use Test-Path with double quotes to ensure paths with spaces are handled correctly
    if (Test-Path $webConfigPath) {
        try {
            # Load the XML from the web.config file
            [xml]$webConfig = Get-Content $webConfigPath
            
            # Check if the <system.web> section exists
            if ($webConfig.configuration.'system.web') {
                # Check if <httpCookies> tag exists
                $httpCookies = $webConfig.configuration.'system.web'.httpCookies

                if ($httpCookies) {
                    if ($httpCookies.httpOnlyCookies -eq "true") {
                        Write-Host "Site: '$siteName' - <httpCookies httpOnlyCookies='true' /> is present (Good)" -ForegroundColor Green
                    } else {
                        Write-Host "Site: '$siteName' - <httpCookies httpOnlyCookies='false' /> is present (Bad)" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Site: '$siteName' - <httpCookies> tag is not present (Bad)" -ForegroundColor Red
                }
            } else {
                Write-Host "Site: '$siteName' - <system.web> section not found (Bad)" -ForegroundColor Red
            }
        } catch {
            Write-Host "Site: '$siteName' - Error reading web.config: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "Site: '$siteName' - web.config file not found at '$webConfigPath'." -ForegroundColor Yellow
    }
}

# ----------------------
# 3.8 (L2) Ensure 'MachineKey validation method - .Net 3.5' is configured (Automated)[ASP.NET Configuration Recommendations]
# ----------------------
Write-Host ""
Write-Host "3.8 (L2) Ensure 'MachineKey validation method - .Net 3.5' is configured (Automated)" -ForegroundColor Cyan
# Get all websites on the server
$websites = Get-Website

# Loop through each website and check the machineKey validation method
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the validation method of the machineKey for each website
        $validationMethod = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$siteName" -filter "system.web/machineKey" -name "validation"

        # Display the result for each website
        if ($validationMethod -ne $null) {
            Write-Host "Website: $siteName - MachineKey Validation Method: $validationMethod (Good)" -ForegroundColor Green
        } else {
            Write-Host "Website: $siteName - MachineKey Validation Method: Not Configured (Bad)" -ForegroundColor Yellow
        }
    } catch {
        # Handle cases where machineKey might not be configured or there's an error
        Write-Host "Website: $siteName - Error retrieving MachineKey Validation Method" -ForegroundColor Red
    }
}

# ----------------------
# 3.9 (L1) Ensure 'MachineKey validation method - .Net 4.5' is configured (Automated) [ASP.NET Configuration Recommendations]
# ----------------------
Write-Host ""
Write-Host "3.9 (L1) Ensure 'MachineKey validation method - .Net 4.5' is configured (Automated)" -ForegroundColor Cyan
# Get the global .NET Trust Level
$trustLevel = Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT' -filter "system.web/trust" -name "level" -ErrorAction SilentlyContinue

if ($trustLevel) {
    if ($trustLevel.Value -eq 'Medium') {
        Write-Host "Global .NET Trust Level is set to Medium (Good)" -ForegroundColor Green
    } else {
        Write-Host "Global .NET Trust Level is set to '$($trustLevel.Value)' (Bad)" -ForegroundColor Red
    }
} else {
    Write-Host "Global .NET Trust Level configuration not found (Check manually)." -ForegroundColor Yellow
}

# ----------------------
# 3.10 (L1) Ensure global .NET trust level is configured (Automated) [ASP.NET Configuration Recommendations]
# ----------------------
Write-Host ""
Write-Host "3.10 (L1) Ensure global .NET trust level is configured (Automated)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and check the .NET Trust Level
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the .NET Trust Level for each website
        $trustLevel = Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST/$siteName" -filter "system.web/trust" -name "level"

        # Access the value property directly
        if ($trustLevel.Value -ne $null) {
            Write-Host "Website: $siteName - .NET Trust Level: $($trustLevel.Value)" -ForegroundColor Green
        } else {
            Write-Host "Website: $siteName - .NET Trust Level: Not Configured" -ForegroundColor Yellow
        }
    } catch {
        # Handle cases where trust level might not be configured or there's an error
        Write-Host "Website: $siteName - Error retrieving .NET Trust Level" -ForegroundColor Red
    }
}

# ----------------------
# 3.11 (L2) Ensure X-Powered-By Header is removed (Manual) [ASP.NET Configuration Recommendations]
# ----------------------
Write-Host ""
Write-Host "3.11 (L2) Ensure X-Powered-By Header is removed (Manual)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and check the httpProtocol section
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the customHeaders from the httpProtocol section for each website
        $customHeaders = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter "system.webServer/httpProtocol/customHeaders" -name "Collection"

        # Check if X-Powered-By header exists
        if ($customHeaders -ne $null) {
            foreach ($header in $customHeaders) {
                if ($header.name -eq "X-Powered-By") {
                    # Flag X-Powered-By as a security risk and display in red
                    Write-Host "Website: $siteName - X-Powered-By Header Found (Bad)" -ForegroundColor Red
                }
            }
        }

    } catch {
        # Handle cases where the httpProtocol section might not be configured or there's an error
        Write-Host "Website: $siteName - Error retrieving httpProtocol configuration" -ForegroundColor Red
    }
}

# ----------------------
# 3.12 (L2) Ensure Server Header is removed (Manual)[ASP.NET Configuration Recommendations]
# ----------------------
Write-Host ""
Write-Host "3.12 (L2) Ensure Server Header is removed (Manual)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and check the removeServerHeader property
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the removeServerHeader property from the requestFiltering section
        $removeServerHeader = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter 'system.webServer/security/requestFiltering' -name 'removeServerHeader'

        # Check if removeServerHeader is set to true (good) or false/not configured (bad)
        if ($removeServerHeader -eq $true) {
            Write-Host "Website: $siteName - Server Header Removal is Enabled (Good)" -ForegroundColor Green
        } else {
            Write-Host "Website: $siteName - Server Header Removal is NOT Enabled (Bad)" -ForegroundColor Red
        }

    } catch {
        # Handle cases where the requestFiltering section might not be configured or there's an error
        Write-Host "Website: $siteName - Error retrieving requestFiltering configuration" -ForegroundColor Red
    }
}

# ----------------------
# 4.1 (L2) Ensure 'maxAllowedContentLength' is configured (Manual)[Request Filtering and Other Restriction Modules]
# ----------------------
Write-Host ""
Write-Host "4.1 (L2) Ensure 'maxAllowedContentLength' is configured (Manual)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and check the maxAllowedContentLength property
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the maxAllowedContentLength property from the requestLimits section
        $maxAllowedContentLength = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxAllowedContentLength"

        # Access the .Value property to get the actual number
        if ($maxAllowedContentLength.Value -ne $null) {
            Write-Host "Website: $siteName - maxAllowedContentLength: $($maxAllowedContentLength.Value) bytes" -ForegroundColor Green
        } else {
            Write-Host "Website: $siteName - maxAllowedContentLength is not configured" -ForegroundColor Yellow
        }

    } catch {
        # Handle cases where the requestLimits section might not be configured or there's an error
        Write-Host "Website: $siteName - Error retrieving maxAllowedContentLength configuration" -ForegroundColor Red
    }
}

# ----------------------
# 4.2 (L2) Ensure 'maxURL request filter' is configured (Automated)[Request Filtering and Other Restriction Modules]
# ----------------------
Write-Host ""
Write-Host "4.2 (L2) Ensure 'maxURL request filter' is configured (Automated)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and check the maxUrl property
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the maxUrl property from the requestLimits section
        $maxUrlLength = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxUrl"

        # Access the .Value property to get the actual number
        if ($maxUrlLength.Value -ne $null) {
            Write-Host "Website: $siteName - maxUrl: $($maxUrlLength.Value) characters" -ForegroundColor Green
        } else {
            Write-Host "Website: $siteName - maxUrl is not configured" -ForegroundColor Yellow
        }

    } catch {
        # Handle cases where the requestLimits section might not be configured or there's an error
        Write-Host "Website: $siteName - Error retrieving maxUrl configuration" -ForegroundColor Red
    }
}

# ----------------------
# 4.3 (L2) Ensure 'MaxQueryString request filter' is configured (Automated)[Request Filtering and Other Restriction Modules]
# ----------------------
Write-Host ""
Write-Host "4.3 (L2) Ensure 'MaxQueryString request filter' is configured (Automated)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and check the maxQueryString property
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the maxQueryString property from the requestLimits section
        $maxQueryStringLength = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter "system.webServer/security/requestFiltering/requestLimits" -name "maxQueryString"

        # Access the .Value property to get the actual number
        if ($maxQueryStringLength.Value -ne $null) {
            Write-Host "Website: $siteName - maxQueryString: $($maxQueryStringLength.Value) characters" -ForegroundColor Green
        } else {
            Write-Host "Website: $siteName - maxQueryString is not configured" -ForegroundColor Yellow
        }

    } catch {
        # Handle cases where the requestLimits section might not be configured or there's an error
        Write-Host "Website: $siteName - Error retrieving maxQueryString configuration" -ForegroundColor Red
    }
}

# ----------------------
# 4.4 (L2) Ensure non-ASCII characters in URLs are not allowed (Automated)[Request Filtering and Other Restriction Modules]
# ----------------------
Write-Host ""
Write-Host "4.4 (L2) Ensure non-ASCII characters in URLs are not allowed (Automated)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and check the allowHighBitCharacters property
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the allowHighBitCharacters property from the requestFiltering section
        $allowHighBitCharacters = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter "system.webServer/security/requestFiltering" -name "allowHighBitCharacters"

        # Access the .Value property to get the actual boolean value
        if ($allowHighBitCharacters.Value -ne $null) {
            if ($allowHighBitCharacters.Value -eq $false) {
                Write-Host "Website: $siteName - High-bit characters are DISABLED (Good)" -ForegroundColor Green
            } else {
                Write-Host "Website: $siteName - High-bit characters are ENABLED (Bad)" -ForegroundColor Red
            }
        } else {
            Write-Host "Website: $siteName - allowHighBitCharacters is not configured" -ForegroundColor Yellow
        }

    } catch {
        # Handle cases where the requestFiltering section might not be configured or there's an error
        Write-Host "Website: $siteName - Error retrieving allowHighBitCharacters configuration" -ForegroundColor Red
    }
}


# ----------------------
# 4.5 (L1) Ensure Double-Encoded requests will be rejected (Automated)[Request Filtering and Other Restriction Modules]
# ----------------------
Write-Host ""
Write-Host "4.5 (L1) Ensure Double-Encoded requests will be rejected (Automated)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and check the allowDoubleEscaping property
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the allowDoubleEscaping property from the requestFiltering section
        $allowDoubleEscaping = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter "system.webServer/security/requestFiltering" -name "allowDoubleEscaping"

        # Access the .Value property to get the actual boolean value
        if ($allowDoubleEscaping.Value -ne $null) {
            if ($allowDoubleEscaping.Value -eq $false) {
                Write-Host "Website: $siteName - Double Escaping is DISABLED (Good)" -ForegroundColor Green
            } else {
                Write-Host "Website: $siteName - Double Escaping is ENABLED (Bad)" -ForegroundColor Red
            }
        } else {
            Write-Host "Website: $siteName - allowDoubleEscaping is not configured" -ForegroundColor Yellow
        }

    } catch {
        # Handle cases where the requestFiltering section might not be configured or there's an error
        Write-Host "Website: $siteName - Error retrieving allowDoubleEscaping configuration" -ForegroundColor Red
    }
}
# ----------------------
# 4.6 (L1) Ensure 'HTTP Trace Method' is disabled (Manual)[Request Filtering and Other Restriction Modules]
# ----------------------
Write-Host ""
Write-Host "4.6 (L1) Ensure 'HTTP Trace Method' is disabled (Manual)" -ForegroundColor Cyan
$websites = Get-Website

foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Use AppCmd to check the requestFiltering configuration for the site
        $appcmdOutput = & "$env:systemroot\system32\inetsrv\appcmd.exe" list config "$siteName" /section:requestfiltering

        # Check if TRACE is disabled
        if ($appcmdOutput -match '<add verb="TRACE" allowed="false" />') {
            Write-Host "Website: $siteName - TRACE method is DISABLED (Good)" -ForegroundColor Green
        } else {
            Write-Host "Website: $siteName - TRACE method is NOT FILTERED (Bad)" -ForegroundColor Red
        }

    } catch {
        Write-Host "Website: $siteName - Error retrieving requestFiltering configuration" -ForegroundColor Red
    }
}
# ----------------------
# 4.7 (L1) Ensure Unlisted File Extensions are not allowed (Automated)[Request Filtering and Other Restriction Modules]
# ----------------------
Write-Host ""
Write-Host "4.7 (L1) Ensure Unlisted File Extensions are not allowed (Automated)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and check the allowUnlisted property for file extensions
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the allowUnlisted property from the fileExtensions section in requestFiltering
        $allowUnlisted = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter "system.webServer/security/requestFiltering/fileExtensions" -name "allowUnlisted"

        # Access the .Value property to get the actual boolean value
        if ($allowUnlisted.Value -ne $null) {
            if ($allowUnlisted.Value -eq $false) {
                Write-Host "Website: $siteName - Unlisted file extensions are DISALLOWED (Good)" -ForegroundColor Green
            } else {
                Write-Host "Website: $siteName - Unlisted file extensions are ALLOWED (Bad)" -ForegroundColor Red
            }
        } else {
            Write-Host "Website: $siteName - allowUnlisted is not configured" -ForegroundColor Yellow
        }

    } catch {
        # Handle cases where the requestFiltering section might not be configured or there's an error
        Write-Host "Website: $siteName - Error retrieving allowUnlisted configuration" -ForegroundColor Red
    }
}

# ----------------------
# 4.8 (L1) Ensure Handler is not granted Write and Script/Execute (Manual)[Request Filtering and Other Restriction Modules]
# ----------------------
Write-Host ""
Write-Host "4.8 (L1) Ensure Handler is not granted Write and Script/Execute (Manual)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and check the accessPolicy attribute for handlers
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the accessPolicy attribute from the handlers section
        $accessPolicy = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter "system.webServer/handlers" -name "accessPolicy"

        # Check if Write is present along with Script or Execute
        if ($accessPolicy -ne $null) {
            if ($accessPolicy -match "Write" -and ($accessPolicy -match "Script" -or $accessPolicy -match "Execute")) {
                Write-Host "Website: $siteName - accessPolicy contains Write with Script or Execute (Bad)" -ForegroundColor Red
            } else {
                Write-Host "Website: $siteName - accessPolicy is safe: $($accessPolicy)" -ForegroundColor Green
            }
        } else {
            Write-Host "Website: $siteName - accessPolicy is not configured" -ForegroundColor Yellow
        }

    } catch {
        # Handle cases where the handlers section might not be configured or there's an error
        Write-Host "Website: $siteName - Error retrieving accessPolicy configuration" -ForegroundColor Red
    }
}
# ----------------------
# 4.9 (L1) Ensure 'notListedIsapisAllowed' is set to false (Automated)[Request Filtering and Other Restriction Modules]
# ----------------------
Write-Host ""
Write-Host "4.9 (L1) Ensure 'notListedIsapisAllowed' is set to false (Automated)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and check the notListedIsapisAllowed property
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the notListedIsapisAllowed property from the isapiCgiRestriction section
        $notListedIsapisAllowed = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter "system.webServer/security/isapiCgiRestriction" -name "notListedIsapisAllowed"

        # Check if notListedIsapisAllowed is set to false (secure)
        if ($notListedIsapisAllowed -ne $null) {
            if ($notListedIsapisAllowed -eq $false) {
                Write-Host "Website: $siteName - Unlisted ISAPI and CGI modules are DISALLOWED (Good)" -ForegroundColor Green
            } else {
                Write-Host "Website: $siteName - Unlisted ISAPI and CGI modules are ALLOWED (Bad)" -ForegroundColor Red
            }
        } else {
            Write-Host "Website: $siteName - notListedIsapisAllowed is not configured" -ForegroundColor Yellow
        }

    } catch {
        # Handle cases where the isapiCgiRestriction section might not be configured or there's an error
        Write-Host "Website: $siteName - Error retrieving notListedIsapisAllowed configuration" -ForegroundColor Red
    }
}

# ----------------------
# 4.10 (L1) Ensure 'notListedCgisAllowed' is set to false (Automated)[Request Filtering and Other Restriction Modules]
# ----------------------
Write-Host ""
Write-Host "4.10 (L1) Ensure 'notListedCgisAllowed' is set to false (Automated)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and check the notListedCgisAllowed property
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the notListedCgisAllowed property from the isapiCgiRestriction section
        $notListedCgisAllowed = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter "system.webServer/security/isapiCgiRestriction" -name "notListedCgisAllowed"

        # Check if notListedCgisAllowed is set to false (secure)
        if ($notListedCgisAllowed.Value -ne $null) {
            if ($notListedCgisAllowed.Value -eq $false) {
                Write-Host "Website: $siteName - Unlisted CGI scripts are DISALLOWED (Good)" -ForegroundColor Green
            } else {
                Write-Host "Website: $siteName - Unlisted CGI scripts are ALLOWED (Bad)" -ForegroundColor Red
            }
        } else {
            Write-Host "Website: $siteName - notListedCgisAllowed is not configured" -ForegroundColor Yellow
        }

    } catch {
        # Handle cases where the isapiCgiRestriction section might not be configured or there's an error
        Write-Host "Website: $siteName - Error retrieving notListedCgisAllowed configuration" -ForegroundColor Red
    }
}
# ----------------------
# 4.11 (L1) Ensure 'Dynamic IP Address Restrictions' is enabled (Manual)[Request Filtering and Other Restriction Modules]
# ----------------------
Write-Host ""
Write-Host "4.11 (L1) Ensure 'Dynamic IP Address Restrictions' is enabled (Manual)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and check the denyByConcurrentRequests settings
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Check if denyByConcurrentRequests is enabled
        $enabled = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -name "enabled"

        # Check the maxConcurrentRequests setting
        $maxConcurrentRequests = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter "system.webServer/security/dynamicIpSecurity/denyByConcurrentRequests" -name "maxConcurrentRequests"

        # Output results
        if ($enabled.Value -eq $true) {
            Write-Host "Website: $siteName - denyByConcurrentRequests is ENABLED" -ForegroundColor Green
            Write-Host "Max Concurrent Requests: $($maxConcurrentRequests.Value)" -ForegroundColor Green
        } else {
            Write-Host "Website: $siteName - denyByConcurrentRequests is DISABLED" -ForegroundColor Red
        }

    } catch {
        Write-Host "Website: $siteName - Error retrieving dynamic IP security configuration" -ForegroundColor Red
    }
}

# ----------------------
# 5.1 (L1) Ensure Default IIS web log location is moved (Automated)[IIS Logging Recommendations]
# ----------------------
Write-Host ""
Write-Host "5.1 (L1) Ensure Default IIS web log location is moved (Automated)" -ForegroundColor Cyan
$websites = Get-Website
$systemDrive = $env:SystemDrive  # Get the system drive (e.g., C:)

# Loop through each website and check the logFile directory
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the logFile directory for each site
        $logFileDirectory = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter "system.applicationHost/sites/siteDefaults/logFile" -name "directory"

        if ($logFileDirectory -ne $null) {
            $logDirectoryPath = $logFileDirectory.Value
            if ($logDirectoryPath.StartsWith($systemDrive)) {
                # Log directory is on the system drive (bad configuration)
                Write-Host "Website: $siteName - Log File Directory is on the system drive: $logDirectoryPath (Bad)" -ForegroundColor Red
            } else {
                # Log directory is on a different drive (good configuration)
                Write-Host "Website: $siteName - Log File Directory is on a different drive: $logDirectoryPath (Good)" -ForegroundColor Green
            }
        } else {
            Write-Host "Website: $siteName - Log File Directory is not configured" -ForegroundColor Yellow
        }

    } catch {
        Write-Host "Website: $siteName - Error retrieving log file directory" -ForegroundColor Red
    }
}
# ----------------------
# 5.2 (L1) Ensure Advanced IIS logging is enabled (Automated)[IIS Logging Recommendations]
# ----------------------
Write-Host ""
Write-Host "5.2 (L1) Ensure Advanced IIS logging is enabled (Automated)" -ForegroundColor Cyan
Write-Host "Manual audit required. Not automated." -ForegroundColor Red

# ----------------------
# 5.3 (L1) Ensure 'ETW Logging' is enabled (Manual)[IIS Logging Recommendations]
# ----------------------
Write-Host ""
Write-Host "5.3 (L1) Ensure 'ETW Logging' is enabled (Manual)" -ForegroundColor Cyan
Write-Host "Manual audit required. Not automated." -ForegroundColor Red
# ----------------------
# 6.1 (L1) Ensure FTP requests are encrypted (Manual)[FTP Requests]
# ----------------------
Write-Host ""
Write-Host "6.1 (L1) Ensure FTP requests are encrypted (Manual)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and check the SSL policies for control and data channels
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the controlChannelPolicy for the FTP server
        $controlChannelPolicy = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter "system.applicationHost/sites/siteDefaults/ftpServer/security/ssl" -name "controlChannelPolicy"

        # Get the dataChannelPolicy for the FTP server
        $dataChannelPolicy = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter "system.applicationHost/sites/siteDefaults/ftpServer/security/ssl" -name "dataChannelPolicy"

        # Check if both policies are set to SslRequire
        if ($controlChannelPolicy -eq "SslRequire" -and $dataChannelPolicy -eq "SslRequire") {
            Write-Host "Website: $siteName - Both control and data channel SSL policies are set to SslRequire (Good)" -ForegroundColor Green
        } else {
            Write-Host "Website: $siteName - SSL policies are NOT properly configured. ControlChannel: $($controlChannelPolicy), DataChannel: $($dataChannelPolicy)" -ForegroundColor Red
        }

    } catch {
        Write-Host "Website: $siteName - Error retrieving SSL policy configurations" -ForegroundColor Red
    }
}
# ----------------------
# 6.2 (L1) Ensure FTP Logon attempt restrictions is enabled (Manual)[FTP Requests]
# ----------------------
Write-Host ""
Write-Host "6.2 (L1) Ensure FTP Logon attempt restrictions is enabled (Manual)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and check if denyByFailure is enabled for the FTP server
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the denyByFailure setting for the FTP server's authentication
        $denyByFailure = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter "system.ftpServer/security/authentication/denyByFailure" -name "enabled"

        # Check if denyByFailure is enabled
        if ($denyByFailure -eq $true) {
            Write-Host "Website: $siteName - denyByFailure is ENABLED (Good)" -ForegroundColor Green
        } else {
            Write-Host "Website: $siteName - denyByFailure is DISABLED (Bad)" -ForegroundColor Red
        }

    } catch {
        Write-Host "Website: $siteName - Error retrieving denyByFailure configuration" -ForegroundColor Red
    }
}
# ----------------------
# 7.1 (L2) Ensure HSTS Header is set (Manual) [Transport Encryption]
# ----------------------
Write-Host ""
Write-Host "7.1 (L2) Ensure HSTS Header is set (Manual)" -ForegroundColor Cyan
$websites = Get-Website

# Loop through each website and check if the Strict-Transport-Security header is configured
foreach ($site in $websites) {
    $siteName = $site.Name
    try {
        # Get the HTTP response headers for the site
        $hstsHeader = Get-WebConfigurationProperty -pspath "IIS:\Sites\$siteName" -filter "system.webServer/httpProtocol/customHeaders" -name "Collection" |
            Where-Object { $_.name -ieq "Strict-Transport-Security" }  # Case-insensitive comparison with -ieq

        if ($hstsHeader) {
            Write-Host "Website: $siteName - HSTS is ENABLED. Header: $($hstsHeader.value)" -ForegroundColor Green
        } else {
            Write-Host "Website: $siteName - HSTS is NOT configured" -ForegroundColor Red
        }

    } catch {
        Write-Host "Website: $siteName - Error retrieving HSTS configuration" -ForegroundColor Red
    }
}
# ----------------------
# 7.2 (L1) Ensure SSLv2 is Disabled (Automated)[Transport Encryption]
# ----------------------
Write-Host ""
Write-Host "7.2 (L1) Ensure SSLv2 is Disabled (Automated)" -ForegroundColor Cyan
# Check SSL 2.0 Server Enabled
$serverEnabled = Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'Enabled' -ErrorAction SilentlyContinue
if ($serverEnabled.Enabled -eq 0) {
    Write-Host "SSL 2.0 Server - Enabled is set to 0 (Good)" -ForegroundColor Green
} else {
    Write-Host "SSL 2.0 Server - Enabled is NOT set to 0 (Bad)" -ForegroundColor Red
}

# Check SSL 2.0 Client Enabled
$clientEnabled = Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'Enabled' -ErrorAction SilentlyContinue
if ($clientEnabled.Enabled -eq 0) {
    Write-Host "SSL 2.0 Client - Enabled is set to 0 (Good)" -ForegroundColor Green
} else {
    Write-Host "SSL 2.0 Client - Enabled is NOT set to 0 (Bad)" -ForegroundColor Red
}

# Check SSL 2.0 Server DisabledByDefault
$serverDisabled = Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -name 'DisabledByDefault' -ErrorAction SilentlyContinue
if ($serverDisabled.DisabledByDefault -eq 1) {
    Write-Host "SSL 2.0 Server - DisabledByDefault is set to 1 (Good)" -ForegroundColor Green
} else {
    Write-Host "SSL 2.0 Server - DisabledByDefault is NOT set to 1 (Bad)" -ForegroundColor Red
}

# Check SSL 2.0 Client DisabledByDefault
$clientDisabled = Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -name 'DisabledByDefault' -ErrorAction SilentlyContinue
if ($clientDisabled.DisabledByDefault -eq 1) {
    Write-Host "SSL 2.0 Client - DisabledByDefault is set to 1 (Good)" -ForegroundColor Green
} else {
    Write-Host "SSL 2.0 Client - DisabledByDefault is NOT set to 1 (Bad)" -ForegroundColor Red
}

# ----------------------
# 7.3 (L1) Ensure SSLv3 is Disabled (Automated)[Transport Encryption]
# ----------------------
Write-Host ""
Write-Host "7.3 (L1) Ensure SSLv3 is Disabled (Automated)" -ForegroundColor Cyan
# Check SSL 3.0 Server Enabled
$ssl3ServerEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'Enabled' -ErrorAction SilentlyContinue
if ($ssl3ServerEnabled -and $ssl3ServerEnabled.Enabled -eq 0) {
    Write-Host "SSL 3.0 Server - Enabled is set to 0 (Good)" -ForegroundColor Green
} else {
    Write-Host "SSL 3.0 Server - Enabled is NOT set to 0 (Bad)" -ForegroundColor Red
}

# Check SSL 3.0 Client Enabled
$ssl3ClientEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'Enabled' -ErrorAction SilentlyContinue
if ($ssl3ClientEnabled -and $ssl3ClientEnabled.Enabled -eq 0) {
    Write-Host "SSL 3.0 Client - Enabled is set to 0 (Good)" -ForegroundColor Green
} else {
    Write-Host "SSL 3.0 Client - Enabled is NOT set to 0 (Bad)" -ForegroundColor Red
}

# Check SSL 3.0 Server DisabledByDefault
$ssl3ServerDisabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue
if ($ssl3ServerDisabled -and $ssl3ServerDisabled.DisabledByDefault -eq 1) {
    Write-Host "SSL 3.0 Server - DisabledByDefault is set to 1 (Good)" -ForegroundColor Green
} else {
    Write-Host "SSL 3.0 Server - DisabledByDefault is NOT set to 1 (Bad)" -ForegroundColor Red
}

# Check SSL 3.0 Client DisabledByDefault
$ssl3ClientDisabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue
if ($ssl3ClientDisabled -and $ssl3ClientDisabled.DisabledByDefault -eq 1) {
    Write-Host "SSL 3.0 Client - DisabledByDefault is set to 1 (Good)" -ForegroundColor Green
} else {
    Write-Host "SSL 3.0 Client - DisabledByDefault is NOT set to 1 (Bad)" -ForegroundColor Red
}

# ----------------------
# 7.4 (L1) Ensure TLS 1.0 is Disabled (Automated)[Transport Encryption]
# ----------------------
Write-Host ""
Write-Host "7.4 (L1) Ensure TLS 1.0 is Disabled (Automated)" -ForegroundColor Cyan
# Check TLS 1.0 Server Enabled
$tls10ServerEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -ErrorAction SilentlyContinue
if ($tls10ServerEnabled -and $tls10ServerEnabled.Enabled -eq 0) {
    Write-Host "TLS 1.0 Server - Enabled is set to 0 (Good)" -ForegroundColor Green
} else {
    Write-Host "TLS 1.0 Server - Enabled is NOT set to 0 (Bad)" -ForegroundColor Red
}

# Check TLS 1.0 Client Enabled
$tls10ClientEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'Enabled' -ErrorAction SilentlyContinue
if ($tls10ClientEnabled -and $tls10ClientEnabled.Enabled -eq 0) {
    Write-Host "TLS 1.0 Client - Enabled is set to 0 (Good)" -ForegroundColor Green
} else {
    Write-Host "TLS 1.0 Client - Enabled is NOT set to 0 (Bad)" -ForegroundColor Red
}

# Check TLS 1.0 Server DisabledByDefault
$tls10ServerDisabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue
if ($tls10ServerDisabled -and $tls10ServerDisabled.DisabledByDefault -eq 1) {
    Write-Host "TLS 1.0 Server - DisabledByDefault is set to 1 (Good)" -ForegroundColor Green
} else {
    Write-Host "TLS 1.0 Server - DisabledByDefault is NOT set to 1 (Bad)" -ForegroundColor Red
}

# Check TLS 1.0 Client DisabledByDefault
$tls10ClientDisabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue
if ($tls10ClientDisabled -and $tls10ClientDisabled.DisabledByDefault -eq 1) {
    Write-Host "TLS 1.0 Client - DisabledByDefault is set to 1 (Good)" -ForegroundColor Green
} else {
    Write-Host "TLS 1.0 Client - DisabledByDefault is NOT set to 1 (Bad)" -ForegroundColor Red
}

# ----------------------
# 7.5 (L1) Ensure TLS 1.1 is Disabled (Automated)[Transport Encryption]
# ----------------------
Write-Host ""
Write-Host "7.5 (L1) Ensure TLS 1.1 is Disabled (Automated)" -ForegroundColor Cyan
# Check TLS 1.1 Server Enabled
$tls11ServerEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -ErrorAction SilentlyContinue
if ($tls11ServerEnabled -and $tls11ServerEnabled.Enabled -eq 0) {
    Write-Host "TLS 1.1 Server - Enabled is set to 0 (Good)" -ForegroundColor Green
} else {
    Write-Host "TLS 1.1 Server - Enabled is NOT set to 0 (Bad)" -ForegroundColor Red
}

# Check TLS 1.1 Client Enabled
$tls11ClientEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -ErrorAction SilentlyContinue
if ($tls11ClientEnabled -and $tls11ClientEnabled.Enabled -eq 0) {
    Write-Host "TLS 1.1 Client - Enabled is set to 0 (Good)" -ForegroundColor Green
} else {
    Write-Host "TLS 1.1 Client - Enabled is NOT set to 0 (Bad)" -ForegroundColor Red
}

# Check TLS 1.1 Server DisabledByDefault
$tls11ServerDisabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue
if ($tls11ServerDisabled -and $tls11ServerDisabled.DisabledByDefault -eq 1) {
    Write-Host "TLS 1.1 Server - DisabledByDefault is set to 1 (Good)" -ForegroundColor Green
} else {
    Write-Host "TLS 1.1 Server - DisabledByDefault is NOT set to 1 (Bad)" -ForegroundColor Red
}

# Check TLS 1.1 Client DisabledByDefault
$tls11ClientDisabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue
if ($tls11ClientDisabled -and $tls11ClientDisabled.DisabledByDefault -eq 1) {
    Write-Host "TLS 1.1 Client - DisabledByDefault is set to 1 (Good)" -ForegroundColor Green
} else {
    Write-Host "TLS 1.1 Client - DisabledByDefault is NOT set to 1 (Bad)" -ForegroundColor Red
}

# ----------------------
# 7.6 (L1) Ensure TLS 1.2 is Enabled (Automated) [Transport Encryption]
# ----------------------
Write-Host ""
Write-Host "7.6 (L1) Ensure TLS 1.2 is Enabled (Automated)" -ForegroundColor Cyan
# Check TLS 1.2 Server Enabled
$tls12ServerEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -ErrorAction SilentlyContinue
if ($tls12ServerEnabled -and $tls12ServerEnabled.Enabled -eq 1) {
    Write-Host "TLS 1.2 Server - Enabled is set to 1 (Good)" -ForegroundColor Green
} else {
    Write-Host "TLS 1.2 Server - Enabled is NOT set to 1 (Bad)" -ForegroundColor Red
}

# Check TLS 1.2 Server DisabledByDefault
$tls12ServerDisabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -ErrorAction SilentlyContinue
if ($tls12ServerDisabled -and $tls12ServerDisabled.DisabledByDefault -eq 0) {
    Write-Host "TLS 1.2 Server - DisabledByDefault is set to 0 (Good)" -ForegroundColor Green
} else {
    Write-Host "TLS 1.2 Server - DisabledByDefault is NOT set to 0 (Bad)" -ForegroundColor Red
}

# ----------------------
# 7.7 (L1) Ensure NULL Cipher Suites is Disabled (Automated) [Transport Encryption]
# ----------------------
Write-Host ""
Write-Host "7.7 (L1) Ensure NULL Cipher Suites is Disabled (Automated)" -ForegroundColor Cyan
$nullCipherEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL' -Name 'Enabled' -ErrorAction SilentlyContinue
if ($nullCipherEnabled -and $nullCipherEnabled.Enabled -eq 0) {
    Write-Host "NULL Cipher Suite - Enabled is set to 0 (Good)" -ForegroundColor Green
} else {
    Write-Host "NULL Cipher Suite - Enabled is NOT set to 0 (Bad)" -ForegroundColor Red
}

# ----------------------
# 7.8 (L1) Ensure DES Cipher Suites is Disabled (Automated) [Transport Encryption]
# ----------------------
Write-Host ""
Write-Host "7.8 (L1) Ensure DES Cipher Suites is Disabled (Automated)" -ForegroundColor Cyan
$desCipherEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56' -Name 'Enabled' -ErrorAction SilentlyContinue
if ($desCipherEnabled -and $desCipherEnabled.Enabled -eq 0) {
    Write-Host "DES Cipher Suite - Enabled is set to 0 (Good)" -ForegroundColor Green
} else {
    Write-Host "DES Cipher Suite - Enabled is NOT set to 0 (Bad)" -ForegroundColor Red
}

# ----------------------
# 7.9 (L1) Ensure RC4 Cipher Suites is Disabled (Automated) [Transport Encryption]
# ----------------------
Write-Host ""
Write-Host "7.9 (L1) Ensure RC4 Cipher Suites is Disabled (Automated)" -ForegroundColor Cyan
$rc4CipherPaths = @(
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128',
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128',
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128',
    'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128'
)

foreach ($rc4CipherPath in $rc4CipherPaths) {
    $rc4Enabled = Get-ItemProperty -Path $rc4CipherPath -Name 'Enabled' -ErrorAction SilentlyContinue
    if ($rc4Enabled -and $rc4Enabled.Enabled -eq 0) {
        Write-Host "$rc4CipherPath - Enabled is set to 0 (Good)" -ForegroundColor Green
    } else {
        Write-Host "$rc4CipherPath - Enabled is NOT set to 0 (Bad)" -ForegroundColor Red
    }
}

# ----------------------
# 7.10 (L1) Ensure AES 128/128 Cipher Suite is Disabled (Automated) [Transport Encryption]
# ----------------------
Write-Host ""
Write-Host "7.10 (L1) Ensure AES 128/128 Cipher Suite is Disabled (Automated)" -ForegroundColor Cyan
$aes128CipherEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128' -Name 'Enabled' -ErrorAction SilentlyContinue
if ($aes128CipherEnabled -and $aes128CipherEnabled.Enabled -eq 0) {
    Write-Host "AES 128/128 Cipher Suite - Enabled is set to 0 (Good)" -ForegroundColor Green
} else {
    Write-Host "AES 128/128 Cipher Suite - Enabled is NOT set to 0 (Bad)" -ForegroundColor Red
}

# ----------------------
# 7.11 (L1) Ensure AES 256/256 Cipher Suite is Enabled (Automated) [Transport Encryption]
# ----------------------
Write-Host ""
Write-Host "7.11 (L1) Ensure AES 256/256 Cipher Suite is Enabled (Automated)" -ForegroundColor Cyan
$aes256CipherEnabled = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256' -Name 'Enabled' -ErrorAction SilentlyContinue
if ($aes256CipherEnabled -and $aes256CipherEnabled.Enabled -eq 1) {
    Write-Host "AES 256/256 Cipher Suite - Enabled is set to 1 (Good)" -ForegroundColor Green
} else {
    Write-Host "AES 256/256 Cipher Suite - Enabled is NOT set to 1 (Bad)" -ForegroundColor Red
}

# ----------------------
# 7.12 (L2) Ensure TLS Cipher Suite ordering is Configured (Automated) [Transport Encryption]
# ----------------------
Write-Host ""
Write-Host "7.12 (L2) Ensure TLS Cipher Suite ordering is Configured (Automated)" -ForegroundColor Cyan
# Note: Check if TLS cipher suite ordering is configured by checking the appropriate registry key.
$tlsCipherSuiteOrder = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols' -Name 'CipherSuiteOrder' -ErrorAction SilentlyContinue
if ($tlsCipherSuiteOrder) {
    Write-Host "TLS Cipher Suite Ordering is configured (Good)" -ForegroundColor Green
} else {
    Write-Host "TLS Cipher Suite Ordering is NOT configured (Bad)" -ForegroundColor Red
}
