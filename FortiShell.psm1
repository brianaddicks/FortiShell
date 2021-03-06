###############################################################################
## Start Powershell Cmdlets
###############################################################################

###############################################################################
# Get-FgAddress

function Get-FgAddress {
    [CmdletBinding()]
	<#
        .SYNOPSIS
            Gets Vlan Info from Hp Switch Configuration
	#>

	Param (
		[Parameter(Mandatory=$True,Position=0)]
		[array]$ShowSupportOutput
	)
	
	$VerbosePrefix = "Get-FgAddress: "
	
	$IpRx = [regex] "(\d+\.){3}\d+"
	
	$TotalLines = $ShowSupportOutput.Count
	$i          = 0 
	$StopWatch  = [System.Diagnostics.Stopwatch]::StartNew() # used by Write-Progress so it doesn't slow the whole function down
	
	$ReturnObject = @()
	
	:fileloop foreach ($line in $ShowSupportOutput) {
		$i++
		
		# Write progress bar, we're only updating every 1000ms, if we do it every line it takes forever
		
		if ($StopWatch.Elapsed.TotalMilliseconds -ge 1000) {
			$PercentComplete = [math]::truncate($i / $TotalLines * 100)
	        Write-Progress -Activity "Reading Support Output" -Status "$PercentComplete% $i/$TotalLines" -PercentComplete $PercentComplete
	        $StopWatch.Reset()
			$StopWatch.Start()
		}
		
		if ($line -eq "") { continue }
		
		###########################################################################################
		# Section Start
		
		$Regex = [regex] "^config\ firewall\ address"
		$Match = HelperEvalRegex $Regex $line
		if ($Match) {
			$Section = $true
			Write-Verbose "Section started"
			continue
		}
		
		if ($Section) {
			#Write-Verbose $line
			###########################################################################################
			# End of Section
			$Regex = [regex] '^end$'
			$Match = HelperEvalRegex $Regex $line
			if ($Match) {
				$NewObject = $null
				break
			}
			
			###########################################################################################
			# Bool Properties and Properties that need special processing
			# Eval Parameters for this section
			$EvalParams              = @{}
			$EvalParams.StringToEval = $line
			
			
			# New Address Object
			$EvalParams.Regex          = [regex] '^\s+edit\ "(.+?)"'
			$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
			if ($Eval) {
				$NewObject       = New-Object FortiShell.Address
				$NewObject.Name  = $Eval
				$ReturnObject   += $NewObject
				Write-Verbose "object created: $($NewObject.Name)"
			}
			if ($NewObject) {
				# Subnet
				$EvalParams.Regex          = [regex] "^\s+set\ subnet\ (?<ip>$IpRx)\ (?<mask>$IpRx)"
				$Eval                      = HelperEvalRegex @EvalParams
				if ($Eval) {
					$NewObject.Value = $Eval.Groups['ip'].Value
					$NewObject.Value += '/' + (ConvertTo-MaskLength $Eval.Groups['mask'].Value)
				}
				
				###########################################################################################
				# Regular Properties
				
				# Update eval Parameters for remaining matches
				$EvalParams.VariableToUpdate = ([REF]$NewObject)
				$EvalParams.ReturnGroupNum   = 1
				$EvalParams.LoopName         = 'fileloop'
				
				###############################################
				# General Properties
				
				# Interface
				$EvalParams.ObjectProperty = "Interface"
				$EvalParams.Regex          = [regex] '^\s+set\ associated-interface\ "(.+?)"'
				$Eval                      = HelperEvalRegex @EvalParams
			}
		} else {
			continue
		}
	}	
	return $ReturnObject
}

###############################################################################
# Get-FgAddressGroup

function Get-FgAddressGroup {
    [CmdletBinding()]
	<#
        .SYNOPSIS
            Gets Vlan Info from Hp Switch Configuration
	#>

	Param (
		[Parameter(Mandatory=$True,Position=0)]
		[array]$ShowSupportOutput
	)
	
	$VerbosePrefix = "Get-FgAddressGroup: "
	
	$IpRx = [regex] "(\d+\.){3}\d+"
	
	$TotalLines = $ShowSupportOutput.Count
	$i          = 0 
	$StopWatch  = [System.Diagnostics.Stopwatch]::StartNew() # used by Write-Progress so it doesn't slow the whole function down
	
	$ReturnObject = @()
	
	:fileloop foreach ($line in $ShowSupportOutput) {
		$i++
		
		# Write progress bar, we're only updating every 1000ms, if we do it every line it takes forever
		
		if ($StopWatch.Elapsed.TotalMilliseconds -ge 1000) {
			$PercentComplete = [math]::truncate($i / $TotalLines * 100)
	        Write-Progress -Activity "Reading Support Output" -Status "$PercentComplete% $i/$TotalLines" -PercentComplete $PercentComplete
	        $StopWatch.Reset()
			$StopWatch.Start()
		}
		
		if ($line -eq "") { continue }
		
		###########################################################################################
		# Section Start
		
		$Regex = [regex] "^config\ firewall\ addrgrp"
		$Match = HelperEvalRegex $Regex $line
		if ($Match) {
			$Section = $true
			Write-Verbose "Section started"
			continue
		}
		
		if ($Section) {
			#Write-Verbose $line
			###########################################################################################
			# End of Section
			$Regex = [regex] '^end$'
			$Match = HelperEvalRegex $Regex $line
			if ($Match) {
				$NewObject = $null
				break
			}
			
			###########################################################################################
			# Bool Properties and Properties that need special processing
			# Eval Parameters for this section
			$EvalParams              = @{}
			$EvalParams.StringToEval = $line
			
			
			# New Address Object
			$EvalParams.Regex          = [regex] '^\s+edit\ "(.+?)"'
			$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
			if ($Eval) {
				$NewObject       = New-Object FortiShell.AddressGroup
				$NewObject.Name  = $Eval
				$ReturnObject   += $NewObject
				Write-Verbose "object created: $($NewObject.Name)"
			}
			if ($NewObject) {
				
				###########################################################################################
				# Regular Properties
				
				# Update eval Parameters for remaining matches
				$EvalParams.VariableToUpdate = ([REF]$NewObject)
				$EvalParams.ReturnGroupNum   = 1
				$EvalParams.LoopName         = 'fileloop'
				
				###############################################
				# General Properties
				
				# Uuid
				$EvalParams.ObjectProperty = "Uuid"
				$EvalParams.Regex          = [regex] '^\s+set\ uuid\ (.+)'
				$Eval                      = HelperEvalRegex @EvalParams
				
				# Value	
				$EvalParams.Regex          = [regex] '^\s+set\ member\ "(.+)"'
				$EvalParams.ObjectProperty = "Value"
				$Eval                      = HelperEvalRegex @EvalParams
				$NewObject."$($EvalParams.ObjectProperty)" = $NewObject."$($EvalParams.ObjectProperty)" -split '" "'
					
				# Comment
				$EvalParams.Regex          = [regex] '^\s+set\ comment\ "(.+)"'
				$EvalParams.ObjectProperty = "Comment"
				$Eval                      = HelperEvalRegex @EvalParams
			}
		} else {
			continue
		}
	}	
	return $ReturnObject
}

###############################################################################
# Get-FgPolicy

function Get-FgPolicy {
    [CmdletBinding()]
	<#
        .SYNOPSIS
            Gets Vlan Info from Hp Switch Configuration
	#>

	Param (
		[Parameter(Mandatory=$True,Position=0)]
		[array]$ShowSupportOutput
	)
	
	$VerbosePrefix = "Get-FgPolicy: "
	
	$TotalLines = $ShowSupportOutput.Count
	$i          = 0 
	$StopWatch  = [System.Diagnostics.Stopwatch]::StartNew() # used by Write-Progress so it doesn't slow the whole function down
	
	$ReturnObject     = @()
	$RuleCount        = 0
	$Global:Unmatched = @()
	
	:fileloop foreach ($line in $ShowSupportOutput) {
		$i++
		
		# Write progress bar, we're only updating every 1000ms, if we do it every line it takes forever
		
		if ($StopWatch.Elapsed.TotalMilliseconds -ge 1000) {
			$PercentComplete = [math]::truncate($i / $TotalLines * 100)
	        Write-Progress -Activity "Reading Support Output" -Status "$PercentComplete% $i/$TotalLines" -PercentComplete $PercentComplete
	        $StopWatch.Reset()
			$StopWatch.Start()
		}
		
		if ($line -eq "") { continue }
		
		###########################################################################################
		# Section Start
		
		$Regex = [regex] "^config\ firewall\ policy"
		$Match = HelperEvalRegex $Regex $line
		if ($Match) {
			$Section = $true
			Write-Verbose "Section started"
			continue
		}
		
		if ($Section) {
			#Write-Verbose $line
			###########################################################################################
			# End of Section
			$Regex = [regex] '^end$'
			$Match = HelperEvalRegex $Regex $line
			if ($Match) {
				$NewObject = $null
				break
			}
			
			###########################################################################################
			# Bool Properties and Properties that need special processing
			# Eval Parameters for this section
			$EvalParams              = @{}
			$EvalParams.StringToEval = $line
			$EvalParams.LoopName     = 'fileloop'
			
			
			# New Address Object
			$EvalParams.Regex          = [regex] '^\s+edit\ (\d+)'
			$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
			if ($Eval) {
				$RuleCount++
				$NewObject        = New-Object FortiShell.Policy
				$NewObject.Edit   = $Eval
				$NewObject.Number = $RuleCount
				$ReturnObject    += $NewObject
				Write-Verbose "object created: $($NewObject.Number)"
				continue
			}
			if ($NewObject) {
				
				###########################################################################################
				# Special Properties
				
				# Inbound
				$EvalParams.Regex          = [regex] "^\s+set\ inbound\ (.+)"
				$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
				if ($Eval -eq "enable") {
					$NewObject.Inbound = $true
					continue
				}
				
				# Outbound
				$EvalParams.Regex          = [regex] "^\s+set\ outbound\ (.+)"
				$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
				if ($Eval -eq "enable") {
					$NewObject.Outbound = $true
					continue
				}
				
				# Disabled
				$EvalParams.Regex          = [regex] "^\s+set\ status\ (.+)"
				$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
				if ($Eval -eq "disable") {
					$NewObject.Disabled = $true
					continue
				}
				
				# ProfileStatus
				$EvalParams.Regex          = [regex] "^\s+set\ profile-status\ (.+)"
				$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
				if ($Eval -eq "enable") {
					$NewObject.ProfileStatus = $true
					continue
				}
				
				# LogTraffic
				$EvalParams.Regex          = [regex] "^\s+set\ logtraffic\ (.+)"
				$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
				if (($Eval -eq "enable") -or ($Eval -eq "all")) {
					$NewObject.LogTraffic = $true
					continue
				}
				
				# Nat
				$EvalParams.Regex          = [regex] "^\s+set\ nat\ (.+)"
				$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
				if ($Eval -eq "enable") {
					$NewObject.NatEnabled = $true
					continue
				}
				
				# NatInbound
				$EvalParams.Regex          = [regex] "^\s+set\ natinbound\ (.+)"
				$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
				if ($Eval -eq "enable") {
					$NewObject.NatInbound = $true
					continue
				}
				
				# ProfileStatus
				$EvalParams.Regex          = [regex] "^\s+set\ profile_status\ (.+)"
				$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
				if ($Eval -eq "enable") {
					$NewObject.ProfileStatus = $true
					continue
				}
				
				# ProfileStatus
				$EvalParams.Regex          = [regex] "^\s+set\ utm-status\ (.+)"
				$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
				if ($Eval -eq "enable") {
					$NewObject.UtmStatus = $true
					continue
				}
				
				# Comments
				$EvalParams.Regex          = [regex] '^\s+set\ comments\ "([^"]+)$'
				$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
				if ($Eval) {
					$MultilineComment = $Eval + "`r`n"
					continue
				}
				
				if ($MultilineComment) {
					if ($line -match '"') {
						$EvalParams.Regex   = [regex] '^([^"]+)"'
						$Eval               = HelperEvalRegex @EvalParams -ReturnGroupNum 1
						$MultilineComment  += $Eval + "`r`n"
						$NewObject.Comments = $MultilineComment
						$MultilineComment   = $null
						continue
					} else {
						$MultilineComment += $line + "`r`n"
						continue
					}
				}
				
				###########################################################################################
				# Regular Properties
				
				# Update eval Parameters for remaining matches
				$EvalParams.VariableToUpdate = ([REF]$NewObject)
				$EvalParams.ReturnGroupNum   = 1
				$EvalParams.LoopName         = 'fileloop'
				
				# SourceInterface	
				$EvalParams.Regex          = [regex] '^\s+set\ srcintf\ "(.+)"'
				$EvalParams.ObjectProperty = "SourceInterface"
				$Eval                      = HelperEvalRegex @EvalParams
				$NewObject."$($EvalParams.ObjectProperty)" = $NewObject."$($EvalParams.ObjectProperty)" -split '" "'
				
				# DestinationInterface	
				$EvalParams.Regex          = [regex] '^\s+set\ dstintf\ "(.+)"'
				$EvalParams.ObjectProperty = "DestinationInterface"
				$Eval                      = HelperEvalRegex @EvalParams
				$NewObject."$($EvalParams.ObjectProperty)" = $NewObject."$($EvalParams.ObjectProperty)" -split '" "'
				
				# SourceAddress	
				$EvalParams.Regex          = [regex] '^\s+set\ srcaddr\ "(.+)"'
				$EvalParams.ObjectProperty = "SourceAddress"
				$Eval                      = HelperEvalRegex @EvalParams
				$NewObject."$($EvalParams.ObjectProperty)" = $NewObject."$($EvalParams.ObjectProperty)" -split '" "'
				
				# DestinationAddress
				$EvalParams.Regex          = [regex] '^\s+set\ dstaddr\ "(.+)"'
				$EvalParams.ObjectProperty = "DestinationAddress"
				$Eval                      = HelperEvalRegex @EvalParams
				$NewObject."$($EvalParams.ObjectProperty)" = $NewObject."$($EvalParams.ObjectProperty)" -split '" "'
				
				# Action	
				$EvalParams.Regex          = [regex] '^\s+set\ action\ (.+)'
				$EvalParams.ObjectProperty = "Action"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# Schedule
				$EvalParams.Regex          = [regex] '^\s+set\ schedule\ "(.+?)"'
				$EvalParams.ObjectProperty = "Schedule"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# Service
				$EvalParams.Regex          = [regex] '^\s+set\ service\ "(.+)"'
				$EvalParams.ObjectProperty = "Service"
				$Eval                      = HelperEvalRegex @EvalParams
				$NewObject.Service         = $NewObject.Service -split '" "'
				
				# VpnTunnel
				$EvalParams.Regex          = [regex] '^\s+set\ vpntunnel\ "(.+?)"'
				$EvalParams.ObjectProperty = "VpnTunnel"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# Profile
				$EvalParams.Regex          = [regex] '^\s+set\ profile\ "(.+?)"'
				$EvalParams.ObjectProperty = "Profile"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# Uuid
				$EvalParams.Regex          = [regex] '^\s+set\ uuid\ (.+)'
				$EvalParams.ObjectProperty = "Uuid"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# TrafficShaper
				$EvalParams.Regex          = [regex] '^\s+set\ traffic-shaper\ "(.+?)"'
				$EvalParams.ObjectProperty = "TrafficShaper"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# TrafficShaperReverse
				$EvalParams.Regex          = [regex] '^\s+set\ traffic-shaper-reverse\ "(.+?)"'
				$EvalParams.ObjectProperty = "TrafficShaperReverse"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# Comments
				$EvalParams.Regex          = [regex] '^\s+set\ comments\ "(.+?)"'
				$EvalParams.ObjectProperty = "Comments"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# WebFilterProfile
				$EvalParams.Regex          = [regex] '^\s+set\ webfilter-profile\ "(.+?)"'
				$EvalParams.ObjectProperty = "WebFilterProfile"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# VoipProfile
				$EvalParams.Regex          = [regex] '^\s+set\ voip-profile\ "(.+?)"'
				$EvalParams.ObjectProperty = "VoipProfile"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# SslSshProfile
				$EvalParams.Regex          = [regex] '^\s+set\ ssl-ssh-profile\ "(.+?)"'
				$EvalParams.ObjectProperty = "SslSshProfile"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# SpamFilterProfile
				$EvalParams.Regex          = [regex] '^\s+set\ spamfilter-profile\ "(.+?)"'
				$EvalParams.ObjectProperty = "SpamFilterProfile"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# IpsSensor
				$EvalParams.Regex          = [regex] '^\s+set\ ips-sensor\ "(.+?)"'
				$EvalParams.ObjectProperty = "IpsSensor"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# ProfileProtocolOptions
				$EvalParams.Regex          = [regex] '^\s+set\ profile-protocol-options\ "(.+?)"'
				$EvalParams.ObjectProperty = "ProfileProtocolOptions"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# ApplicationList
				$EvalParams.Regex          = [regex] '^\s+set\ application-list\ "(.+?)"'
				$EvalParams.ObjectProperty = "ApplicationList"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# AvProfile
				$EvalParams.Regex          = [regex] '^\s+set\ av-profile\ "(.+?)"'
				$EvalParams.ObjectProperty = "AvProfile"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# DlpSensor
				$EvalParams.Regex          = [regex] '^\s+set\ dlp-sensor\ "(.+?)"'
				$EvalParams.ObjectProperty = "DlpSensor"
				$Eval                      = HelperEvalRegex @EvalParams
			}
			
			if ($line -match "^\s+next") {
				continue
			} else {
				$Global:Unmatched += $line
			}
		} else {
			continue
		}
	}	
	return $ReturnObject
}

###############################################################################
# Get-FgService

function Get-FgService {
    [CmdletBinding()]
	<#
        .SYNOPSIS
            Gets Vlan Info from Hp Switch Configuration
	#>

	Param (
		[Parameter(Mandatory=$True,Position=0)]
		[array]$ShowSupportOutput
	)
	
	$VerbosePrefix = "Get-FgService: "
	
	$TotalLines = $ShowSupportOutput.Count
	$i          = 0 
	$StopWatch  = [System.Diagnostics.Stopwatch]::StartNew() # used by Write-Progress so it doesn't slow the whole function down
	
	$ReturnObject = @()
	
	:fileloop foreach ($line in $ShowSupportOutput) {
		$i++
		
		# Write progress bar, we're only updating every 1000ms, if we do it every line it takes forever
		
		if ($StopWatch.Elapsed.TotalMilliseconds -ge 1000) {
			$PercentComplete = [math]::truncate($i / $TotalLines * 100)
	        Write-Progress -Activity "Reading Support Output" -Status "$PercentComplete% $i/$TotalLines" -PercentComplete $PercentComplete
	        $StopWatch.Reset()
			$StopWatch.Start()
		}
		
		if ($line -eq "") { continue }
		
		###########################################################################################
		# Section Start
		
		$Regex = [regex] "^config\ firewall\ service\ custom"
		$Match = HelperEvalRegex $Regex $line
		if ($Match) {
			$Section = $true
			Write-Verbose "Section started"
		}
		
		if ($Section) {
			#Write-Verbose $line
			###########################################################################################
			# End of Section
			$Regex = [regex] '^end$'
			$Match = HelperEvalRegex $Regex $line
			if ($Match) {
				$NewObject = $null
				break
			}
			
			###########################################################################################
			# Bool Properties and Properties that need special processing
			# Eval Parameters for this section
			$EvalParams              = @{}
			$EvalParams.StringToEval = $line
			
			
			# New Address Object
			$EvalParams.Regex          = [regex] '^\s+edit\ "(.+?)"'
			$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
			if ($Eval) {
				$NewObject       = New-Object FortiShell.Service
				$NewObject.Name  = $Eval
				$ReturnObject   += $NewObject
				Write-Verbose "object created: $($NewObject.Name)"
			}
			if ($NewObject) {
				
				###########################################################################################
				# Special Properties
				
				# Tcp Port Range
				$EvalParams.Regex          = [regex] "^\s+set\ (?<protocol>udp|tcp)-portrange\ (?<port>.+)"
				$Eval                      = HelperEvalRegex @EvalParams
				if ($Eval) {
					$Protocol = $Eval.Groups["protocol"].Value
					Write-Verbose $Protocol
					$List  = @()
					$Split = ($Eval.Groups["port"].Value).Trim().Split()
					Write-Verbose "port: $($Eval.Groups["port"].Value.Split())"
					foreach ($s in $Split) {
						Write-Verbose "s $s"
						$Range = ($s.split(":"))[0]
						Write-Verbose "Range $Range"
						$DashSplit = $Range.Split('-')
						if ($DashSplit[0] -eq $DashSplit[1]) {
							$Range = $DashSplit[0]
						}
						$NewObject.Value += "$Protocol/$Range"
					}
				}
				
				$EvalParams.Regex          = [regex] "^\s+set\ protocol\ (.+)"
				$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
				if ($Eval) {
					$ParentProtocol = $Eval
				}
				
				if ($ParentProtocol) {
					$EvalParams.Regex          = [regex] "^\s+set\ dstport\ (.+)"
					$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
					if ($Eval) {
						$Port = $Eval
						$Split = $Port.Split('-')
						if ($Split[0] -eq $Split[1]) {
							$Port = $Split[0]
						}
						$PortString = $ParentProtocol.ToLower()
						$PortString += '/' + $Port
						$NewObject.Value += $PortString
					}
				}
				
				###########################################################################################
				# Regular Properties
				
				# Update eval Parameters for remaining matches
				$EvalParams.VariableToUpdate = ([REF]$NewObject)
				$EvalParams.ReturnGroupNum   = 1
				$EvalParams.LoopName         = 'fileloop'
					
				# Category
				$EvalParams.ObjectProperty = "Category"
				$EvalParams.Regex          = [regex] '^\s+set\ category\ "(.+?)"'
				$Eval                      = HelperEvalRegex @EvalParams
				
				# Comment
				$EvalParams.ObjectProperty = "Comment"
				$EvalParams.Regex          = [regex] '^\s+set\ comment\ "(.+?)"'
				$Eval                      = HelperEvalRegex @EvalParams
			}
		} else {
			continue
		}
	}	
	return $ReturnObject
}

###############################################################################
# Get-FgServiceGroup

function Get-FgServiceGroup {
    [CmdletBinding()]
	<#
        .SYNOPSIS
            Gets Vlan Info from Hp Switch Configuration
	#>

	Param (
		[Parameter(Mandatory=$True,Position=0)]
		[array]$ShowSupportOutput
	)
	
	$VerbosePrefix = "Get-FgServiceGroup: "
	
	$TotalLines = $ShowSupportOutput.Count
	$i          = 0 
	$StopWatch  = [System.Diagnostics.Stopwatch]::StartNew() # used by Write-Progress so it doesn't slow the whole function down
	
	$ReturnObject = @()
	
	:fileloop foreach ($line in $ShowSupportOutput) {
		$i++
		
		# Write progress bar, we're only updating every 1000ms, if we do it every line it takes forever
		
		if ($StopWatch.Elapsed.TotalMilliseconds -ge 1000) {
			$PercentComplete = [math]::truncate($i / $TotalLines * 100)
	        Write-Progress -Activity "Reading Support Output" -Status "$PercentComplete% $i/$TotalLines" -PercentComplete $PercentComplete
	        $StopWatch.Reset()
			$StopWatch.Start()
		}
		
		if ($line -eq "") { continue }
		
		###########################################################################################
		# Section Start
		
		$Regex = [regex] "^config\ firewall\ service\ group"
		$Match = HelperEvalRegex $Regex $line
		if ($Match) {
			$Section = $true
			Write-Verbose "Section started"
		}
		
		if ($Section) {
			#Write-Verbose $line
			###########################################################################################
			# End of Section
			$Regex = [regex] '^end$'
			$Match = HelperEvalRegex $Regex $line
			if ($Match) {
				$NewObject = $null
				break
			}
			
			###########################################################################################
			# Bool Properties and Properties that need special processing
			# Eval Parameters for this section
			$EvalParams              = @{}
			$EvalParams.StringToEval = $line
			
			
			# New Address Object
			$EvalParams.Regex          = [regex] '^\s+edit\ "(.+?)"'
			$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
			if ($Eval) {
				$NewObject       = New-Object FortiShell.ServiceGroup
				$NewObject.Name  = $Eval
				$ReturnObject   += $NewObject
				Write-Verbose "object created: $($NewObject.Name)"
			}
			if ($NewObject) {
				
				###########################################################################################
				# Special Properties
				
				# Members
				$EvalParams.Regex          = [regex] "^\s+set\ member\ (.+)"
				$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
				if ($Eval) {
					$Split = $Eval.Split()
					foreach ($s in $Split) {
						$NewObject.Value += $s -replace '"',''
					}
				}
				
				###########################################################################################
				# Regular Properties
				
				# Update eval Parameters for remaining matches
				$EvalParams.VariableToUpdate = ([REF]$NewObject)
				$EvalParams.ReturnGroupNum   = 1
				$EvalParams.LoopName         = 'fileloop'
			}
		} else {
			continue
		}
	}	
	return $ReturnObject
}

###############################################################################
# Get-FgStaticRoute

function Get-FgStaticRoute {
    [CmdletBinding()]
	<#
        .SYNOPSIS
            Gets Vlan Info from Hp Switch Configuration
	#>

	Param (
		[Parameter(Mandatory=$True,Position=0)]
		[array]$ShowSupportOutput
	)
	
	$IpRx = [regex] "(\d+\.){3}\d+"
	$VerbosePrefix = "Get-FgStaticRoute: "
	
	$TotalLines = $ShowSupportOutput.Count
	$i          = 0 
	$StopWatch  = [System.Diagnostics.Stopwatch]::StartNew() # used by Write-Progress so it doesn't slow the whole function down
	
	$ReturnObject = @()
	
	:fileloop foreach ($line in $ShowSupportOutput) {
		$i++
		
		# Write progress bar, we're only updating every 1000ms, if we do it every line it takes forever
		
		if ($StopWatch.Elapsed.TotalMilliseconds -ge 1000) {
			$PercentComplete = [math]::truncate($i / $TotalLines * 100)
	        Write-Progress -Activity "Reading Support Output" -Status "$PercentComplete% $i/$TotalLines" -PercentComplete $PercentComplete
	        $StopWatch.Reset()
			$StopWatch.Start()
		}
		
		if ($line -eq "") { continue }
		
		###########################################################################################
		# Section Start
		
		$Regex = [regex] "^config\ router\ static"
		$Match = HelperEvalRegex $Regex $line
		if ($Match) {
			$Section = $true
			Write-Verbose "Section started"
		}
		
		if ($Section) {
			#Write-Verbose $line
			###########################################################################################
			# End of Section
			$Regex = [regex] '^end$'
			$Match = HelperEvalRegex $Regex $line
			if ($Match) {
				$NewObject = $null
				break
			}
			
			###########################################################################################
			# Bool Properties and Properties that need special processing
			# Eval Parameters for this section
			$EvalParams              = @{}
			$EvalParams.StringToEval = $line
			
			
			# New Address Object
			$EvalParams.Regex          = [regex] '^\s+edit\ (.+?)'
			$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
			if ($Eval) {
				$NewObject         = New-Object FortiShell.Route
				$NewObject.Number  = $Eval
				$NewObject.Type    = "static"
				$ReturnObject     += $NewObject
				Write-Verbose "object created: $($NewObject.Number)"
			}
			if ($NewObject) {
				
				###########################################################################################
				# Special Properties
				
				# Tcp Port Range
				$EvalParams.Regex          = [regex] "^\s+set\ dst\ (?<network>$IpRx)\ (?<mask>$IpRx)"
				$Eval                      = HelperEvalRegex @EvalParams
				if ($Eval) {
					$NewObject.Destination  = $Eval.Groups['network'].Value
					$NewObject.Destination += '/'
					$NewObject.Destination += (ConvertTo-MaskLength $Eval.Groups['mask'].Value)
				}
				
				###########################################################################################
				# Regular Properties
				
				# Update eval Parameters for remaining matches
				$EvalParams.VariableToUpdate = ([REF]$NewObject)
				$EvalParams.ReturnGroupNum   = 1
				$EvalParams.LoopName         = 'fileloop'
					
				# SourceInterface
				$EvalParams.Regex          = [regex] '^\s+set\ device\ "(.+?)"'
				$EvalParams.ObjectProperty = "Interface"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# NextHop
				$EvalParams.Regex          = [regex] '^\s+set\ gateway\ (.+)'
				$EvalParams.ObjectProperty = "NextHop"
				$Eval                      = HelperEvalRegex @EvalParams
			}
		} else {
			continue
		}
	}	
	return $ReturnObject
}

###############################################################################
# Get-FgVip

function Get-FgVip {
    [CmdletBinding()]
	<#
        .SYNOPSIS
            Gets Vlan Info from Hp Switch Configuration
	#>

	Param (
		[Parameter(Mandatory=$True,Position=0)]
		[array]$ShowSupportOutput
	)
	
	$VerbosePrefix = "Get-FgVip: "
	
	$IpRx = [regex] "(\d+\.){3}\d+"
	
	$TotalLines = $ShowSupportOutput.Count
	$i          = 0 
	$StopWatch  = [System.Diagnostics.Stopwatch]::StartNew() # used by Write-Progress so it doesn't slow the whole function down
	
	$ReturnObject = @()
	
	:fileloop foreach ($line in $ShowSupportOutput) {
		$i++
		
		# Write progress bar, we're only updating every 1000ms, if we do it every line it takes forever
		
		if ($StopWatch.Elapsed.TotalMilliseconds -ge 1000) {
			$PercentComplete = [math]::truncate($i / $TotalLines * 100)
	        Write-Progress -Activity "Reading Support Output" -Status "$PercentComplete% $i/$TotalLines" -PercentComplete $PercentComplete
	        $StopWatch.Reset()
			$StopWatch.Start()
		}
		
		if ($line -eq "") { continue }
		
		###########################################################################################
		# Section Start
		
		$Regex = [regex] "^config\ firewall\ vip"
		$Match = HelperEvalRegex $Regex $line
		if ($Match) {
			$Section = $true
			Write-Verbose "Section started"
			continue
		}
		
		if ($Section) {
			#Write-Verbose $line
			###########################################################################################
			# End of Section
			$Regex = [regex] '^end$'
			$Match = HelperEvalRegex $Regex $line
			if ($Match) {
				$NewObject = $null
				break
			}
			
			###########################################################################################
			# Bool Properties and Properties that need special processing
			# Eval Parameters for this section
			$EvalParams              = @{}
			$EvalParams.StringToEval = $line
			$EvalParams.LoopName     = 'fileloop'
			
			# New Address Object
			$EvalParams.Regex          = [regex] '^\s+edit\ "(.+?)"'
			$Eval                      = HelperEvalRegex @EvalParams -ReturnGroupNum 1
			if ($Eval) {
				$NewObject       = New-Object FortiShell.Vip
				$NewObject.Name  = $Eval
				$ReturnObject   += $NewObject
				Write-Verbose "object created: $($NewObject.Name)"
			}
			if ($NewObject) {
				
				###########################################################################################
				# Regular Properties
				
				# Update eval Parameters for remaining matches
				$EvalParams.VariableToUpdate = ([REF]$NewObject)
				$EvalParams.ReturnGroupNum   = 1
				
				###############################################
				# General Properties
				
				# ExternalInterface
				$EvalParams.ObjectProperty = "ExternalInterface"
				$EvalParams.Regex          = [regex] '^\s+set\ extintf\ "(.+?)"'
				$Eval                      = HelperEvalRegex @EvalParams
				
				# ExternalIp
				$EvalParams.ObjectProperty = "ExternalIp"
				$EvalParams.Regex          = [regex] '^\s+set\ extip\ (.+)'
				$Eval                      = HelperEvalRegex @EvalParams
				
				# MappedIp
				$EvalParams.ObjectProperty = "MappedIp"
				$EvalParams.Regex          = [regex] '^\s+set\ mappedip\ (.+)'
				$Eval                      = HelperEvalRegex @EvalParams
			}
		} else {
			continue
		}
	}	
	return $ReturnObject
}

###############################################################################
## Start Helper Functions
###############################################################################

###############################################################################
# HelperDetectClassful

function HelperDetectClassful {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True,Position=0,ParameterSetName='RxString')]
		[ValidatePattern("(\d+\.){3}\d+")]
		[String]$IpAddress
	)
	
	$VerbosePrefix = "HelperDetectClassful: "
	
	$Regex = [regex] "(?x)
					  (?<first>\d+)\.
					  (?<second>\d+)\.
					  (?<third>\d+)\.
					  (?<fourth>\d+)"
						  
	$Match = HelperEvalRegex $Regex $IpAddress
	
	$First  = $Match.Groups['first'].Value
	$Second = $Match.Groups['second'].Value
	$Third  = $Match.Groups['third'].Value
	$Fourth = $Match.Groups['fourth'].Value
	
	$Mask = 32
	if ($Fourth -eq "0") {
		$Mask -= 8
		if ($Third -eq "0") {
			$Mask -= 8
			if ($Second -eq "0") {
				$Mask -= 8
			}
		}
	}
	
	return "$IpAddress/$([string]$Mask)"
}

###############################################################################
# HelperEvalRegex

function HelperEvalRegex {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$True,Position=0,ParameterSetName='RxString')]
		[String]$RegexString,
		
		[Parameter(Mandatory=$True,Position=0,ParameterSetName='Rx')]
		[regex]$Regex,
		
		[Parameter(Mandatory=$True,Position=1)]
		[string]$StringToEval,
		
		[Parameter(Mandatory=$False)]
		[string]$ReturnGroupName,
		
		[Parameter(Mandatory=$False)]
		[int]$ReturnGroupNumber,
		
		[Parameter(Mandatory=$False)]
		$VariableToUpdate,
		
		[Parameter(Mandatory=$False)]
		[string]$ObjectProperty,
		
		[Parameter(Mandatory=$False)]
		[string]$LoopName
	)
	
	$VerbosePrefix = "HelperEvalRegex: "
	
	if ($RegexString) {
		$Regex = [Regex] $RegexString
	}
	
	if ($ReturnGroupName) { $ReturnGroup = $ReturnGroupName }
	if ($ReturnGroupNumber) { $ReturnGroup = $ReturnGroupNumber }
	
	$Match = $Regex.Match($StringToEval)
	if ($Match.Success) {
		#Write-Verbose "$VerbosePrefix Matched: $($Match.Value)"
		if ($ReturnGroup) {
			#Write-Verbose "$VerbosePrefix ReturnGroup"
			switch ($ReturnGroup.Gettype().Name) {
				"Int32" {
					$ReturnValue = $Match.Groups[$ReturnGroup].Value.Trim()
				}
				"String" {
					$ReturnValue = $Match.Groups["$ReturnGroup"].Value.Trim()
				}
				default { Throw "ReturnGroup type invalid" }
			}
			if ($VariableToUpdate) {
				if ($VariableToUpdate.Value.$ObjectProperty) {
					#Property already set on Variable
					continue $LoopName
				} else {
					$VariableToUpdate.Value.$ObjectProperty = $ReturnValue
					Write-Verbose "$ObjectProperty`: $ReturnValue"
				}
				continue $LoopName
			} else {
				return $ReturnValue
			}
		} else {
			return $Match
		}
	} else {
		if ($ObjectToUpdate) {
			return
			# No Match
		} else {
			return $false
		}
	}
}

###############################################################################
# HelperTestVerbose

function HelperTestVerbose {
[CmdletBinding()]
param()
    [System.Management.Automation.ActionPreference]::SilentlyContinue -ne $VerbosePreference
}

###############################################################################
## Export Cmdlets
###############################################################################

Export-ModuleMember *-*
