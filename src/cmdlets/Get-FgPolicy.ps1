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
				if ($Eval -eq "enable") {
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
				
				###########################################################################################
				# Regular Properties
				
				# Update eval Parameters for remaining matches
				$EvalParams.VariableToUpdate = ([REF]$NewObject)
				$EvalParams.ReturnGroupNum   = 1
				$EvalParams.LoopName         = 'fileloop'
				
				# SourceInterface	
				$EvalParams.Regex          = [regex] '^\s+set\ srcintf\ "(.+?)"'
				$EvalParams.ObjectProperty = "SourceInterface"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# SourceInterface	
				$EvalParams.Regex          = [regex] '^\s+set\ dstintf\ "(.+?)"'
				$EvalParams.ObjectProperty = "DestinationInterface"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# SourceAddress	
				$EvalParams.Regex          = [regex] '^\s+set\ srcaddr\ "(.+?)"'
				$EvalParams.ObjectProperty = "SourceAddress"
				$Eval                      = HelperEvalRegex @EvalParams
				
				# DestinationAddress
				$EvalParams.Regex          = [regex] '^\s+set\ dstaddr\ "(.+?)"'
				$EvalParams.ObjectProperty = "DestinationAddress"
				$Eval                      = HelperEvalRegex @EvalParams
				
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