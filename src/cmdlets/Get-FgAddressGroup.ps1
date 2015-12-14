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