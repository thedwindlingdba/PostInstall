Enum SqlConnectionProtocol {
    TCP
    NP
    Any

}

Enum SqlInstanceAvailability {
    Available = 0 
    Unavailable = 1 
    Unknown = 2
}

Enum KPMGConfidenceLevel {
    High = 4
    Low = 1 
    Medium = 2
    None = 0
}

Enum KPMGDiscoveryMethod {
     IPRanges = 1 
     DomainSPN = 2
     Domain = 2
     DataSourceEnumeration = 4
     DomainServer = 8
     All = 15
}

Enum SqlInstanceScanType {
    All = 127
    Browsers = 32
    Default = 125
    DNSResolve = 8 
    Ping = 64 
    SPN = 16 
    SqlConnect = 2 
    SqlService = 4
    TCPPort = 1
}

Enum SqlInstanceInputType {
		Default
		Linked
		Server
		RegisteredServer
		ConnectionString
		ConnectionStringLocalDB
		SqlConnection
	}

if ( $PSVersionTable.PSVersion -ge '5.0' )
{
function Get-AccessorPropertyName
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(ValueFromPipeline = $true)]
        [string]
        $String
    )
    process
    {
        # check for missing underscore
        $regex = [regex]'\$(?!_)(?<PropertyName>\w*)\s*=\s*'
        $match = $regex.Match($String)
        if ( $match.Success )
        {
            throw [System.FormatException]::new(
                "Missing underscore in property name at`r`n$String"
            )
        }

        # the main match
        $regex = [regex]'\$_(?<PropertyName>\w*)\s*=\s*'
        $match = $regex.Match($String)
        (ConvertFrom-RegexNamedGroupCapture -Match $match -Regex $regex).PropertyName
    }
}


function Accessor
{
    [CmdletBinding()]
    param
    (
        [Parameter(position=1, Mandatory = $true)]
        $Object,

        [Parameter(position=2, Mandatory = $true)]
        [scriptblock]
        $Scriptblock
    )
    process
    {
        # extract the property name
        $propertyName = $MyInvocation.Line | Get-AccessorPropertyName


        # Prepare the get and set functions that are invoked
        # inside the scriptblock passed to Accessor.
        $functions = @{
            getFunction = {
                param
                (
                    $Scriptblock = (
                        # default getter
                        Invoke-Expression "{`$this._$propertyName}"
                    )
                )
                return New-Object psobject -Property @{
                    Accessor = 'get'; Scriptblock = $Scriptblock
                }
            }
            setFunction = [scriptblock]::Create({
                param
                (
                    $Scriptblock = (
                        # default setter
                        Invoke-Expression "{param(`$p) `$this._$propertyName = `$p}"
                    )
                )
                return New-Object psobject -Property @{
                    Accessor = 'set'; Scriptblock = $Scriptblock
                }
            })
        }

        # Prepare the variables that are available inside the
        # scriptblock that is passed to the accessor.
        $this = $Object
        $__propertyName = $propertyName
        $variables = Get-Variable 'this','__propertyName'

        # avoid a naming collision with the set and get aliases
        Remove-Item alias:\set -ErrorAction Stop
        Set-Alias set setFunction
        Set-Alias get getFunction

        # invoke the scriptblock
        $items = $MyInvocation.MyCommand.Module.NewBoundScriptBlock(
            $Scriptblock
        ).InvokeWithContext($functions,$variables)

        # This empty getter is invoked when no get statement is
        # included in Accessor.
        $getter = {}


        $initialValue = [System.Collections.ArrayList]::new()
        foreach ( $item in $items )
        {
            # get the initializer values
            if ( 'get','set' -notcontains $item.Accessor )
            {
                $initialValue.Add($item) | Out-Null
            }

            # extract the getter
            if ( $item.Accessor -eq 'get' )
            {
                $getter = $item.Scriptblock
            }

            # extract the setter
            if ( $item.Accessor -eq 'set' )
            {
                $setter = $item.Scriptblock
            }
        }

        # If there is no getter or setter don't add a scriptproperty.
        if ( -not $getter -and -not $setter )
        {
            return $initialValue
        }

        # Prepare to create the scriptproperty.
        $splat = @{
            MemberType = 'ScriptProperty'
            Name = $propertyName
            Value = $getter
        }

        # Omit the setter parameter if it is null.
        if ( $setter )
        {
            $splat.SecondValue = $setter
        }

        # Add the accessors by creating a scriptproperty.
        $Object | Add-Member @splat | Out-Null

        # Return the initializers.
        return $initialValue
    }
}
}

Class SqlPortReport {

    SqlPortReport([string]$ComputerName,[bool]$IsOpen,[int]$port){

        $this.ComputerName = $ComputerName 
        $this.Port = $port 
        $This.IsOpen = $ISOpen
    }

   [string]ToString(){

        return ("{0}:{1} - {2}" -f $this.ComputerName, $This.Port, $this.Isopen)

    }

}

Class SqlBrowserReply {
    [String]$MachineName
    [string]$ComputerName
    [string]$SqlInstance 
    [string]$InstanceName 
    [int]$TCPPort
    [string]$Version
    [bool]$IsClustered

   [string]Tostring(){
        return $this.SqlInstance
    }

}

Class SqlInstanceReport {

    [string]$MachineName 
    [string]$ComputerName
    [String]$InstanceName

Add-Member -InptuObject $this -MemberType "ScriptProperty" -Name "SqlInstance" -Value {



    if(-not([string]::ISNullOrEmpty($this.InstanceName)) -and ($this.InstanceName -notlike "*MSSQLSERVER*")){

        return "{0}\{1}" -f $this.ComputerName,$this.InstanceName
    }
    if(($this.Port -eq 1433) -or ($this.InstanceName -like "*MSSQLSERVER*")){

        return $this.ComputerName
    }

    return "{0},{1}" -f $this.ComputerName,$this.Port 


}

Add-Member -InputObject $This -MemberType "ScriptProperty" -Name "FullName" -Value {




    if(-not([string]::IsNullOrEmpty($this.InstanceName)) -and ($this.InstanceName -notlike "*MSSQLSERVER*")){

        return ("{0}\{1}" -f $this.ComputerName,$this.InstanceName )
    }
    if(($this.Port -eq 1433) -or ($this.InstanceName -like "*MSSQLSERVER*")){

        return $This.ComputerName

    } 
    return "{0}:{1}" -f $this.ComputerName,$This.Port

}

    
[int]$Port
[bool]$TcpConnected
[bool]$SqlConnected
[System.Net.IpHostEntry]$DnsResolution
[bool]$Ping
[SqlBrowserReply]$SqlBrowserReply
[object]$Services
[object]$SystemServices
[string[]]$SPNs
[SqlPortReport[]]$PortsScanned
[SqlInstanceAvailability]$Availability
[KPMGConfidenceLevel]$Confidence
[SqlInstanceScanType]$ScanTypes
[DateTime]$TimeStamp

   







}


Class SqlDatabaseParameter{
    [object]$InputObject
    [object]$Database
    [String]$Name 
   
    SqlDatabaseParameter([string]$Name){
        $this.InputObject = $name 
        $this.Name = $name 
    }

    SqlDatabaseParameter([object]$item){
    
        if($null -eq $Item){
            throw "Input Must not be null"
        }

        $this.InputObject = $item 
        [pscustomObject]$PSObject = $Item  -as [pscustomObject]   
        if($PSObject.TypeNames.Contains("Microsoft.SqlServer.Management.Smo.Database")){
            $this.Database =$item 
            $this.Name = [string]$PSObject.Properties["Name"].Value
            return 
        }

        foreach($PropertyInfo in $PSobject.Properties){

               if(($PropertyInfo.Name -like "*Database*")-and($null -ne $PropertyInfo.Value)){
                [pscustomobject]$PSObject2 = $PropertyInfo.Value -as [pscustomObject]
                if($PSObject2.TypeNames.Contains("Microsoft.SqlServer.Management.Smo.Database")){
                                      $this.Database =$PropertyInfo.Value
                    $this.Name = [string]$PSObject2.Properties["Name"].Value
                    return
                }

            } 

        }

    

        
        Throw "Cannot interpret input as Smo database object"
    
    }  

}


Class SqlDatabaseSMOParameter {

    [object]$Database
    [object]$InputObject
    [string]$name



    <#public DbaDatabaseSmoParameter(object Item)
{
	if (Item == null)
	{
		throw new ArgumentException("Input must not be null!");
	}
	this.InputObject = Item;
	PSObject psobject = new PSObject(Item);
	if (psobject.TypeNames.Contains("Microsoft.SqlServer.Management.Smo.Database"))
	{
		this.Database = Item;
		this.Name = (string)psobject.Properties["Name"].Value;
		return;
	}
	foreach (PSPropertyInfo pspropertyInfo in psobject.Properties)
	{
		if (UtilityHost.IsLike(pspropertyInfo.Name, "Database", false) && pspropertyInfo.Value != null)
		{
			PSObject psobject2 = new PSObject(pspropertyInfo.Value);
			if (psobject2.TypeNames.Contains("Microsoft.SqlServer.Management.Smo.Database"))
			{
				this.Database = pspropertyInfo.Value;
				this.Name = (string)psobject2.Properties["Name"].Value;
				return;
			}
		}
	}
	throw new ArgumentException("Cannot interpret input as SMO Database object");
}
#>

    SqlDatabaseSMOParameter([object]$Item){


        if($null -eq $Item){
            Throw "Item cannot be null"
        }

        $this.InputObject = $item 
        [PScustomObject]$PSObject = $item -as [PScustomObject]

        if($PSObject.TypeNames.Contians("Microsoft.SqlServer.Management.Smo.Database")){
            $this.Database = $item 
            $this.Name = [string]$PSObject.Properties["Name"].Value 
            return 
        }

        foreach($PropertyInfo in $PSObject.Properties){

                if(($PropertyInfo.Name -like "*Database*") -and ($null -ne $PropertyInfo.Value)){

                    [pscustomObject]$PSObject2 = $PropertyInfo.Value -as [PSCustomObject]

                    if($PSobject2.TypeNames.Contains("Microsoft.SqlServer.Management.Smo.Database")){
                        $this.Database = $PropertyInfo.Value
                        $this.Name = [string]$PSObject2.Properites["Name"].Value 
                        return
                    }



                }


        }

        Throw "Cannot interpret input as SMO Database Object"
    }


    [string]ToString(){
        return $this.Name 
    }



}


Class SqlInstanceParameter {

 Add-Member -inputobject $this -MemberType "ScriptProperty" -Name "ComputerName" -Value {

  

        if($this._ComputerName -eq "(LocalDB)"){
            return "localhost"
        }
        return $this._ComputerName 


   }


Add-Member -InputObject $this -MemberType "ScriptProperty" -Name "InstanceName" -Value {


    if([string]::ISNullOrEmpty($this._InstanceName)){

        return "MSSQLSERVER"
    }
    return $this._InstanceName


}


Add-Member -InputObject $this -MemberType "ScriptProperty" -Name "Port" -Value {


    if($this._Port -eq 0 -and [string]::ISNullOrEmpty($this._InstanceName)){


        return 1433
    }
    return $this._Port

}


Add-Member -InputObject $this -MemberType "ScriptProperty" -Name "NetworkProtocol" -Value {


    return $this._NetworkProtocol 


}

Add-Member -InputObject $this -MemberType "ScriptProperty" -Name "FullName" -Value {



				 $text = $this._ComputerName;
				if ($this._Port -gt 0)
				{
					$text = $text + ":" + $this._Port;
				}
				if (![string]::IsNullOrEmpty($this._InstanceName))
				{
					$text = $text + "\\" + $this._InstanceName;
				}
				return $text;
			

}


Add-Member -InputObject $this -MemberType "ScriptProperty" -Name "FullSMOName" -Value {
        
    
				$text = $this._ComputerName;
				if ($this._NetworkProtocol -eq [SqlConnectionProtocol]::NP)
				{
					$text = "NP:" + $text;
				}
				if ($this._NetworkProtocol -eq [SqlConnectionProtocol]::TCP)
				{
					$text = "TCP:" + $text;
				}
				if (![string]::IsNullOrEmpty($this._InstanceName) -and $this._Port -gt 0)
				{
					return [string]::Format("{0}\\{1},{2}", $text, $this._InstanceName, $this._Port);
				}
				if ($this._Port -gt 0)
				{
					return $text + "," + $this._Port;
				}
				if (![string]::IsNullOrEmpty($this._InstanceName))
				{
					return $text + "\\" + $this._InstanceName;
				}
				return $text;







}

Add-Member -Im $this -MemberType "ScriptProperty" -Name "SqlComputerName" -Value {


    return "[" + $this.ComputerName + "]"


}

Add-Member -Inputobject $this -MemberType "ScriptProperty" -Name "SqlInstanceName" -Value {

    if ([string]::IsNullOrEmpty($this._InstanceName))
    {
        return "[MSSQLSERVER]";
    }
    return "[" + $this._InstanceName + "]";


}


Add-Member -Inputobject $this -MemberType "ScriptProperty" -Name "SqlFullName" -Value {

                if ([string]::IsNullOrEmpty($this._InstanceName))
				{
					return "[" + $this._ComputerName + "]";
				}

                [string[]]$StringArray=@("[",$this._ComputerName,"\\",$this._InstanceName,"]")


				return [string]::Concat($StringArray);



}

[bool]$IsConnectionString

Add-Member -InputObject $This -Name Type -MemberType ScriptProperty -Value {


        [SqlInstanceInputType] $result;
				try
				{
					[string] $a =  [PSCustomObject]($this.InputObject).TypeNames[0].ToLower();
					if (!($a -eq "microsoft.sqlserver.management.smo.server"))
					{
						if (!($a -eq "microsoft.sqlserver.management.smo.linkedserver"))
						{
							if (!($a -eq "microsoft.sqlserver.management.registeredservers.registeredserver"))
							{
								if (!($a -eq "system.data.sqlclient.sqlconnection"))
								{
									$result = [SqlaInstanceInputType]::Default;
								}
								else
								{
									$result = [SqlInstanceInputType]::SqlConnection;
								}
							}
							else
							{
								$result = [SqlInstanceInputType]::RegisteredServer;
							}
						}
						else
						{
							$result = [SqlInstanceInputType]::Linked;
						}
					}
					else
					{
						$result = [SqlInstanceInputType]::Server;
					}
				}
				catch
				{
					$result = [SqlInstanceInputType]::Default;
				}
				return $result;
			}



            Add-Member -InputObject $this  -MemberType "ScriptProperty" -Name "LinkedLive" -Value {

                return ([SqlInstanceInputType]::RegisteredServer -band  $this.Type) -gt [SqlInstanceInputType]::Default;
    
            }


            SqlInstanceParameter([SqlInstanceInputType]$Input){
               return $Input.FullName
            }

            Add-Member -InputObject $this -MemberType "ScriptProperty" -Name "LinkedServer" -Value {


                [SqlInstanceInputType]$type = $this.Type;
				if ($type -eq [SqlInstanceInputType]::Linked)
				{
					return $this.InputObject;
				}
				if ($type -ne [SqlInstanceInputType]::Server)
				{
					return $null;
				}
				return  [PSCustomObject]($this.InputObject).Properties["LinkedServers"].Value;
            }
    

        SqlInstanceParameter([string]$Name){

            $this.InputObject = $Name;
			if ([string]::IsNullOrWhiteSpace($Name))
			{
				throw "Please provide an instance name"
			}
			if ($Name -eq ".")
			{
				$this._ComputerName = Name;
				$this._NetworkProtocol = [SqlConnectionProtocol]::NP;
				return;
			}
			 $text = $Name.Trim();
			$text = [Regex]::Replace($text, "^\\[(.*)\\]$", "$1");
			if ($text -like ".\\*")
			{
				$this._ComputerName = $Name;
				$this._NetworkProtocol = [SqlConnectionProtocol]::NP;
				[string] $text2 = $text.Substring(2);
				if (![Validation]::IsValidInstanceName($text2, $false))
				{
					throw [string]::Format("Failed to interpret instance name: '{0}' is not a legal name!", $text2));
				}
				$this._InstanceName = $text2;
				return;
			}
			else
			{
				if ($text -like "*.WORKGROUP")
				{
					$text = [Regex]::Replace($text, "\\.WORKGROUP$", "", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase);
				}
				if ([Regex]::IsMatch($text, '^\\\\\\\\[^\\\\]+\\\\pipe\\\\([^\\\\]+\\\\){0,1}[t]{0,1}sql\\\\query$',[System.Text.RegularExpressions.RegexOptions]::IgnoreCase))
				{
					try
					{
						$this._NetworkProtocol = [SqlConnectionProtocol]::NP;
						$this._ComputerName = [Regex]::Match($text, "^\\\\\\\\([^\\\\]+)\\\\").Groups[1].Value;
						if ([Regex]::IsMatch($text, '\\\\MSSQL\\$[^\\\\]+\\\\', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))
						{
							$this._InstanceName = [Regex]::Match($text, '\\\\MSSQL\\$([^\\\\]+)\\\\', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase).Groups[1].Value;
						}
					}
					catch 
					{
						throw [string]::Format("Failed to interpret named pipe path notation: {0} | {1}", this.InputObject, $_.Exeception.Message);
					}
					return;
				}
				try
				{
					[SqlInstanceParameter]$SqlInstanceParameter = [SqlInstanceParameter]::new(([System.Data.SqlClient.SqlConnectionStringBuilder]::New($text)).DataSource);
					$this._ComputerName = [SqlInstanceParameter]::ComputerName;
					if ([SqlInstanceParameter]::InstanceName -ne "MSSQLSERVER")
					{
						$this._InstanceName = [SqlInstanceParameter]::InstanceName;
					}
					if ([SqlInstanceParameter]::Port -ne 1433)
					{
						$this._Port = [SQlInstanceParameter]::Port;
					}
					$this._NetworkProtocol = [SqlInstanceParameter]::NetworkProtocol;
					if ($text -like  "(localdb)\\*")
					{
						$this._NetworkProtocol = [SqlConnectionProtocol]::NP;
					}
					$this.IsConnectionString = $true;
					return;
				}
				catch 
				{
					 $a = "unknown";
					try
					{
						$a = $_.Exception.TargetSite.GetParameters()[0].Name;
					}
					catch
					{
					}
					if ($a -eq "keyword")
					{
						throw;
					}
				}
				catch 
				{
					throw;
				}
				catch
				{
				}
				if ([Regex]::IsMatch($text, "^TCP:", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))
				{
					$this._NetworkProtocol = [SqlConnectionProtocol]::TCP;
					$text = $text.Substring(4);
				}
				if ([Regex]::IsMatch($text, "^NP:", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))
				{
					$this._NetworkProtocol = [SqlConnectionProtocol]::NP;
					$text = $text.Substring(3);
				}
				if ($text.Split('\\').Length -eq 1)
				{
					if ([Regex]::IsMatch($text, "[:,]\\d{1,5}$") -and -not [Regex]::IsMatch($text, [RegexHelper]::IPv6) -and ($text.Split(':').Length -eq 2 -or $text.Split(',').Length -eq 2))
					{
						
						if ([Regex]::IsMatch($text, '[:]\\d{1,5}$'))
						{
							$c = ':';
						}
						else
						{
							$c = ',';
						}
						try
						{
                            $OutPort=0
							[int]::TryParse($text.Split($c)[1], ([ref]$OutPort));
                            $this._Port =  $OutPort 
							if ($this._Port -gt 65535)
							{
								throw ("Failed to parse instance name: " + $text);
							}
							$text = $text.Split($c)[0];
						}
						catch
						{
							throw ("Failed to parse instance name: " + $Name);
						}
					}
					if ([Validation]::IsValidComputerTarget($text))
					{
						$this._ComputerName = $text;
						return;
					}
					throw ("Failed to parse instance name: " + $Name);
				}
				else
				{
					if ($text.Split('\\').Length -ne 2)
					{
						throw ("Failed to parse instance name: " + $Name);
					}
					$text3 = $text.Split('\\')[0];
					 $text4 = text.Split('\\')[1];
					if ([Regex]::IsMatch($text3, '[:,]\\d{1,5}$') -and -not [Regex]::IsMatch($text3, [RegexHelper]::IPv6))
					{
						
						if ([Regex]::IsMatch($text3, '[:]\\d{1,5}$'))
						{
							$c2 = ':';
						}
						else
						{
                            $c2 = ',';
						}
						try
						{
                            $OutPort2 = 0
							[int]::TryParse($text3.Split($c2)[1], ([ref]$OutPort2));
                            $this._Port = $OutPort2
							if ($this._Port -gt 65535)
							{
								throw ("Failed to parse instance name: " + $Name);
							}
							$text3 = $text3.Split($c2)[0];
						
						}
						catch
						{
							throw ("Failed to parse instance name: " + $Name);
						}
					}
					if ([Regex]::IsMatch($text4, '[:,]\\d{1,5}$') -and -not [Regex]::IsMatch($text4, [RegexHelper]::IPv6))
					{
						
						if ([Regex]::IsMatch($text, '[:]\\d{1,5}$'))
						{
							$c3 = ':';
						}
						else
						{
							$c3 = ',';
						}
						try
                        {
                            $OutPort3=0 
							[int]::TryParse($text4.Split($c3)[1],([ref]$OutPort3));
                            $this._Port = $OutPort3
							if ($this._Port -gt 65535)
							{
								throw ("Failed to parse instance name: " + $Name);
							}
							$text4 = $text4.Split($c3)[0];
						}
						catch
						{
							throw ("Failed to parse instance name: " + $Name);
						}
					}
				
					if (-not ($text3 -like "(localdb)") -and ( -not [Validation]::IsValidComputerTarget($text3) -or -not [Validation]::IsValidInstanceName($text4, $true)))
					{
						throw ([string]::Format("Failed to parse instance name: {0}. Computer Name: {1}, Instance {2}", $Name, $text3, $text4));
					}
					if (($text3 -like "(localdb)"))
					{
						$this._ComputerName = "(localdb)";
					}
					else
					{
						$this._ComputerName = $text3;
					}
					if ($text4.ToLower() -ne "default" -and $text4.ToLower() -ne "mssqlserver")
					{
						$this._InstanceName = $text4;
						return;
					}
				}
				return;
			}
		}




}








class Validation {


         static [bool]IsLocalhost([string]$Name)
		{
			try
			{
				[system.net.ipaddress]$ipaddress=0.0.0.0;
				[System.Net.IPAddress]::TryParse($Name, ([ref]$ipaddress));
				if ([System.Net.IPAddress]::IsLoopback($ipaddress))
				{
					return $true;
				}
				[System.Net.NetworkInformation.NetworkInterface[]]$allNetworkInterfaces = [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces();
				for ($i = 0; $i -lt  $allNetworkInterfaces.Length; $i++)
				{
					foreach ( $unicastIPAddressInformation in $allNetworkInterfaces[$i].GetIPProperties().UnicastAddresses)
					{
						if ($ipaddress.ToString() -eq $unicastIPAddressInformation.Address.ToString())
						{
							return $true;
						}
					}
		                                                                                                                                                                                                                                                                                                                                                                                                                      		}
			}
			catch
			{
			}
			try
			{
				if ($Name -eq ".")
				{
					return $true;
				}
				if ($Name.ToLower() -eq "localhost")
				{
					return $true;
				}
				if ($Name.ToLower() -eq [Environment]::MachineName.ToLower())
				{
					return $true;
				}
				if ($Name.ToLower() -eq ([Environment]::MachineName + "." + [Environment]::GetEnvironmentVariable("USERDNSDOMAIN")).ToLower())
				{
					return $true;
				}
			}
			catch
			{
			}
			return $false;
		}


    Static [bool]IsValidInstanceName([string]$InstanceName,[bool]$Lenient=$false){


        
           
			if (($InstanceName.Split('\\')).Length -eq 1){
				
                $text = $InstanceName;
			
			else
			{
				if (($InstanceName.Split('\\')).Length -ne 2)
				{
					return $false;
				}
                $text = $InstanceName.Split('\\')[1];
            }
           
			if ([Regex]::IsMatch($text, [RegexHelper]::SqlReservedKeyword, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))
			{
				return $false;
			}
			if (!$Lenient)
			{
				if ($text.ToLower() -eq "default")
				{
					return $false;
				}
				if ($text.ToLower() -eq "mssqlserver")
				{
					return $false;
				}
			}
			return [Regex]::IsMatch($text, [RegexHelper]::InstanceName, [System.text.RegularExpressions.RegexOptions]::IgnoreCase);
		}


    }


    static [bool] IsValidInstanceName([string] $InstanceName, [bool] $Lenient = $false)
		{
			
			if ($InstanceName.Split('\\').Length -eq 1)
			{
				$text = InstanceName;
			}
			else
			{
				if ($InstanceName.Split('\\').Length -ne 2)
				{
					return $false;
				}
				$text = $InstanceName.Split('\\')[1];
			}
			if ([Regex]::IsMatch($text, [RegexHelper]::SqlReservedKeyword, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))
			{
				return $false;
			}
			if (!$Lenient)
			{
				if ($text.ToLower() -eq "default")
				{
					return $false;
				}
				if ($text.ToLower() -eq "mssqlserver")
				{
					return $false;
				}
			}
			return [Regex]::IsMatch($text, [RegexHelper]::InstanceName, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase);
		}
	}







    






Class RegexHelper {

    
		static [string]$SqlReservedKeyword = '^ADD$|^ALL$|^ALTER$|^AND$|^ANY$|^AS$|^ASC$|^AUTHORIZATION$|^BACKUP$|^BEGIN$|^BETWEEN$|^BREAK$|^BROWSE$|^BULK$|^BY$|^CASCADE$|^CASE$|^CHECK$|^CHECKPOINT$|^CLOSE$|^CLUSTERED$|^COALESCE$|^COLLATE$|^COLUMN$|^COMMIT$|^COMPUTE$|^CONSTRAINT$|^CONTAINS$|^CONTAINSTABLE$|^CONTINUE$|^CONVERT$|^CREATE$|^CROSS$|^CURRENT$|^CURRENT_DATE$|^CURRENT_TIME$|^CURRENT_TIMESTAMP$|^CURRENT_USER$|^CURSOR$|^DATABASE$|^DBCC$|^DEALLOCATE$|^DECLARE$|^DEFAULT$|^DELETE$|^DENY$|^DESC$|^DISK$|^DISTINCT$|^DISTRIBUTED$|^DOUBLE$|^DROP$|^DUMP$|^ELSE$|^END$|^ERRLVL$|^ESCAPE$|^EXCEPT$|^EXEC$|^EXECUTE$|^EXISTS$|^EXIT$|^EXTERNAL$|^FETCH$|^FILE$|^FILLFACTOR$|^FOR$|^FOREIGN$|^FREETEXT$|^FREETEXTTABLE$|^FROM$|^FULL$|^FUNCTION$|^GOTO$|^GRANT$|^GROUP$|^HAVING$|^HOLDLOCK$|^IDENTITY$|^IDENTITY_INSERT$|^IDENTITYCOL$|^IF$|^IN$|^INDEX$|^INNER$|^INSERT$|^INTERSECT$|^INTO$|^IS$|^JOIN$|^KEY$|^KILL$|^LEFT$|^LIKE$|^LINENO$|^LOAD$|^MERGE$|^NATIONAL$|^NOCHECK$|^NONCLUSTERED$|^NOT$|^NULL$|^NULLIF$|^OF$|^OFF$|^OFFSETS$|^ON$|^OPEN$|^OPENDATASOURCE$|^OPENQUERY$|^OPENROWSET$|^OPENXML$|^OPTION$|^OR$|^ORDER$|^OUTER$|^OVER$|^PERCENT$|^PIVOT$|^PLAN$|^PRECISION$|^PRIMARY$|^PRINT$|^PROC$|^PROCEDURE$|^PUBLIC$|^RAISERROR$|^READ$|^READTEXT$|^RECONFIGURE$|^REFERENCES$|^REPLICATION$|^RESTORE$|^RESTRICT$|^RETURN$|^REVERT$|^REVOKE$|^RIGHT$|^ROLLBACK$|^ROWCOUNT$|^ROWGUIDCOL$|^RULE$|^SAVE$|^SCHEMA$|^SECURITYAUDIT$|^SELECT$|^SEMANTICKEYPHRASETABLE$|^SEMANTICSIMILARITYDETAILSTABLE$|^SEMANTICSIMILARITYTABLE$|^SESSION_USER$|^SET$|^SETUSER$|^SHUTDOWN$|^SOME$|^STATISTICS$|^SYSTEM_USER$|^TABLE$|^TABLESAMPLE$|^TEXTSIZE$|^THEN$|^TO$|^TOP$|^TRAN$|^TRANSACTION$|^TRIGGER$|^TRUNCATE$|^TRY_CONVERT$|^TSEQUAL$|^UNION$|^UNIQUE$|^UNPIVOT$|^UPDATE$|^UPDATETEXT$|^USE$|^USER$|^VALUES$|^VARYING$|^VIEW$|^WAITFOR$|^WHEN$|^WHERE$|^WHILE$|^WITH$|^WITHIN GROUP$|^WRITETEXT$'

        static [string]$InstanceName = '^[\\p{L}&_#][\\p{L}\\d\\$#_]{0,15}$'

        static [string]$IPV6 = '^(?:^|(?<=\\s))(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(?=\\s|$)$'

        static [string]$HostName = '^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-_]{0,62})(\\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-_]{0,61}[a-zA-Z0-9]))*$'

}