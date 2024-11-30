# **Bash \> PS Cheat Sheet**

| Bash | PowerShell | PowerShell Alias | Example | Note |
| :---: | :---: | :---: | :---: | :---: |
| Cd | Set-Location | Cd, sl, chdir | Set-Location \-Path .\\Desktop\\ | Change Directory |
| Cp | Copy-Item | Cp, copy cpi | Copy-Item \-Path .\\DemoFile.xlsx \-Destination .\\NewFile.xlsx | Copy a file |
| Find | Get-ChildItem |  | Get-ChildItem \-Filter "\*RDP\*" \-Recurse \-File | Find a file |
| Kill | Stop-Process |  | Get-Process \-Name Zoom |  |
| Ls | Get-ChildItem | Ls, dir | Get-ChildItem $env:USERPROFILE\\desktop | Sort-Object \-Property LastWriteTime |  |
| Man | Get-Help |  | Get-Help Test-Connection \-Full | Manual for a command |
| Man \-k | Get-Command |  | Get-Command \-Name "\*dns\*" | Find a command |
| Mkdir | New-Item |  | New-Item \-ItemType Directory \-Name ‘Articles’ | Make directory |
| Ping | Test-Connection |  | Test-Connection 10.0.0.6 | Format-Table \-AutoSize |  |
| Ps | Get-Process |  | Get-Process zoom | FL |  |
| pwd | Get-Location | Pwd, gl | Get-Location | Get present working directory |
| Rm | Remove-Item | Rm, ri, rmdir, rd, del | Remove-Item \-Recuse \-Force | Remove directory |
| Tail | Get-Content | gc | Get-Content \-Tail 7 '.\\CU Insights \- Computer Trends.csv' | Display the last 7 lines of a text file |
| cat | Get-Content | gc |  | Displays the contents of a text file |
| Touch | New-Item | ni | New-Item \-Name "xx.txt" \-ItemType File | Create a new, empty file |
| Wc | Measure-Object |  | Get-Content '.\\CU Insights \- Computer Trends (5).csv' | Measure-Object \-Character \-Line \-Word | Wc \= Word count |
| Whoami | whoami |  | whoami | Display the username |

| Bash/Linux | PowerShell |
| ----- | ----- |
| ls | ls |
| mv | mv |
| cp | cp |
| pwd | pwd |
| rm | rm |
| cat | cat |
| grep | select-string |
| echo | echo |
| var=0 | $var=0 |
| df | gdr Get-PSdrive |
| wc | measure-object |
| wc \-l | type \[gc \[object\]\]|measure-object \-line|select lines |
| ps | ps |
| find | gci |
| diff | diff |
| kill | kill |
| time | measure-command |
| if \[condition\] then something fi | if (condition) { something } |
| \-e file | Test-Path file |
| for ((i=0; i \< 10; i++)) ; do echo $i ; done | for ($i=0;$i \-lt 10; $i++) { echo $i } |
| more | | Out-Host \-Paging |

# **Live Examination**

* \> **Get-Verb** – output all verb that can possibly be used in PS verb/noun combinations  
* \> **ctrl+l** – clears work on screen  
* \> **| Format-List** – displays output in an easy to view list format  
* \> **| Out-Host \-Paging –** essentially the more command in bash  
* \> **| Ft \-wrap** – useful to display the full length of information on the same screen

* ## \> **Get-Process**

  * Handles – open files, resources, registry keys  
  * NPM (Non-page Memory) – memory in RAM  
  * PM (Page Memory) – the memory that has been swapped out of the disk

* \> **Get-Process \<process name\> | Select-Object \-Property \*** – used to **extract** **all** information it knows about a specific process running on the machine.   
  * \> **Get-Process \<process name\> | Select-Object \-Property name, id** – used to specify what item in the property list you would like to pull

* ## **\> Get-CimInstance**

  * Common information model (CIM) a **more detailed** version of Get-Process for incident response and allows us to pull the actual commands specific processes generate. **THINK ProcessID details**

  * \> **Get-CimInstnace \-Class Win32\_Process | Where-Object \-Property Name \-EQ ‘\<name of executable\>’ | Select-Object \-Property \***  
    * Using CimInstance you have to specify the full process name of the executable and then use “Select-Object” to specify that you want all extra information for that process (e.g., ExecutablePath, CommandLine, CreationDate, etc.).

  ### **Example Drill Down**

* **Get-Process & Get-CimInstance Use Case**  
  * **\> Get-Process ‘\<process name\>’ | Select-Object \-Property Id** – used to pull more general process information

  * **\> Get-CimInstance \-Class Win32\_Process | Where-Object \-Property ParentProcessId \-EQ \<Id from Get-Process\> | Format-List \-Property CommandLine**– pull more detailed information

* ## **\> Get-NetTCPConnection**

  * Essentially the same function as netstat in bash and allows you to examine network usage. 

  ### **Example Drill Down**

  * 1\) **\> Get-NetTCPConnection \-State Listen** – identify what properties you specifically want for a possible malicious process

  * 2\) **\> Get-NetTCPConnection \-State Listen | Select-Object \-Property localaddress, localport**

  * 3\) **\> Get-NetTCPConnection \-State Listen | Where-Object \-Property localport \-EQ \<port\#\>** 

  * 4\) **\> Get-NetTCPConnection \-State Listen | Where-Object \-Property localport \-EQ \<port\#\> | Select-Object \-Property \*** – identifying the information regarding the process that created the connection to that specific port number.

  * 5\) **\> Get-CimInstance \-Class Win32\_Process | Where-Object \-Property ProcessID \-EQ \<proces\#\>**

  * 6\) **\> Get-CimInstance \-Class Win32\_Process | Where-Object \-Property ProcessID \-EQ \<proces\#\> | Select-Object \-Property \***

* \> **Get-NetTCPConnection \-State Listen | Select-Object \-Property  LocalAddress, LocalPort, OwningProcess** – used to identify potential malicious processes on the network.  
  * \> **Get-NetTCPConnection \-RemoteAddress \<malicious IP\> | Select-Object CreationTime, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess, State** – used to further investigate the identified malicious process present on your system.

  * \> **Get-NetTCPConnection | Select-Object \-Property local\*, remote\*, state, @{Name='Process' ; Expression={(Get-Process \-Id $\_.OwningProcess).ProcessName}} | Format-Table** – used to get network connection details and the process name in one command using a hash table (@ { })

* ## **\> Get-Service**

  ### **Example Drill Down**

  * 1\) \> **Get-Service \<service-name\>**  
  * 2\) \> **Get-Service \<service-name\> | Select-Object \-Property \***  
  * 3\) \> **Get-CimInstance \-ClassName Win32\_Service | Where-Object \-Property \***  
  * 4\) \> **Get-CimInstance \-ClassName Win32\_Service | Where-Object \-Name  \-EQ** **\<service-name\>** – provides us our ProcessID needed for further investigation  
  * 5\) \> **Get-CimInstance \-ClassName Win32\_Service | Where-Object \-Name \-EQ \<service-name\> | Select-Object \-Property \***

* ## **\> Get-ChildItem \+ Get-ItemProperty**

  * Get-ChildItem – used to navigate to specific registry key  
  * Get-ItemProperty – used to enumerate the values in the registry

  ### **Example Drill Down**

  * 1\) \> **Get-ChildItem 'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' | Select-Object \-Property \***  
  * 2\) \> **Get-ChildItem 'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\' | Select-Object PSChildName**  
  * 3\) \> **Set-Location 'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\'** – changing directories into  the HKLM registry

  * 1\) \> **Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\' | Format-Table \-Wrap** – here you can looking into “Run” registry and see application that are **scheduled to run at startup or automatically**

* ## **Unusual Accounts**

  * ### \> **Get-LocalUser**

    * Used to identify common users on the system

  * ### \> **Get-LocalGroup** 

    * Used to identify local groups on the system

  * ### \> **Get-LocalGroupMember**

    * Used to identify the users associated with that group

* **\> Get-LocalUser | Where-Object {$\_.Enabled \-eq $True}** – used to specify only accounts that are active (legacy method)  
* \> **Get-LocalUser | Where-Object \-Property Enabled \-EQ $True** – an alternative way to specify you want only active accounts (updated method)  
  * $true – used to specify a specific Boolean variable  
* **\> Get-LocalUser | Select-Object \-Property \***

* ## **Scheduled Tasks**

  * **\> Get-ScheduledTask**   
    * Get a complete list of scheduled tasks on the system  
  * **\> Export-ScheduledTask**   
    * Used to export more in-depth information about odd scheduled tasks that you’ve found running on a machine  
  * **\> Get-ScheduledTaskInfo**   
    * Displays basic information such as LastRunTime, NextRunTime, and LastTaskResult

* ## **\> Get-WinEvent**

  * Used for parse through log entries

  ### **Example Drill Down**

* 1\) \> **$start \= Get-Date 10/1/2023**  
* 2\) \> **$end= Get-Date 10/15/2023**  
* 3\) \> **Get-WinEvent \-FilterHashtable @ { LogName=’Security’; StartTime=$start; EndTime=$end; }** – more efficient that utilizing Get-WinEvent alone (takes quite awhile for all log events to populate)  
  * \-FilterHashtable – parameter used to build a dictionary object using @ { }

* 1\) \> **Get-WinEvent \-LogName \***  
* 2\) \> **Get-WinEvent \-LogName \<Log Type\>| Select-Object \-Property \* | Format-List**  
* 3\) \> **Get-WinEvent \-LogName \<Log Type\>| Where-Object \-Property Id \-EQ \# | Format-List \-Property \***  
* 4\) \> **Get-WinEvent \-LogName \<Log Type\>| Where-Object \-Property Id \-EQ \# | Format-List \-Property ProcessId,TimeCreated**

* ## \> **Compare-Object**

  * The process of utilizing a golden image of your system or objects within a specific system and using the Compare-Object cmdlet to highlight differences between your **golden image** and the current system.

  ### **Example Drill Down**

  * \> **Get-Service \> baseline-services-20231018.txt** – serves as our golden image of for services  
  * \> **Get-Service \> services-liveinvestigation.txt**  
  * \> **$baseline \= Get-Content .\\baseline-service-20231018.txt** – creation of objects that can be compared against something else   
  * \> **$current \= Get-Content services-liveinvestigation.txt**  
  * \> **Compare-Object \-ReferenceObject $baseline \-DifferenceObject $current** – final comparison, will highlight key differences with the $baseline being the known good copy

# **Network Examination**

* Analyzing Packet Captures/Next Generation (pcaps/pcapng) 

  * ## **Tcpdump**

    * $ **tcpdump \-D** – used to list all interfaces that you want to sniff on  
    * \# **tcdump \-i \<interface\>** – capturing traffic for a specific interface that your workstation is connected to.  
    * \# **tcpdump \-i \<interface\> \-w \<file.pcap\>** – used to capture traffic for an interface and write it to a specific file for later analysis  
    * $ **tcpdump \-r \<file.pcap\> \-n \-A** – used to read pcaps, not resolve hostnames (numeric only), and only place the information in a human-readable form.

  * ## **Berkley Packet FIltering (BPF)**

    * Type: host, net, port, portrange  
    * Direction: src, dst  
    * Protocol: ip, tcp, udp, icmp, snmp, ssh, rdp  
    * Primitives: (and, &&); (or, ||); (not, \!)

  * ## **Web Proxy Logs**

    * Access Log Request (Squid Web proxy)  
      * Request Time  
      * Duration  
      * Source/Client  
      * Server Response  
      * Response Size  
      * HTTP Method  
      * URL  
      * User  
      * Content Type

  * ### **Example Drill Down** 

    * \# **tcpdump \-D**  
    * \# **tcpdump \-n \-i \<interface\> \-w \<file.pcap\>** – write to a file for later investigation  
    * \# **tcpdump \-r \<file.pcap\>** – beginning stages of network analysis  
    * \# **tcpdump \-r \<file.pcap\> \-n “port 80 && (src host X.X.X.X)”** – a combination of tcpdump and BPF to filter traffic on port 80 with X.X.X.X IP address  
    * \# **tcpdump \-r \<file.pcap\> \-n \-c 3 “src host X.X.X.X” \-tttt** – used to output only the first 3 packets where the src host is X.X.X.X to elucidate timestamps

    * \# **tcpdump \-r \<file.pcap\> \-n \-t “ip” | awk ‘{print $2}’ | cut \-d. \-f 1-4 | sort \-u**  
      * $ awk ‘{print $2}’ – grabs the second field of only IP addresses from tcpdump, the delimiter is defaulted to spaces  
      * $ cut \-d. \-f 1-4 – cuts out any additional octets representing ports that IP addresses communicate with and grabs only the first 4 fields separated by “.”  
      * $ sort \-u – sort all of the unique IP addresses in the extracted list

# **Memory Investigation**

* **ESSENTIALLY:** the creation of static memory from volatile memory to extend the time for incident responders to analyze determine root causes of incidents   
  * Tools – Volciraptor, WinPmem, Volatility  
    * [Velociraptor](https://docs.velociraptor.app//)  
    * [WinPmem](https://github.com/Velocidex/WinPmem?search=1)  
    * [Volatility](https://github.com/volatilityfoundation/volatility) – platform.class.PluginName (e.g., windows.pslist.PsList)

* ## **Volatility**

  ### **Listing Processes**

  * $ **vol \-q \-f memcapture.raw windows.pslist.Pslist \> newfile.txt**  
    * \-q – quite output, doesn’t tell you the current progress of loading  
    * \-f – file  
    * Raw\_mem – copied RAM memory from windows system  
    * windows.pstree.PsTree – plugin used to format the process list running within the copied RAM

  ### **Parent and Child Processes**

  * Useful to visually identify the parent and child process types that may have spawned within the RAM snapshot

  * $ **vol \-q \-f memcapture.raw windows.ptree.PsTree \> newfile.txt**

  ### **Network Connections**

  * List all network connections for processes within that memory capture, THINK: retroactive netstat

  * $ **vol \-q \-f memcapture.raw windows.netscan.NetScan**

  ### **Process Command Line**

  * Used to output actual command line and paths of executables that occurred. THINK: Get-CimInstance within PS

  * $ **vol \-q \-f memcapture.raw windows.cmdline.CmdLine**

  ### **Other Volatility Plugins**

  * **$ windows.dlllist.DllList** – list DLLs for processes  
  * **$ windows.driverscan.DriverScan** – list kernel modules  
  * **$ windows.envars.Envars** – list environment variables  
  * **$ windows.filescan.FileScan** – scan for files  
  * **$ windows.dumpfiles.DumpFiles** – carve out files  
  * **$ windows.info.Info** – examine Windows version information  
  * **$ windows.hashdump.HashDump** – retrieve password hashes  
  * **$ windows.privileges.Privileges** – listy privileges of process  
  * **$ windows.registry.hivelist.HiveList** – list registry hive offsets  
  * **$ windows.regsitry.printkey.PrintKey** – Access keys with \--offset  
  * **$ windows.registry.userassit.UserAssist** – enumerate programs run from the Start menu  
  * **$ windows.registry.certificates.Certificates** – list trusted certificates in Windows cert. store  
  * **$ windows.svcscan.ScvScan** – list service name, display name, PID

# **Lab 1.3 – Memory Investigation**

* 

# **Malware Investigation**

* \> Get-FileHash \<file\> – calculate SHA256 has on a file in Windows  
  * \> Get-FileHash \-Algorithm \<type\> \<file\> – to specify what algorithm you’d like to use on the file  
* \> strings \<file\> – view ASCII and 16-bit little endian Unicode strings located in Windows sysinternals  
* $ strings \<file\> – view all ASCII strings on Linux  
* $ strings \-e l \<file\> –view 16-bit little endian Unicode strings on Linux  
  * \-e l – specifies little endian (Little-endian stores the **least significant byte first, followed by the more significant bytes** in ascending order 

    Integer value: 0x12345678

    Little-endian: 78 56 34 12  
    CPU read: 12 34 56 78

    * Little-endian allows for processing of memory native to how the CPU processes information (right to left) which wil match the integer value and one less step than Big-endian. 

  * \-e b – specifies big endian (Big-endian stores the **most significant byte first**, **followed by the less significant bytes** in descending order.  

    Integer value: 0x12345678

    Big-endian: 12 34 56 78

    CPU read: 78 56 34 12

    CPU reverse (**additional**): 12 34 56 78

    * Big-endian requires an additional reversal step due the way that the CPU processes information (right to left), which results in a mismatch of the integer value and reversal, which takes additional processing time, energy, and money.

* ## **Regshot**

  * **Snapshot Monitoring Tool** for Windows registry and file systems\!  
  * Useful with instances when the malware you may be analyzing is programmed to identify if it is being actively monitored – regshot can be used to analyze malware after some time has passed. 

* ## **Process Monitor ([Procmon](https://gist.github.com/githubfoam/d4c4f3c956f5dbdd527f330c7fa6ae78#file-sysinternals-cheat-sheet))**

  * **Continuous Monitoring Tool** captures process activity in real-time (e.g., registry, file system, network, processes in detail)  
  * [**WINDOWS SYSINTERNALS FG**](https://os.cybbh.io/public/os/latest/015_windows_sysinternals/sysint_fg.html#_9_pslist)  
  * \> **net use \* [http://live.sysinternals.com](http://live.sysinternals.com)** – downloads all of the Sysinternals tool and places them in Drive

# **Lab 1.4 – Malware Investigation**

* 

# **Cloud Investigations**

* Responsibility Demarcation (Shared Responsibility)   
* Dynamic Approach to Incident Response (**DAIR**) \>   
  Preparation, Identification, Containment, Eradication, Remediation, Lessons Learned (**PICERL**) \>   
  Preparation, Verification and Triage, Scope, Containment, Eradication, Recovery, Remediation, Post-Incident Wrap-Up (**PV-SCERR-P**) 

* ## **DAIR Applied to the Cloud**

  * ALL WORK FOR IR SHOULD BE DONE IN THE CLOUD USING A CLOUD WORKSTATION:  
    * [SIFT (SANS Forensics) Workstation Walkthrough](https://forensicate.cloud/aws/sift-ami)

* [s3logparse.py](http://s3logparse.py)  
* [vpc-flow-log-analysis](https://github.com/FlorianPfisterer/vpc-flow-log-analysis)

# **Lab 1.5 – Cloud Investigation**

* 

# **Olympics**

## **PowerShell**

* \> C:\\Tools\\psolympics **.\\psolymipics**

## **Linux**

* $ **bootcamp** – to access Linux fundamentals walkthrough

# **Resources**

* [Zimmerman’s Tools](https://ericzimmerman.github.io/#!index.md)  
* [Velociraptor](https://docs.velociraptor.app//)  
* [WinPmem](https://github.com/Velocidex/WinPmem?search=1)  
* [Volatility](https://github.com/volatilityfoundation/volatility)  
* [OS Notes](https://docs.google.com/document/u/0/d/1ocozHXsx0LnhFzprHjk27t9AAl8OHmPkrjGNyw_-xv8/edit)