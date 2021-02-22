export const EXECUTION_DETAILS = [
  {
    "id": "attack-pattern--01a5a209-b94c-450b-b7f9-946497d91055",
    "platform": "windows",
    "tid": "T1047",
    "technique": "Windows Management Instrumentation",
    "tactic": "execution",
    "datasources": "authentication-logs|netflow-enclave-netflow|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse Windows Management Instrumentation (WMI) to achieve execution. WMI is a Windows administration feature that provides a uniform environment for local and remote access to Windows system components. It relies on the WMI service for local and remote access and the server message block (SMB) (Citation: Wikipedia SMB) and Remote Procedure Call Service (RPCS) (Citation: TechNet RPC) for remote access. RPCS operates over port 135. (Citation: MSDN WMI)<br /><br />An adversary can use WMI to interact with local and remote systems and use it as a means to perform many tactic functions, such as gathering information for Discovery and remote Execution of files as part of Lateral Movement. (Citation: FireEye WMI SANS 2015) (Citation: FireEye WMI 2015)<br /><br />",
    "technique_references": [
      {
        "source_name": "Wikipedia SMB",
        "url": "https://en.wikipedia.org/wiki/Server_Message_Block",
        "description": "Wikipedia. (2016, June 12). Server Message Block. Retrieved June 12, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet RPC",
        "url": "https://technet.microsoft.com/en-us/library/cc787851.aspx",
        "description": "Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "MSDN WMI",
        "url": "https://msdn.microsoft.com/en-us/library/aa394582.aspx",
        "description": "Microsoft. (n.d.). Windows Management Instrumentation. Retrieved April 27, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye WMI SANS 2015",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/sans-dfir-2015.pdf",
        "description": "Devon Kerr. (2015). There's Something About WMI. Retrieved May 4, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye WMI 2015",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf",
        "description": "Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--35dd844a-b219-4e2b-a6bb-efa9a75995a9",
    "platform": "windows|linux|macos",
    "tid": "T1053",
    "technique": "Scheduled Task/Job",
    "tactic": "execution",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1053.001",
      "T1053.002",
      "T1053.003",
      "T1053.004",
      "T1053.005",
      "T1053.006"
    ],
    "count_subtechniques": 6,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code. Utilities exist within all major operating systems to schedule programs or scripts to be executed at a specified date and time. A task can also be scheduled on a remote system, provided the proper authentication is met (ex: RPC and file and printer sharing in Windows environments). Scheduling a task on a remote system typically requires being a member of an admin or otherwise privileged group on the remote system.(Citation: TechNet Task Scheduler Security)<br /><br />Adversaries may use task scheduling to execute programs at system startup or on a scheduled basis for persistence. These mechanisms can also be abused to run a process under the context of a specified account (such as one with elevated permissions/privileges).<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/557.html",
        "description": "none",
        "external_id": "CAPEC-557"
      },
      {
        "source_name": "TechNet Task Scheduler Security",
        "url": "https://technet.microsoft.com/en-us/library/cc785125.aspx",
        "description": "Microsoft. (2005, January 21). Task Scheduler and security. Retrieved June 8, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--7385dfaf-6886-4229-9ecd-6fd678040830",
    "platform": "linux|macos|windows|network",
    "tid": "T1059",
    "technique": "Command and Scripting Interpreter",
    "tactic": "execution",
    "datasources": "powershell-logs|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1059.001",
      "T1059.002",
      "T1059.003",
      "T1059.004",
      "T1059.005",
      "T1059.006",
      "T1059.007",
      "T1059.008"
    ],
    "count_subtechniques": 8,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of [Unix Shell](https://attack.mitre.org/techniques/T1059/004) while Windows installations include the [Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).<br /><br />There are also cross-platform interpreters such as [Python](https://attack.mitre.org/techniques/T1059/006), as well as those commonly associated with client applications such as [JavaScript/JScript](https://attack.mitre.org/techniques/T1059/007) and [Visual Basic](https://attack.mitre.org/techniques/T1059/005).<br /><br />Adversaries may abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in [Initial Access](https://attack.mitre.org/tactics/TA0001) payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--92a78814-b191-47ca-909c-1ccfe3777414",
    "platform": "linux|macos|windows",
    "tid": "T1072",
    "technique": "Software Deployment Tools",
    "tactic": "execution",
    "datasources": "authentication-logs|binary-file-metadata|file-monitoring|process-monitoring|process-use-of-network|third-party-application-logs|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may gain access to and use third-party software suites installed within an enterprise network, such as administration, monitoring, and deployment systems, to move laterally through the network. Third-party applications and software deployment systems may be in use in the network environment for administration purposes (e.g., SCCM, VNC, HBSS, Altiris, etc.).<br /><br />Access to a third-party network-wide or enterprise-wide software system may enable an adversary to have remote code execution on all systems that are connected to such a system. The access may be used to laterally move to other systems, gather information, or cause a specific effect, such as wiping the hard drives on all endpoints.<br /><br />The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the third-party system, or specific domain credentials may be required. However, the system may require an administrative account to log in or to perform it's intended purpose.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/187.html",
        "description": "none",
        "external_id": "CAPEC-187"
      }
    ]
  },
  {
    "id": "attack-pattern--391d824f-0ef1-47a0-b0ee-c59a75e27670",
    "platform": "windows|macos|linux",
    "tid": "T1106",
    "technique": "Native API",
    "tactic": "execution",
    "datasources": "api-monitoring|loaded-dlls|process-monitoring|system-calls",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may directly interact with the native OS application programming interface (API) to execute behaviors. Native APIs provide a controlled means of calling low-level OS services within the kernel, such as those involving hardware/devices, memory, and processes.(Citation: NT API Windows)(Citation: Linux Kernel API) These native APIs are leveraged by the OS during system boot (when other system components are not yet initialized) as well as carrying out tasks and requests during routine operations.<br /><br />Functionality provided by native APIs are often also exposed to user-mode applications via interfaces and libraries. For example, functions such as the Windows API <code>CreateProcess()</code> or GNU <code>fork()</code> will allow programs and scripts to start other processes.(Citation: Microsoft CreateProcess)(Citation: GNU Fork) This may allow API callers to execute a binary, run a CLI command, load modules, etc. as thousands of similar API functions exist for various system operations.(Citation: Microsoft Win32)(Citation: LIBC)(Citation: GLIBC)<br /><br />Higher level software frameworks, such as Microsoft .NET and macOS Cocoa, are also available to interact with native APIs. These frameworks typically provide language wrappers/abstractions to API functionalities and are designed for ease-of-use/portability of code.(Citation: Microsoft NET)(Citation: Apple Core Services)(Citation: MACOS Cocoa)(Citation: macOS Foundation)<br /><br />Adversaries may abuse these native API functions as a means of executing behaviors. Similar to [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059), the native API and its hierarchy of interfaces, provide mechanisms to interact with and utilize various components of a victimized system.<br /><br />",
    "technique_references": [
      {
        "source_name": "NT API Windows",
        "url": "https://undocumented.ntinternals.net/",
        "description": "The NTinterlnals.net team. (n.d.). Nowak, T. Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Linux Kernel API",
        "url": "https://www.kernel.org/doc/html/v4.12/core-api/kernel-api.html",
        "description": "Linux Kernel Organization, Inc. (n.d.). The Linux Kernel API. Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft CreateProcess",
        "url": "http://msdn.microsoft.com/en-us/library/ms682425",
        "description": "Microsoft. (n.d.). CreateProcess function. Retrieved December 5, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "GNU Fork",
        "url": "https://www.gnu.org/software/libc/manual/html_node/Creating-a-Process.html",
        "description": "Free Software Foundation, Inc.. (2020, June 18). Creating a Process. Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Win32",
        "url": "https://docs.microsoft.com/en-us/windows/win32/api/",
        "description": "Microsoft. (n.d.). Programming reference for the Win32 API. Retrieved March 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "LIBC",
        "url": "https://man7.org/linux/man-pages//man7/libc.7.html",
        "description": "Kerrisk, M. (2016, December 12). libc(7) — Linux manual page. Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "GLIBC",
        "url": "https://www.gnu.org/software/libc/",
        "description": "glibc developer community. (2020, February 1). The GNU C Library (glibc). Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft NET",
        "url": "https://dotnet.microsoft.com/learn/dotnet/what-is-dotnet-framework",
        "description": "Microsoft. (n.d.). What is .NET Framework?. Retrieved March 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Apple Core Services",
        "url": "https://developer.apple.com/documentation/coreservices",
        "description": "Apple. (n.d.). Core Services. Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "MACOS Cocoa",
        "url": "https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/OSX_Technology_Overview/CocoaApplicationLayer/CocoaApplicationLayer.html#//apple_ref/doc/uid/TP40001067-CH274-SW1",
        "description": "Apple. (2015, September 16). Cocoa Application Layer. Retrieved June 25, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "macOS Foundation",
        "url": "https://developer.apple.com/documentation/foundation",
        "description": "Apple. (n.d.). Foundation. Retrieved July 1, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0a5231ec-41af-4a35-83d0-6bdf11f28c65",
    "platform": "windows",
    "tid": "T1129",
    "technique": "Shared Modules",
    "tactic": "execution",
    "datasources": "api-monitoring|dll-monitoring|file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse shared modules to execute malicious payloads. The Windows module loader can be instructed to load DLLs from arbitrary local paths and arbitrary Universal Naming Convention (UNC) network paths. This functionality resides in NTDLL.dll and is part of the Windows [Native API](https://attack.mitre.org/techniques/T1106) which is called from functions like <code>CreateProcess</code>, <code>LoadLibrary</code>, etc. of the Win32 API. (Citation: Wikipedia Windows Library Files)<br /><br />The module loader can load DLLs:<br /><br />* via specification of the (fully-qualified or relative) DLL pathname in the IMPORT directory;<br /><br />    <br /><br />* via EXPORT forwarded to another DLL, specified with (fully-qualified or relative) pathname (but without extension);<br /><br />    <br /><br />* via an NTFS junction or symlink program.exe.local with the fully-qualified or relative pathname of a directory containing the DLLs specified in the IMPORT directory or forwarded EXPORTs;<br /><br />    <br /><br />* via <code>&#x3c;file name=\"filename.extension\" loadFrom=\"fully-qualified or relative pathname\"&#x3e;</code> in an embedded or external \"application manifest\". The file name refers to an entry in the IMPORT directory or a forwarded EXPORT.<br /><br />Adversaries may use this functionality as a way to execute arbitrary code on a victim system. For example, malware may execute share modules to load additional components or features.<br /><br />",
    "technique_references": [
      {
        "source_name": "Wikipedia Windows Library Files",
        "url": "https://en.wikipedia.org/wiki/Microsoft_Windows_library_files",
        "description": "Wikipedia. (2017, January 31). Microsoft Windows library files. Retrieved February 13, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--be2dcee9-a7a7-4e38-afd6-21b31ecc3d63",
    "platform": "linux|windows|macos",
    "tid": "T1203",
    "technique": "Exploitation for Client Execution",
    "tactic": "execution",
    "datasources": "anti-virus|process-monitoring|system-calls",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may exploit software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to unsecure coding practices that can lead to unanticipated behavior. Adversaries can take advantage of certain vulnerabilities through targeted exploitation for the purpose of arbitrary code execution. Oftentimes the most valuable exploits to an offensive toolkit are those that can be used to obtain code execution on a remote system because they can be used to gain access to that system. Users will expect to see files related to the applications they commonly used to do work, so they are a useful target for exploit research and development because of their high utility.<br /><br />Several types exist:<br /><br />### Browser-based Exploitation<br /><br />Web browsers are a common target through [Drive-by Compromise](https://attack.mitre.org/techniques/T1189) and [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002). Endpoint systems may be compromised through normal web browsing or from certain users being targeted by links in spearphishing emails to adversary controlled sites used to exploit the web browser. These often do not require an action by the user for the exploit to be executed.<br /><br />### Office Applications<br /><br />Common office and productivity applications such as Microsoft Office are also targeted through [Phishing](https://attack.mitre.org/techniques/T1566). Malicious files will be transmitted directly as attachments or through links to download them. These require the user to open the document or file for the exploit to run.<br /><br />### Common Third-party Applications<br /><br />Other applications that are commonly seen or are part of the software deployed in a target network may also be used for exploitation. Applications such as Adobe Reader and Flash, which are common in enterprise environments, have been routinely targeted by adversaries attempting to gain access to systems. Depending on the software and nature of the vulnerability, some may be exploited in the browser or require the user to open a file. For instance, some Flash exploits have been delivered as objects within Microsoft Office documents.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--8c32eb4d-805f-4fc5-bf60-c4d476c131b5",
    "platform": "linux|windows|macos",
    "tid": "T1204",
    "technique": "User Execution",
    "tactic": "execution",
    "datasources": "anti-virus|process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1204.001",
      "T1204.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "An adversary may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious code by, for example, opening a malicious document file or link. These user actions will typically be observed as follow-on behavior from forms of [Phishing](https://attack.mitre.org/techniques/T1566).<br /><br />While [User Execution](https://attack.mitre.org/techniques/T1204) frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it. This activity may also be seen shortly after [Internal Spearphishing](https://attack.mitre.org/techniques/T1534).<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--acd0ba37-7ba9-4cc5-ac61-796586cd856d",
    "platform": "windows",
    "tid": "T1559",
    "technique": "Inter-Process Communication",
    "tactic": "execution",
    "datasources": "dll-monitoring|file-monitoring|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1559.001",
      "T1559.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution. IPC is typically used by processes to share data, communicate with each other, or synchronize execution. IPC is also commonly used to avoid situations such as deadlocks, which occurs when processes are stuck in a cyclic waiting pattern. <br /><br />Adversaries may abuse IPC to execute arbitrary code or commands. IPC mechanisms may differ depending on OS, but typically exists in a form accessible through programming languages/libraries or native interfaces such as Windows [Dynamic Data Exchange](https://attack.mitre.org/techniques/T1559/002) or [Component Object Model](https://attack.mitre.org/techniques/T1559/001). Higher level execution mediums, such as those of [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)s, may also leverage underlying IPC mechanisms.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--d157f9d2-d09a-4efa-bb2a-64963f94e253",
    "platform": "windows|macos",
    "tid": "T1569",
    "technique": "System Services",
    "tactic": "execution",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1569.001",
      "T1569.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse system services or daemons to execute commands or programs. Adversaries can execute malicious content by interacting with or creating services. Many services are set to run at boot, which can aid in achieving persistence ([Create or Modify System Process](https://attack.mitre.org/techniques/T1543)), but adversaries can also abuse services for one-time or temporary execution.<br /><br />",
    "technique_references": []
  }
]
