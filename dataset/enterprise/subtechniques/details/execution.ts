 [
  {
    "id": "attack-pattern--6636bc83-0611-45a6-b74f-1f3daf635b8e",
    "platform": "linux",
    "tid": "T1053.001",
    "technique": "At (Linux)",
    "tactic": "execution",
    "datasources": "process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse the [at](https://attack.mitre.org/software/S0110) utility to perform task scheduling for initial or recurring execution of malicious code. The [at](https://attack.mitre.org/software/S0110) command within Linux operating systems enables administrators to schedule tasks.(Citation: Kifarunix - Task Scheduling in Linux)<br /><br />An adversary may use [at](https://attack.mitre.org/software/S0110) in Linux environments to execute programs at system startup or on a scheduled basis for persistence. [at](https://attack.mitre.org/software/S0110) can also be abused to conduct remote Execution as part of Lateral Movement and or to run a process under the context of a specified account.<br /><br />",
    "technique_references": [
      {
        "source_name": "Kifarunix - Task Scheduling in Linux",
        "url": "https://kifarunix.com/scheduling-tasks-using-at-command-in-linux/",
        "description": "Koromicha. (2019, September 7). Scheduling tasks using at command in Linux. Retrieved December 3, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--f3d95a1f-bba2-44ce-9af7-37866cd63fd0",
    "platform": "windows",
    "tid": "T1053.002",
    "technique": "At (Windows)",
    "tactic": "execution",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse the <code>at.exe</code> utility to perform task scheduling for initial or recurring execution of malicious code. The [at](https://attack.mitre.org/software/S0110) utility exists as an executable within Windows for scheduling tasks at a specified time and date. Using [at](https://attack.mitre.org/software/S0110) requires that the Task Scheduler service be running, and the user to be logged on as a member of the local Administrators group. <br /><br />An adversary may use <code>at.exe</code> in Windows environments to execute programs at system startup or on a scheduled basis for persistence. [at](https://attack.mitre.org/software/S0110) can also be abused to conduct remote Execution as part of Lateral Movement and or to run a process under the context of a specified account (such as SYSTEM).<br /><br />Note: The <code>at.exe</code> command line utility has been deprecated in current versions of Windows in favor of <code>schtasks</code>.<br /><br />",
    "technique_references": [
      {
        "source_name": "Twitter Leoloobeek Scheduled Task",
        "url": "https://twitter.com/leoloobeek/status/939248813465853953",
        "description": "Loobeek, L. (2017, December 8). leoloobeek Status. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Forum Scheduled Task Operational Setting",
        "url": "https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen",
        "description": "Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Scheduled Task Events",
        "url": "https://technet.microsoft.com/library/dd315590.aspx",
        "description": "Microsoft. (n.d.). General Task Registration. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Scheduled Task Events Win10",
        "url": "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events",
        "description": "Microsoft. (2017, May 28). Audit Other Object Access Events. Retrieved June 27, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Autoruns",
        "url": "https://technet.microsoft.com/en-us/sysinternals/bb963902",
        "description": "Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--2acf44aa-542f-4366-b4eb-55ef5747759c",
    "platform": "linux|macos",
    "tid": "T1053.003",
    "technique": "Cron",
    "tactic": "execution",
    "datasources": "process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse the <code>cron</code> utility to perform task scheduling for initial or recurring execution of malicious code. The <code>cron</code> utility is a time-based job scheduler for Unix-like operating systems.  The <code> crontab</code> file contains the schedule of cron entries to be run and the specified times for execution. Any <code>crontab</code> files are stored in operating system-specific file paths.<br /><br />An adversary may use <code>cron</code> in Linux or Unix environments to execute programs at system startup or on a scheduled basis for persistence. <code>cron</code> can also be abused to conduct remote Execution as part of Lateral Movement and or to run a process under the context of a specified account.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--8faedf87-dceb-4c35-b2a2-7286f59a3bc3",
    "platform": "macos",
    "tid": "T1053.004",
    "technique": "Launchd",
    "tactic": "execution",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse the <code>Launchd</code> daemon to perform task scheduling for initial or recurring execution of malicious code. The <code>launchd</code> daemon, native to macOS, is responsible for loading and maintaining services within the operating system. This process loads the parameters for each launch-on-demand system-level daemon from the property list (plist) files found in <code>/System/Library/LaunchDaemons</code> and <code>/Library/LaunchDaemons</code> (Citation: AppleDocs Launch Agent Daemons). These LaunchDaemons have property list files which point to the executables that will be launched (Citation: Methods of Mac Malware Persistence).<br /><br />An adversary may use the <code>launchd</code> daemon in macOS environments to schedule new executables to run at system startup or on a scheduled basis for persistence. <code>launchd</code> can also be abused to run a process under the context of a specified account. Daemons, such as <code>launchd</code>, run with the permissions of the root user account, and will operate regardless of which user account is logged in.<br /><br />",
    "technique_references": [
      {
        "source_name": "AppleDocs Launch Agent Daemons",
        "url": "https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html",
        "description": "Apple. (n.d.). Creating Launch Daemons and Agents. Retrieved July 10, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Methods of Mac Malware Persistence",
        "url": "https://www.virusbulletin.com/uploads/pdf/conference/vb2014/VB2014-Wardle.pdf",
        "description": "Patrick Wardle. (2014, September). Methods of Malware Persistence on Mac OS X. Retrieved July 5, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--005a06c6-14bf-4118-afa0-ebcd8aebb0c9",
    "platform": "windows",
    "tid": "T1053.005",
    "technique": "Scheduled Task",
    "tactic": "execution",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code. There are multiple ways to access the Task Scheduler in Windows. The <code>schtasks</code> can be run directly on the command line, or the Task Scheduler can be opened through the GUI within the Administrator Tools section of the Control Panel. In some cases, adversaries have used a .NET wrapper for the Windows Task Scheduler, and alternatively, adversaries have used the Windows netapi32 library to create a scheduled task.<br /><br />The deprecated [at](https://attack.mitre.org/software/S0110) utility could also be abused by adversaries (ex: [At (Windows)](https://attack.mitre.org/techniques/T1053/002)), though <code>at.exe</code> can not access tasks created with <code>schtasks</code> or the Control Panel.<br /><br />An adversary may use Windows Task Scheduler to execute programs at system startup or on a scheduled basis for persistence. The Windows Task Scheduler can also be abused to conduct remote Execution as part of Lateral Movement and or to run a process under the context of a specified account (such as SYSTEM).<br /><br />",
    "technique_references": [
      {
        "source_name": "Twitter Leoloobeek Scheduled Task",
        "url": "https://twitter.com/leoloobeek/status/939248813465853953",
        "description": "Loobeek, L. (2017, December 8). leoloobeek Status. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Forum Scheduled Task Operational Setting",
        "url": "https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen",
        "description": "Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Scheduled Task Events",
        "url": "https://technet.microsoft.com/library/dd315590.aspx",
        "description": "Microsoft. (n.d.). General Task Registration. Retrieved December 12, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Scheduled Task Events Win10",
        "url": "https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events",
        "description": "Microsoft. (2017, May 28). Audit Other Object Access Events. Retrieved June 27, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Autoruns",
        "url": "https://technet.microsoft.com/en-us/sysinternals/bb963902",
        "description": "Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--a542bac9-7bc1-4da7-9a09-96f69e23cc21",
    "platform": "linux",
    "tid": "T1053.006",
    "technique": "Systemd Timers",
    "tactic": "execution",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse systemd timers to perform task scheduling for initial or recurring execution of malicious code. Systemd timers are unit files with file extension <code>.timer</code> that control services. Timers can be set to run on a calendar event or after a time span relative to a starting point. They can be used as an alternative to [Cron](https://attack.mitre.org/techniques/T1053/003) in Linux environments.(Citation: archlinux Systemd Timers Aug 2020)<br /><br />Each <code>.timer</code> file must have a corresponding <code>.service</code> file with the same name, e.g., <code>example.timer</code> and <code>example.service</code>. <code>.service</code> files are [Systemd Service](https://attack.mitre.org/techniques/T1543/002) unit files that are managed by the systemd system and service manager.(Citation: Linux man-pages: systemd January 2014) Privileged timers are written to <code>/etc/systemd/system/</code> and <code>/usr/lib/systemd/system</code> while user level are written to <code>~/.config/systemd/user/</code>.<br /><br />An adversary may use systemd timers to execute malicious code at system startup or on a scheduled basis for persistence.(Citation: Arch Linux Package Systemd Compromise BleepingComputer 10JUL2018)(Citation: gist Arch package compromise 10JUL2018)(Citation: acroread package compromised Arch Linux Mail 8JUL2018) Timers installed using privileged paths may be used to maintain root level persistence. Adversaries may also install user level timers to achieve user level persistence.<br /><br />",
    "technique_references": [
      {
        "source_name": "archlinux Systemd Timers Aug 2020",
        "url": "https://wiki.archlinux.org/index.php/Systemd/Timers",
        "description": "archlinux. (2020, August 11). systemd/Timers. Retrieved October 12, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Linux man-pages: systemd January 2014",
        "url": "http://man7.org/linux/man-pages/man1/systemd.1.html",
        "description": "Linux man-pages. (2014, January). systemd(1) - Linux manual page. Retrieved April 23, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Arch Linux Package Systemd Compromise BleepingComputer 10JUL2018",
        "url": "https://www.bleepingcomputer.com/news/security/malware-found-in-arch-linux-aur-package-repository/",
        "description": "Catalin Cimpanu. (2018, July 10). Malware Found in Arch Linux AUR Package Repository. Retrieved April 23, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "gist Arch package compromise 10JUL2018",
        "url": "https://gist.github.com/campuscodi/74d0d2e35d8fd9499c76333ce027345a",
        "description": "Catalin Cimpanu. (2018, July 10). ~x file downloaded in public Arch package compromise. Retrieved April 23, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "acroread package compromised Arch Linux Mail 8JUL2018",
        "url": "https://lists.archlinux.org/pipermail/aur-general/2018-July/034153.html",
        "description": "Eli Schwartz. (2018, June 8). acroread package compromised. Retrieved April 23, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--970a3432-3237-47ad-bcca-7d8cbb217736",
    "platform": "windows",
    "tid": "T1059.001",
    "technique": "PowerShell",
    "tactic": "execution",
    "datasources": "dll-monitoring|file-monitoring|loaded-dlls|powershell-logs|process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. (Citation: TechNet PowerShell) Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the <code>Start-Process</code> cmdlet which can be used to run an executable and the <code>Invoke-Command</code> cmdlet which runs a command locally or on a remote computer (though administrator permissions are required to use PowerShell to connect to remote systems).<br /><br />PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk.<br /><br />A number of PowerShell-based offensive testing tools are available, including [Empire](https://attack.mitre.org/software/S0363),  [PowerSploit](https://attack.mitre.org/software/S0194), [PoshC2](https://attack.mitre.org/software/S0378), and PSAttack.(Citation: Github PSAttack)<br /><br />PowerShell commands/scripts can also be executed without directly invoking the <code>powershell.exe</code> binary through interfaces to PowerShell's underlying <code>System.Management.Automation</code> assembly DLL exposed through the .NET framework and Windows Common Language Interface (CLI). (Citation: Sixdub PowerPick Jan 2016)(Citation: SilentBreak Offensive PS Dec 2015)(Citation: Microsoft PSfromCsharp APR 2014)<br /><br />",
    "technique_references": [
      {
        "source_name": "TechNet PowerShell",
        "url": "https://technet.microsoft.com/en-us/scriptcenter/dd742419.aspx",
        "description": "Microsoft. (n.d.). Windows PowerShell Scripting. Retrieved April 28, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Github PSAttack",
        "url": "https://github.com/jaredhaight/PSAttack",
        "description": "Haight, J. (2016, April 21). PS>Attack. Retrieved June 1, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Sixdub PowerPick Jan 2016",
        "url": "http://www.sixdub.net/?p=367",
        "description": "Warner, J.. (2015, January 6). Inexorable PowerShell – A Red Teamer’s Tale of Overcoming Simple AppLocker Policies. Retrieved December 8, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "SilentBreak Offensive PS Dec 2015",
        "url": "https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe/",
        "description": "Christensen, L.. (2015, December 28). The Evolution of Offensive PowerShell Invocation. Retrieved December 8, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft PSfromCsharp APR 2014",
        "url": "https://blogs.msdn.microsoft.com/kebab/2014/04/28/executing-powershell-scripts-from-c/",
        "description": "Babinec, K. (2014, April 28). Executing PowerShell scripts from C#. Retrieved April 22, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Malware Archaeology PowerShell Cheat Sheet",
        "url": "http://www.malwarearchaeology.com/s/Windows-PowerShell-Logging-Cheat-Sheet-ver-June-2016-v2.pdf",
        "description": "Malware Archaeology. (2016, June). WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later. Retrieved June 24, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye PowerShell Logging 2016",
        "url": "https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html",
        "description": "Dunwoody, M. (2016, February 11). GREATER VISIBILITY THROUGH POWERSHELL LOGGING. Retrieved February 16, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--37b11151-1776-4f8f-b328-30939fbf2ceb",
    "platform": "macos",
    "tid": "T1059.002",
    "technique": "AppleScript",
    "tactic": "execution",
    "datasources": "api-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse AppleScript for execution. AppleScript is a macOS scripting language designed to control applications and parts of the OS via inter-application messages called AppleEvents.(Citation: Apple AppleScript) These AppleEvent messages can be sent independently or easily scripted with AppleScript. These events can locate open windows, send keystrokes, and interact with almost any open application locally or remotely.<br /><br />Scripts can be run from the command-line via <code>osascript /path/to/script</code> or <code>osascript -e \"script here\"</code>. Aside from the command line, scripts can be executed in numerous ways including Mail rules, Calendar.app alarms, and Automator workflows. AppleScripts can also be executed as plain text shell scripts by adding <code>#!/usr/bin/osascript</code> to the start of the script file.(Citation: SentinelOne AppleScript)<br /><br />AppleScripts do not need to call <code>osascript</code> to execute, however. They may be executed from within mach-O binaries by using the macOS [Native API](https://attack.mitre.org/techniques/T1106)s <code>NSAppleScript</code> or <code>OSAScript</code>, both of which execute code independent of the <code>/usr/bin/osascript</code> command line utility.<br /><br />Adversaries may abuse AppleScript to execute various behaviors, such as interacting with an open SSH connection, moving to remote machines, and even presenting users with fake dialog boxes. These events cannot start applications remotely (they can start them locally), but they can interact with applications if they're already running remotely. On macOS 10.10 Yosemite and higher, AppleScript has the ability to execute [Native API](https://attack.mitre.org/techniques/T1106)s, which otherwise would require compilation and execution in a mach-O binary file format.(Citation: SentinelOne macOS Red Team). Since this is a scripting language, it can be used to launch more common techniques as well such as a reverse shell via [Python](https://attack.mitre.org/techniques/T1059/006).(Citation: Macro Malware Targets Macs)<br /><br />",
    "technique_references": [
      {
        "source_name": "Apple AppleScript",
        "url": "https://developer.apple.com/library/archive/documentation/AppleScript/Conceptual/AppleScriptLangGuide/introduction/ASLR_intro.html",
        "description": "Apple. (2016, January 25). Introduction to AppleScript Language Guide. Retrieved March 28, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "SentinelOne AppleScript",
        "url": "https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/",
        "description": "Phil Stokes. (2020, March 16). How Offensive Actors Use AppleScript For Attacking macOS. Retrieved July 17, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "SentinelOne macOS Red Team",
        "url": "https://www.sentinelone.com/blog/macos-red-team-calling-apple-apis-without-building-binaries/",
        "description": "Phil Stokes. (2019, December 5). macOS Red Team: Calling Apple APIs Without Building Binaries. Retrieved July 17, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Macro Malware Targets Macs",
        "url": "https://www.mcafee.com/blogs/other-blogs/mcafee-labs/macro-malware-targets-macs/",
        "description": "Yerko Grbic. (2017, February 14). Macro Malware Targets Macs. Retrieved July 8, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--d1fcf083-a721-4223-aedf-bf8960798d62",
    "platform": "windows",
    "tid": "T1059.003",
    "technique": "Windows Command Shell",
    "tactic": "execution",
    "datasources": "process-command-line-parameters|process-monitoring|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse the Windows command shell for execution. The Windows command shell (<code>cmd.exe</code>) is the primary command prompt on Windows systems. The Windows command prompt can be used to control almost any aspect of a system, with various permission levels required for different subsets of commands. <br /><br />Batch files (ex: .bat or .cmd) also provide the shell with a list of sequential commands to run, as well as normal scripting operations such as conditionals and loops. Common uses of batch files include long or repetitive tasks, or the need to run the same set of commands on multiple systems.<br /><br />Adversaries may leverage <code>cmd.exe</code> to execute various commands and payloads. Common uses include <code>cmd.exe /c</code> to execute a single command, or abusing <code>cmd.exe</code> interactively with input and output forwarded over a command and control channel.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--a9d4b653-6915-42af-98b2-5758c4ceee56",
    "platform": "macos|linux",
    "tid": "T1059.004",
    "technique": "Unix Shell",
    "tactic": "execution",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse Unix shell commands and scripts for execution. Unix shells are the primary command prompt on Linux and macOS systems, though many variations of the Unix shell exist (e.g. sh, bash, zsh, etc.) depending on the specific OS or distribution.(Citation: DieNet Bash)(Citation: Apple ZShell) Unix shells can control every aspect of a system, with certain commands requiring elevated privileges.<br /><br />Unix shells also support scripts that enable sequential execution of commands as well as other typical programming operations such as conditionals and loops. Common uses of shell scripts include long or repetitive tasks, or the need to run the same set of commands on multiple systems.<br /><br />Adversaries may abuse Unix shells to execute various commands or payloads. Interactive shells may be accessed through command and control channels or during lateral movement such as with [SSH](https://attack.mitre.org/techniques/T1021/004). Adversaries may also leverage shell scripts to deliver and execute multiple commands on victims or as part of payloads used for persistence.<br /><br />",
    "technique_references": [
      {
        "source_name": "DieNet Bash",
        "url": "https://linux.die.net/man/1/bash",
        "description": "die.net. (n.d.). bash(1) - Linux man page. Retrieved June 12, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Apple ZShell",
        "url": "https://support.apple.com/HT208050",
        "description": "Apple. (2020, January 28). Use zsh as the default shell on your Mac. Retrieved June 12, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--dfd7cc1d-e1d8-4394-a198-97c4cab8aa67",
    "platform": "windows|macos|linux",
    "tid": "T1059.005",
    "technique": "Visual Basic",
    "tactic": "execution",
    "datasources": "dll-monitoring|file-monitoring|loaded-dlls|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse Visual Basic (VB) for execution. VB is a programming language created by Microsoft with interoperability with many Windows technologies such as [Component Object Model](https://attack.mitre.org/techniques/T1559/001) and the [Native API](https://attack.mitre.org/techniques/T1106) through the Windows API. Although tagged as legacy with no planned future evolutions, VB is integrated and supported in the .NET Framework and cross-platform .NET Core.(Citation: VB .NET Mar 2020)(Citation: VB Microsoft)<br /><br />Derivative languages based on VB have also been created, such as Visual Basic for Applications (VBA) and VBScript. VBA is an event-driven programming language built into Microsoft Office, as well as several third-party applications.(Citation: Microsoft VBA)(Citation: Wikipedia VBA) VBA enables documents to contain macros used to automate the execution of tasks and other functionality on the host. VBScript is a default scripting language on Windows hosts and can also be used in place of [JavaScript/JScript](https://attack.mitre.org/techniques/T1059/007) on HTML Application (HTA) webpages served to Internet Explorer (though most modern browsers do not come with VBScript support).(Citation: Microsoft VBScript)<br /><br />Adversaries may use VB payloads to execute malicious commands. Common malicious usage includes automating execution of behaviors with VBScript or embedding VBA content into [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001) payloads.<br /><br />",
    "technique_references": [
      {
        "source_name": "VB .NET Mar 2020",
        "url": "https://devblogs.microsoft.com/vbteam/visual-basic-support-planned-for-net-5-0/",
        "description": ".NET Team. (2020, March 11). Visual Basic support planned for .NET 5.0. Retrieved June 23, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "VB Microsoft",
        "url": "https://docs.microsoft.com/dotnet/visual-basic/",
        "description": "Microsoft. (n.d.). Visual Basic documentation. Retrieved June 23, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft VBA",
        "url": "https://docs.microsoft.com/office/vba/api/overview/",
        "description": "Microsoft. (2019, June 11). Office VBA Reference. Retrieved June 23, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Wikipedia VBA",
        "url": "https://en.wikipedia.org/wiki/Visual_Basic_for_Applications",
        "description": "Wikipedia. (n.d.). Visual Basic for Applications. Retrieved August 13, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft VBScript",
        "url": "https://docs.microsoft.com/previous-versions//1kw29xwf(v=vs.85)",
        "description": "Microsoft. (2011, April 19). What Is VBScript?. Retrieved March 28, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--cc3502b5-30cc-4473-ad48-42d51a6ef6d1",
    "platform": "linux|windows|macos",
    "tid": "T1059.006",
    "technique": "Python",
    "tactic": "execution",
    "datasources": "api-monitoring|process-command-line-parameters|process-monitoring|system-calls",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse Python commands and scripts for execution. Python is a very popular scripting/programming language, with capabilities to perform many functions. Python can be executed interactively from the command-line (via the <code>python.exe</code> interpreter) or via scripts (.py) that can be written and distributed to different systems. Python code can also be compiled into binary executables.<br /><br />Python comes with many built-in packages to interact with the underlying system, such as file operations and device I/O. Adversaries can use these libraries to download and execute commands or other scripts as well as perform various malicious behaviors.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--0f4a0c76-ab2d-4cb0-85d3-3f0efb8cba0d",
    "platform": "windows|macos|linux",
    "tid": "T1059.007",
    "technique": "JavaScript/JScript",
    "tactic": "execution",
    "datasources": "dll-monitoring|file-monitoring|loaded-dlls|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse JavaScript and/or JScript for execution. JavaScript (JS) is a platform-agnostic scripting language (compiled just-in-time at runtime) commonly associated with scripts in webpages, though JS can be executed in runtime environments outside the browser.(Citation: NodeJS)<br /><br />JScript is the Microsoft implementation of the same scripting standard. JScript is interpreted via the Windows Script engine and thus integrated with many components of Windows such as the [Component Object Model](https://attack.mitre.org/techniques/T1559/001) and Internet Explorer HTML Application (HTA) pages.(Citation: JScrip May 2018)(Citation: Microsoft JScript 2007)(Citation: Microsoft Windows Scripts)<br /><br />Adversaries may abuse JavaScript / JScript to execute various behaviors. Common uses include hosting malicious scripts on websites as part of a [Drive-by Compromise](https://attack.mitre.org/techniques/T1189) or downloading and executing these script files as secondary payloads. Since these payloads are text-based, it is also very common for adversaries to obfuscate their content as part of [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027).<br /><br />",
    "technique_references": [
      {
        "source_name": "NodeJS",
        "url": "https://nodejs.org/",
        "description": "OpenJS Foundation. (n.d.). Node.js. Retrieved June 23, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "JScrip May 2018",
        "url": "https://docs.microsoft.com/windows/win32/com/translating-to-jscript",
        "description": "Microsoft. (2018, May 31). Translating to JScript. Retrieved June 23, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft JScript 2007",
        "url": "https://docs.microsoft.com/archive/blogs/gauravseth/the-world-of-jscript-javascript-ecmascript",
        "description": "Microsoft. (2007, August 15). The World of JScript, JavaScript, ECMAScript …. Retrieved June 23, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Windows Scripts",
        "url": "https://docs.microsoft.com/scripting/winscript/windows-script-interfaces",
        "description": "Microsoft. (2017, January 18). Windows Script Interfaces. Retrieved June 23, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--818302b2-d640-477b-bf88-873120ce85c4",
    "platform": "network",
    "tid": "T1059.008",
    "technique": "Network Device CLI",
    "tactic": "execution",
    "datasources": "network-device-command-history|network-device-configuration|network-device-logs|network-device-run-time-memory",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse scripting or built-in command line interpreters (CLI) on network devices to execute malicious command and payloads. The CLI is the primary means through which users and administrators interact with the device in order to view system information, modify device operations, or perform diagnostic and administrative functions. CLIs typically contain various permission levels required for different commands. <br /><br />Scripting interpreters automate tasks and extend functionality beyond the command set included in the network OS. The CLI and scripting interpreter are accessible through a direct console connection, or through remote means, such as telnet or secure shell (SSH).<br /><br />Adversaries can use the network CLI to change how network devices behave and operate. The CLI may be used to manipulate traffic flows to intercept or manipulate data, modify startup configuration parameters to load malicious system software, or to disable security features or logging to avoid detection. (Citation: Cisco Synful Knock Evolution)<br /><br />",
    "technique_references": [
      {
        "source_name": "Cisco Synful Knock Evolution",
        "url": "https://blogs.cisco.com/security/evolution-of-attacks-on-cisco-ios-devices",
        "description": "Graham Holmes. (2015, October 8). Evolution of attacks on Cisco IOS devices. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco IOS Software Integrity Assurance - Command History",
        "url": "https://tools.cisco.com/security/center/resources/integrity_assurance.html#23",
        "description": "Cisco. (n.d.). Cisco IOS Software Integrity Assurance - Command History. Retrieved October 21, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ef67e13e-5598-4adc-bdb2-998225874fa9",
    "platform": "linux|macos|windows",
    "tid": "T1204.001",
    "technique": "Malicious Link",
    "tactic": "execution",
    "datasources": "anti-virus|process-monitoring|web-proxy",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "An adversary may rely upon a user clicking a malicious link in order to gain execution. Users may be subjected to social engineering to get them to click on a link that will lead to code execution. This user action will typically be observed as follow-on behavior from [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002). Clicking on a link may also lead to other execution techniques such as exploitation of a browser or application vulnerability via [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203). Links may also lead users to download files that require execution via [Malicious File](https://attack.mitre.org/techniques/T1204/002).<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--232b7f21-adf9-4b42-b936-b9d6f7df856e",
    "platform": "linux|macos|windows",
    "tid": "T1204.002",
    "technique": "Malicious File",
    "tactic": "execution",
    "datasources": "anti-virus|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "An adversary may rely upon a user opening a malicious file in order to gain execution. Users may be subjected to social engineering to get them to open a file that will lead to code execution. This user action will typically be observed as follow-on behavior from [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001). Adversaries may use several types of files that require a user to execute them, including .doc, .pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, and .cpl.<br /><br />Adversaries may employ various forms of [Masquerading](https://attack.mitre.org/techniques/T1036) on the file to increase the likelihood that a user will open it.<br /><br />While [Malicious File](https://attack.mitre.org/techniques/T1204/002) frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it. This activity may also be seen shortly after [Internal Spearphishing](https://attack.mitre.org/techniques/T1534).<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--2f6b4ed7-fef1-44ba-bcb8-1b4beb610b64",
    "platform": "windows",
    "tid": "T1559.001",
    "technique": "Component Object Model",
    "tactic": "execution",
    "datasources": "dll-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use the Windows Component Object Model (COM) for local code execution. COM is an inter-process communication (IPC) component of the native Windows application programming interface (API) that enables interaction between software objects, or executable code that implements one or more interfaces.(Citation: Fireeye Hunting COM June 2019) Through COM, a client object can call methods of server objects, which are typically binary Dynamic Link Libraries (DLL) or executables (EXE).(Citation: Microsoft COM)<br /><br />Various COM interfaces are exposed that can be abused to invoke arbitrary execution via a variety of programming languages such as C, C++, Java, and [Visual Basic](https://attack.mitre.org/techniques/T1059/005).(Citation: Microsoft COM) Specific COM objects also exist to directly perform functions beyond code execution, such as creating a [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053), fileless download/execution, and other adversary behaviors related to privilege escalation and persistence.(Citation: Fireeye Hunting COM June 2019)(Citation: ProjectZero File Write EoP Apr 2018)<br /><br />",
    "technique_references": [
      {
        "source_name": "Fireeye Hunting COM June 2019",
        "url": "https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html",
        "description": "Hamilton, C. (2019, June 4). Hunting COM Objects. Retrieved June 10, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft COM",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ms680573.aspx",
        "description": "Microsoft. (n.d.). Component Object Model (COM). Retrieved November 22, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "ProjectZero File Write EoP Apr 2018",
        "url": "https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html",
        "description": "Forshaw, J. (2018, April 18). Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege. Retrieved May 3, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Enigma Outlook DCOM Lateral Movement Nov 2017",
        "url": "https://enigma0x3.net/2017/11/16/lateral-movement-using-outlooks-createobject-method-and-dotnettojscript/",
        "description": "Nelson, M. (2017, November 16). Lateral Movement using Outlook's CreateObject Method and DotNetToJScript. Retrieved November 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Enigma MMC20 COM Jan 2017",
        "url": "https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/",
        "description": "Nelson, M. (2017, January 5). Lateral Movement using the MMC20 Application COM Object. Retrieved November 21, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--232a7e42-cd6e-4902-8fe9-2960f529dd4d",
    "platform": "windows",
    "tid": "T1559.002",
    "technique": "Dynamic Data Exchange",
    "tactic": "execution",
    "datasources": "dll-monitoring|file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use Windows Dynamic Data Exchange (DDE) to execute arbitrary commands. DDE is a client-server protocol for one-time and/or continuous inter-process communication (IPC) between applications. Once a link is established, applications can autonomously exchange transactions consisting of strings, warm data links (notifications when a data item changes), hot data links (duplications of changes to a data item), and requests for command execution.<br /><br />Object Linking and Embedding (OLE), or the ability to link data between documents, was originally implemented through DDE. Despite being superseded by [Component Object Model](https://attack.mitre.org/techniques/T1559/001), DDE may be enabled in Windows 10 and most of Microsoft Office 2016 via Registry keys. (Citation: BleepingComputer DDE Disabled in Word Dec 2017) (Citation: Microsoft ADV170021 Dec 2017) (Citation: Microsoft DDE Advisory Nov 2017)<br /><br />Microsoft Office documents can be poisoned with DDE commands (Citation: SensePost PS DDE May 2016) (Citation: Kettle CSV DDE Aug 2014), directly or through embedded files (Citation: Enigma Reviving DDE Jan 2018), and used to deliver execution via [Phishing](https://attack.mitre.org/techniques/T1566) campaigns or hosted Web content, avoiding the use of Visual Basic for Applications (VBA) macros. (Citation: SensePost MacroLess DDE Oct 2017) DDE could also be leveraged by an adversary operating on a compromised machine who does not have direct access to a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059).<br /><br />",
    "technique_references": [
      {
        "source_name": "BleepingComputer DDE Disabled in Word Dec 2017",
        "url": "https://www.bleepingcomputer.com/news/microsoft/microsoft-disables-dde-feature-in-word-to-prevent-further-malware-attacks/",
        "description": "Cimpanu, C. (2017, December 15). Microsoft Disables DDE Feature in Word to Prevent Further Malware Attacks. Retrieved December 19, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft ADV170021 Dec 2017",
        "url": "https://portal.msrc.microsoft.com/security-guidance/advisory/ADV170021",
        "description": "Microsoft. (2017, December 12). ADV170021 - Microsoft Office Defense in Depth Update. Retrieved February 3, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft DDE Advisory Nov 2017",
        "url": "https://technet.microsoft.com/library/security/4053440",
        "description": "Microsoft. (2017, November 8). Microsoft Security Advisory 4053440 - Securely opening Microsoft Office documents that contain Dynamic Data Exchange (DDE) fields. Retrieved November 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "SensePost PS DDE May 2016",
        "url": "https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/",
        "description": "El-Sherei, S. (2016, May 20). PowerShell, C-Sharp and DDE The Power Within. Retrieved November 22, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Kettle CSV DDE Aug 2014",
        "url": "https://www.contextis.com/blog/comma-separated-vulnerabilities",
        "description": "Kettle, J. (2014, August 29). Comma Separated Vulnerabilities. Retrieved November 22, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Enigma Reviving DDE Jan 2018",
        "url": "https://posts.specterops.io/reviving-dde-using-onenote-and-excel-for-code-execution-d7226864caee",
        "description": "Nelson, M. (2018, January 29). Reviving DDE: Using OneNote and Excel for Code Execution. Retrieved February 3, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "SensePost MacroLess DDE Oct 2017",
        "url": "https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/",
        "description": "Stalmans, E., El-Sherei, S. (2017, October 9). Macro-less Code Exec in MSWord. Retrieved November 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "NVisio Labs DDE Detection Oct 2017",
        "url": "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/",
        "description": "NVISO Labs. (2017, October 11). Detecting DDE in MS Office documents. Retrieved November 21, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--810aa4ad-61c9-49cb-993f-daa06199421d",
    "platform": "macos",
    "tid": "T1569.001",
    "technique": "Launchctl",
    "tactic": "execution",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse launchctl to execute commands or programs. Launchctl controls the macOS launchd process, which handles things like [Launch Agent](https://attack.mitre.org/techniques/T1543/001)s and [Launch Daemon](https://attack.mitre.org/techniques/T1543/004)s, but can execute other commands or programs itself. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from standard input.(Citation: Launchctl Man)<br /><br />By loading or reloading [Launch Agent](https://attack.mitre.org/techniques/T1543/001)s or [Launch Daemon](https://attack.mitre.org/techniques/T1543/004)s, adversaries can install persistence or execute changes they made.(Citation: Sofacy Komplex Trojan)<br /><br />Running a command from launchctl is as simple as <code>launchctl submit -l <labelName> -- /Path/to/thing/to/execute \"arg\" \"arg\" \"arg\"</code>. Adversaries can abuse this functionality to execute code or even bypass application control if launchctl is an allowed process.<br /><br />",
    "technique_references": [
      {
        "source_name": "Launchctl Man",
        "url": "https://ss64.com/osx/launchctl.html",
        "description": "SS64. (n.d.). launchctl. Retrieved March 28, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Sofacy Komplex Trojan",
        "url": "https://researchcenter.paloaltonetworks.com/2016/09/unit42-sofacys-komplex-os-x-trojan/",
        "description": "Dani Creus, Tyler Halfpop, Robert Falcone. (2016, September 26). Sofacy's 'Komplex' OS X Trojan. Retrieved July 8, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--f1951e8a-500e-4a26-8803-76d95c4554b4",
    "platform": "windows",
    "tid": "T1569.002",
    "technique": "Service Execution",
    "tactic": "execution",
    "datasources": "process-command-line-parameters|process-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse the Windows service control manager to execute malicious commands or payloads. The Windows service control manager (<code>services.exe</code>) is an interface to manage and manipulate services.(Citation: Microsoft Service Control Manager) The service control manager is accessible to users via GUI components as well as system utilities such as <code>sc.exe</code> and [Net](https://attack.mitre.org/software/S0039).<br /><br />[PsExec](https://attack.mitre.org/software/S0029) can also be used to execute commands or payloads via a temporary Windows service created through the service control manager API.(Citation: Russinovich Sysinternals)<br /><br />Adversaries may leverage these mechanisms to execute malicious content. This can be done by either executing a new or modified service. This technique is the execution used in conjunction with [Windows Service](https://attack.mitre.org/techniques/T1543/003) during service persistence or privilege escalation.<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft Service Control Manager",
        "url": "https://docs.microsoft.com/windows/win32/services/service-control-manager",
        "description": "Microsoft. (2018, May 31). Service Control Manager. Retrieved March 28, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Russinovich Sysinternals",
        "url": "https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx",
        "description": "Russinovich, M. (2014, May 2). Windows Sysinternals PsExec v2.11. Retrieved May 13, 2015.",
        "external_id": "none"
      }
    ]
  }
]
