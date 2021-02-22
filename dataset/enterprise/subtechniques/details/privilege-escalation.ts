export const PRIVILEGE_ESCALATION_SUBTECHNIQUE_DETAILS = [
  {
    "id": "attack-pattern--eb125d40-0b2d-41ac-a71a-3229241c2cd3",
    "platform": "windows",
    "tid": "T1037.001",
    "technique": "Logon Script (Windows)",
    "tactic": "privilege-escalation",
    "datasources": "process-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence. Windows allows logon scripts to be run whenever a specific user or group of users log into a system.(Citation: TechNet Logon Scripts) This is done via adding a path to a script to the <code>HKCU\\Environment\\UserInitMprLogonScript</code> Registry key.(Citation: Hexacorn Logon Scripts)<br /><br />Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary. <br /><br />",
    "technique_references": [
      {
        "source_name": "TechNet Logon Scripts",
        "url": "https://technet.microsoft.com/en-us/library/cc758918(v=ws.10).aspx",
        "description": "Microsoft. (2005, January 21). Creating logon scripts. Retrieved April 27, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Hexacorn Logon Scripts",
        "url": "http://www.hexacorn.com/blog/2014/11/14/beyond-good-ol-run-key-part-18/",
        "description": "Hexacorn. (2014, November 14). Beyond good ol’ Run key, Part 18. Retrieved November 15, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--43ba2b05-cf72-4b6c-8243-03a4aba41ee0",
    "platform": "macos",
    "tid": "T1037.002",
    "technique": "Logon Script (Mac)",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use macOS logon scripts automatically executed at logon initialization to establish persistence. macOS allows logon scripts (known as login hooks) to be executed whenever a specific user logs into a system. A login hook tells Mac OS X to execute a certain script when a user logs in, but unlike [Startup Items](https://attack.mitre.org/techniques/T1037/005), a login hook executes as the elevated root user.(Citation: creating login hook)<br /><br />Adversaries may use these login hooks to maintain persistence on a single system.(Citation: S1 macOs Persistence) Access to login hook scripts may allow an adversary to insert additional malicious code. There can only be one login hook at a time though and depending on the access configuration of the hooks, either local credentials or an administrator account may be necessary. <br /><br />",
    "technique_references": [
      {
        "source_name": "creating login hook",
        "url": "https://support.apple.com/de-at/HT2420",
        "description": "Apple. (2011, June 1). Mac OS X: Creating a login hook. Retrieved July 17, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "S1 macOs Persistence",
        "url": "https://www.sentinelone.com/blog/how-malware-persists-on-macos/",
        "description": "Stokes, P. (2019, July 17). How Malware Persists on macOS. Retrieved March 27, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--c63a348e-ffc2-486a-b9d9-d7f11ec54d99",
    "platform": "windows",
    "tid": "T1037.003",
    "technique": "Network Logon Script",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use network logon scripts automatically executed at logon initialization to establish persistence. Network logon scripts can be assigned using Active Directory or Group Policy Objects.(Citation: Petri Logon Script AD) These logon scripts run with the privileges of the user they are assigned to. Depending on the systems within the network, initializing one of these scripts could apply to more than one or potentially all systems.  <br /><br /> <br /><br />Adversaries may use these scripts to maintain persistence on a network. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.<br /><br />",
    "technique_references": [
      {
        "source_name": "Petri Logon Script AD",
        "url": "https://www.petri.com/setting-up-logon-script-through-active-directory-users-computers-windows-server-2008",
        "description": "Daniel Petri. (2009, January 8). Setting up a Logon Script through Active Directory Users and Computers in Windows Server 2008. Retrieved November 15, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--dca670cf-eeec-438f-8185-fd959d9ef211",
    "platform": "macos",
    "tid": "T1037.004",
    "technique": "Rc.common",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use rc.common automatically executed at boot initialization to establish persistence. During the boot process, macOS executes <code>source /etc/rc.common</code>, which is a shell script containing various utility functions. This file also defines routines for processing command-line arguments and for gathering system settings and is thus recommended to include in the start of Startup Item Scripts (Citation: Startup Items). In macOS and OS X, this is now a deprecated mechanism in favor of [Launch Agent](https://attack.mitre.org/techniques/T1543/001) and [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) but is currently still used.<br /><br />Adversaries can use the rc.common file as a way to hide code for persistence that will execute on each reboot as the root user. (Citation: Methods of Mac Malware Persistence)<br /><br />",
    "technique_references": [
      {
        "source_name": "Startup Items",
        "url": "https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/StartupItems.html",
        "description": "Apple. (2016, September 13). Startup Items. Retrieved July 11, 2017.",
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
    "id": "attack-pattern--c0dfe7b0-b873-4618-9ff8-53e31f70907f",
    "platform": "macos",
    "tid": "T1037.005",
    "technique": "Startup Items",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use startup items automatically executed at boot initialization to establish persistence. Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items. (Citation: Startup Items)<br /><br />This is technically a deprecated technology (superseded by [Launch Daemon](https://attack.mitre.org/techniques/T1543/004)), and thus the appropriate folder, <code>/Library/StartupItems</code> isn’t guaranteed to exist on the system by default, but does appear to exist by default on macOS Sierra. A startup item is a directory whose executable and configuration property list (plist), <code>StartupParameters.plist</code>, reside in the top-level directory. <br /><br />An adversary can create the appropriate folders/files in the StartupItems directory to register their own persistence mechanism (Citation: Methods of Mac Malware Persistence). Additionally, since StartupItems run during the bootup phase of macOS, they will run as the elevated root user.<br /><br />",
    "technique_references": [
      {
        "source_name": "Startup Items",
        "url": "https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/StartupItems.html",
        "description": "Apple. (2016, September 13). Startup Items. Retrieved July 11, 2017.",
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
    "id": "attack-pattern--6636bc83-0611-45a6-b74f-1f3daf635b8e",
    "platform": "linux",
    "tid": "T1053.001",
    "technique": "At (Linux)",
    "tactic": "privilege-escalation",
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
    "tactic": "privilege-escalation",
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
    "tactic": "privilege-escalation",
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
    "tactic": "privilege-escalation",
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
    "tactic": "privilege-escalation",
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
    "tactic": "privilege-escalation",
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
    "id": "attack-pattern--f4599aa0-4f85-4a32-80ea-fc39dc965945",
    "platform": "windows",
    "tid": "T1055.001",
    "technique": "Dynamic-link Library Injection",
    "tactic": "privilege-escalation",
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
    "technique_description": "Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges. DLL injection is a method of executing arbitrary code in the address space of a separate live process.  <br /><br />DLL injection is commonly performed by writing the path to a DLL in the virtual address space of the target process before loading the DLL by invoking a new thread. The write can be performed with native Windows API calls such as <code>VirtualAllocEx</code> and <code>WriteProcessMemory</code>, then invoked with <code>CreateRemoteThread</code> (which calls the <code>LoadLibrary</code> API responsible for loading the DLL). (Citation: Endgame Process Injection July 2017) <br /><br />Variations of this method such as reflective DLL injection (writing a self-mapping DLL into a process) and memory module (map DLL when writing into process) overcome the address relocation issue as well as the additional APIs to invoke execution (since these methods load and execute the files in memory by manually preforming the function of <code>LoadLibrary</code>).(Citation: Endgame HuntingNMemory June 2017)(Citation: Endgame Process Injection July 2017) <br /><br />Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via DLL injection may also evade detection from security products since the execution is masked under a legitimate process. <br /><br />",
    "technique_references": [
      {
        "source_name": "Endgame Process Injection July 2017",
        "url": "https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process",
        "description": "Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Endgame HuntingNMemory June 2017",
        "url": "https://www.endgame.com/blog/technical-blog/hunting-memory",
        "description": "Desimone, J. (2017, June 13). Hunting in Memory. Retrieved December 7, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--806a49c4-970d-43f9-9acc-ac0ee11e6662",
    "platform": "windows",
    "tid": "T1055.002",
    "technique": "Portable Executable Injection",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may inject portable executables (PE) into processes in order to evade process-based defenses as well as possibly elevate privileges. PE injection is a method of executing arbitrary code in the address space of a separate live process. <br /><br />PE injection is commonly performed by copying code (perhaps without a file on disk) into the virtual address space of the target process before invoking it via a new thread. The write can be performed with native Windows API calls such as <code>VirtualAllocEx</code> and <code>WriteProcessMemory</code>, then invoked with <code>CreateRemoteThread</code> or additional code (ex: shellcode). The displacement of the injected code does introduce the additional requirement for functionality to remap memory references. (Citation: Endgame Process Injection July 2017) <br /><br />Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via PE injection may also evade detection from security products since the execution is masked under a legitimate process. <br /><br />",
    "technique_references": [
      {
        "source_name": "Endgame Process Injection July 2017",
        "url": "https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process",
        "description": "Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--41d9846c-f6af-4302-a654-24bba2729bc6",
    "platform": "windows",
    "tid": "T1055.003",
    "technique": "Thread Execution Hijacking",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. Thread Execution Hijacking is a method of executing arbitrary code in the address space of a separate live process. <br /><br />Thread Execution Hijacking is commonly performed by suspending an existing process then unmapping/hollowing its memory, which can then be replaced with malicious code or the path to a DLL. A handle to an existing victim process is first created with native Windows API calls such as <code>OpenThread</code>. At this point the process can be suspended then written to, realigned to the injected code, and resumed via <code>SuspendThread </code>, <code>VirtualAllocEx</code>, <code>WriteProcessMemory</code>, <code>SetThreadContext</code>, then <code>ResumeThread</code> respectively.(Citation: Endgame Process Injection July 2017)<br /><br />This is very similar to [Process Hollowing](https://attack.mitre.org/techniques/T1055/012) but targets an existing process rather than creating a process in a suspended state.  <br /><br />Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via Thread Execution Hijacking may also evade detection from security products since the execution is masked under a legitimate process. <br /><br />",
    "technique_references": [
      {
        "source_name": "Endgame Process Injection July 2017",
        "url": "https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process",
        "description": "Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--7c0f17c9-1af6-4628-9cbd-9e45482dd605",
    "platform": "windows",
    "tid": "T1055.004",
    "technique": "Asynchronous Procedure Call",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may inject malicious code into processes via the asynchronous procedure call (APC) queue in order to evade process-based defenses as well as possibly elevate privileges. APC injection is a method of executing arbitrary code in the address space of a separate live process. <br /><br />APC injection is commonly performed by attaching malicious code to the APC Queue (Citation: Microsoft APC) of a process's thread. Queued APC functions are executed when the thread enters an alterable state.(Citation: Microsoft APC) A handle to an existing victim process is first created with native Windows API calls such as <code>OpenThread</code>. At this point <code>QueueUserAPC</code> can be used to invoke a function (such as <code>LoadLibrayA</code> pointing to a malicious DLL). <br /><br />A variation of APC injection, dubbed \"Early Bird injection\", involves creating a suspended process in which malicious code can be written and executed before the process' entry point (and potentially subsequent anti-malware hooks) via an APC. (Citation: CyberBit Early Bird Apr 2018) AtomBombing (Citation: ENSIL AtomBombing Oct 2016) is another variation that utilizes APCs to invoke malicious code previously written to the global atom table.(Citation: Microsoft Atom Table)<br /><br />Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via APC injection may also evade detection from security products since the execution is masked under a legitimate process. <br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft APC",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ms681951.aspx",
        "description": "Microsoft. (n.d.). Asynchronous Procedure Calls. Retrieved December 8, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "CyberBit Early Bird Apr 2018",
        "url": "https://www.cyberbit.com/blog/endpoint-security/new-early-bird-code-injection-technique-discovered/",
        "description": "Gavriel, H. & Erbesfeld, B. (2018, April 11). New ‘Early Bird’ Code Injection Technique Discovered. Retrieved May 24, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "ENSIL AtomBombing Oct 2016",
        "url": "https://blog.ensilo.com/atombombing-brand-new-code-injection-for-windows",
        "description": "Liberman, T. (2016, October 27). ATOMBOMBING: BRAND NEW CODE INJECTION FOR WINDOWS. Retrieved December 8, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Atom Table",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ms649053.aspx",
        "description": "Microsoft. (n.d.). About Atom Tables. Retrieved December 8, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Endgame Process Injection July 2017",
        "url": "https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process",
        "description": "Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--e49ee9d2-0d98-44ef-85e5-5d3100065744",
    "platform": "windows",
    "tid": "T1055.005",
    "technique": "Thread Local Storage",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may inject malicious code into processes via thread local storage (TLS) callbacks in order to evade process-based defenses as well as possibly elevate privileges. TLS callback injection is a method of executing arbitrary code in the address space of a separate live process. <br /><br />TLS callback injection involves manipulating pointers inside a portable executable (PE) to redirect a process to malicious code before reaching the code's legitimate entry point. TLS callbacks are normally used by the OS to setup and/or cleanup data used by threads. Manipulating TLS callbacks may be performed by allocating and writing to specific offsets within a process’ memory space using other [Process Injection](https://attack.mitre.org/techniques/T1055) techniques such as [Process Hollowing](https://attack.mitre.org/techniques/T1055/012).(Citation: FireEye TLS Nov 2017)<br /><br />Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via TLS callback injection may also evade detection from security products since the execution is masked under a legitimate process. <br /><br />",
    "technique_references": [
      {
        "source_name": "FireEye TLS Nov 2017",
        "url": "https://www.fireeye.com/blog/threat-research/2017/11/ursnif-variant-malicious-tls-callback-technique.html",
        "description": "Vaish, A. & Nemes, S. (2017, November 28). Newly Observed Ursnif Variant Employs Malicious TLS Callback Technique to Achieve Process Injection. Retrieved December 18, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Endgame Process Injection July 2017",
        "url": "https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process",
        "description": "Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ea016b56-ae0e-47fe-967a-cc0ad51af67f",
    "platform": "linux",
    "tid": "T1055.008",
    "technique": "Ptrace System Calls",
    "tactic": "privilege-escalation",
    "datasources": "process-monitoring|system-calls",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may inject malicious code into processes via ptrace (process trace) system calls in order to evade process-based defenses as well as possibly elevate privileges. Ptrace system call injection is a method of executing arbitrary code in the address space of a separate live process. <br /><br />Ptrace system call injection involves attaching to and modifying a running process. The ptrace system call enables a debugging process to observe and control another process (and each individual thread), including changing memory and register values.(Citation: PTRACE man) Ptrace system call injection is commonly performed by writing arbitrary code into a running process (ex: <code>malloc</code>) then invoking that memory with <code>PTRACE_SETREGS</code> to set the register containing the next instruction to execute. Ptrace system call injection can also be done with <code>PTRACE_POKETEXT</code>/<code>PTRACE_POKEDATA</code>, which copy data to a specific address in the target processes’ memory (ex: the current address of the next instruction). (Citation: PTRACE man)(Citation: Medium Ptrace JUL 2018) <br /><br />Ptrace system call injection may not be possible targeting processes with high-privileges, and on some system those that are non-child processes.(Citation: BH Linux Inject) <br /><br />Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via ptrace system call injection may also evade detection from security products since the execution is masked under a legitimate process. <br /><br />",
    "technique_references": [
      {
        "source_name": "PTRACE man",
        "url": "http://man7.org/linux/man-pages/man2/ptrace.2.html",
        "description": "Kerrisk, M. (2020, February 9). PTRACE(2) - Linux Programmer's Manual. Retrieved February 21, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Medium Ptrace JUL 2018",
        "url": "https://medium.com/@jain.sm/code-injection-in-running-process-using-ptrace-d3ea7191a4be",
        "description": "Jain, S. (2018, July 25). Code injection in running process using ptrace. Retrieved February 21, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "BH Linux Inject",
        "url": "https://github.com/gaffe23/linux-inject/blob/master/slides_BHArsenal2015.pdf",
        "description": "Colgan, T. (2015, August 15). Linux-Inject. Retrieved February 21, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "ArtOfMemoryForensics",
        "url": "none",
        "description": "Ligh, M.H. et al.. (2014, July). The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and Mac Memory. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "GNU Acct",
        "url": "https://www.gnu.org/software/acct/",
        "description": "GNU. (2010, February 5). The GNU Accounting Utilities. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "RHEL auditd",
        "url": "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing",
        "description": "Jahoda, M. et al.. (2017, March 14). redhat Security Guide - Chapter 7 - System Auditing. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Chokepoint preload rootkits",
        "url": "http://www.chokepoint.net/2014/02/detecting-userland-preload-rootkits.html",
        "description": "stderr. (2014, February 14). Detecting Userland Preload Rootkits. Retrieved December 20, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--d201d4cc-214d-4a74-a1ba-b3fa09fd4591",
    "platform": "linux",
    "tid": "T1055.009",
    "technique": "Proc Memory",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may inject malicious code into processes via the /proc filesystem in order to evade process-based defenses as well as possibly elevate privileges. Proc memory injection is a method of executing arbitrary code in the address space of a separate live process. <br /><br />Proc memory injection involves enumerating the memory of a process via the /proc filesystem (<code>/proc/[pid]</code>) then crafting a return-oriented programming (ROP) payload with available gadgets/instructions. Each running process has its own directory, which includes memory mappings. Proc memory injection is commonly performed by overwriting the target processes’ stack using memory mappings provided by the /proc filesystem. This information can be used to enumerate offsets (including the stack) and gadgets (or instructions within the program that can be used to build a malicious payload) otherwise hidden by process memory protections such as address space layout randomization (ASLR). Once enumerated, the target processes’ memory map within <code>/proc/[pid]/maps</code> can be overwritten using dd.(Citation: Uninformed Needle)(Citation: GDS Linux Injection)(Citation: DD Man) <br /><br />Other techniques such as [LD_PRELOAD](https://attack.mitre.org/techniques/T1574/006) may be used to populate a target process with more available gadgets. Similar to [Process Hollowing](https://attack.mitre.org/techniques/T1055/012), proc memory injection may target child processes (such as a backgrounded copy of sleep).(Citation: GDS Linux Injection) <br /><br />Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via proc memory injection may also evade detection from security products since the execution is masked under a legitimate process. <br /><br />",
    "technique_references": [
      {
        "source_name": "Uninformed Needle",
        "url": "http://hick.org/code/skape/papers/needle.txt",
        "description": "skape. (2003, January 19). Linux x86 run-time process manipulation. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "GDS Linux Injection",
        "url": "https://blog.gdssecurity.com/labs/2017/9/5/linux-based-inter-process-code-injection-without-ptrace2.html",
        "description": "McNamara, R. (2017, September 5). Linux Based Inter-Process Code Injection Without Ptrace(2). Retrieved February 21, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "DD Man",
        "url": "http://man7.org/linux/man-pages/man1/dd.1.html",
        "description": "Kerrisk, M. (2020, February 2). DD(1) User Commands. Retrieved February 21, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfa298",
    "platform": "windows",
    "tid": "T1055.011",
    "technique": "Extra Window Memory Injection",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may inject malicious code into process via Extra Window Memory (EWM) in order to evade process-based defenses as well as possibly elevate privileges. EWM injection is a method of executing arbitrary code in the address space of a separate live process. <br /><br />Before creating a window, graphical Windows-based processes must prescribe to or register a windows class, which stipulate appearance and behavior (via windows procedures, which are functions that handle input/output of data).(Citation: Microsoft Window Classes) Registration of new windows classes can include a request for up to 40 bytes of EWM to be appended to the allocated memory of each instance of that class. This EWM is intended to store data specific to that window and has specific application programming interface (API) functions to set and get its value. (Citation: Microsoft GetWindowLong function) (Citation: Microsoft SetWindowLong function)<br /><br />Although small, the EWM is large enough to store a 32-bit pointer and is often used to point to a windows procedure. Malware may possibly utilize this memory location in part of an attack chain that includes writing code to shared sections of the process’s memory, placing a pointer to the code in EWM, then invoking execution by returning execution control to the address in the process’s EWM.<br /><br />Execution granted through EWM injection may allow access to both the target process's memory and possibly elevated privileges. Writing payloads to shared sections also avoids the use of highly monitored API calls such as <code>WriteProcessMemory</code> and <code>CreateRemoteThread</code>.(Citation: Endgame Process Injection July 2017) More sophisticated malware samples may also potentially bypass protection mechanisms such as data execution prevention (DEP) by triggering a combination of windows procedures and other system functions that will rewrite the malicious payload inside an executable portion of the target process.  (Citation: MalwareTech Power Loader Aug 2013) (Citation: WeLiveSecurity Gapz and Redyms Mar 2013)<br /><br />Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via EWM injection may also evade detection from security products since the execution is masked under a legitimate process. <br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft Window Classes",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ms633574.aspx",
        "description": "Microsoft. (n.d.). About Window Classes. Retrieved December 16, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft GetWindowLong function",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ms633584.aspx",
        "description": "Microsoft. (n.d.). GetWindowLong function. Retrieved December 16, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft SetWindowLong function",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ms633591.aspx",
        "description": "Microsoft. (n.d.). SetWindowLong function. Retrieved December 16, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Endgame Process Injection July 2017",
        "url": "https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process",
        "description": "Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "MalwareTech Power Loader Aug 2013",
        "url": "https://www.malwaretech.com/2013/08/powerloader-injection-something-truly.html",
        "description": "MalwareTech. (2013, August 13). PowerLoader Injection – Something truly amazing. Retrieved December 16, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "WeLiveSecurity Gapz and Redyms Mar 2013",
        "url": "https://www.welivesecurity.com/2013/03/19/gapz-and-redyms-droppers-based-on-power-loader-code/",
        "description": "Matrosov, A. (2013, March 19). Gapz and Redyms droppers based on Power Loader code. Retrieved December 16, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft SendNotifyMessage function",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ms644953.aspx",
        "description": "Microsoft. (n.d.). SendNotifyMessage function. Retrieved December 16, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b200542e-e877-4395-875b-cf1a44537ca4",
    "platform": "windows",
    "tid": "T1055.012",
    "technique": "Process Hollowing",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. Process hollowing is a method of executing arbitrary code in the address space of a separate live process.  <br /><br />Process hollowing is commonly performed by creating a process in a suspended state then unmapping/hollowing its memory, which can then be replaced with malicious code. A victim process can be created with native Windows API calls such as <code>CreateProcess</code>, which includes a flag to suspend the processes primary thread. At this point the process can be unmapped using APIs calls such as <code>ZwUnmapViewOfSection</code> or <code>NtUnmapViewOfSection</code>  before being written to, realigned to the injected code, and resumed via <code>VirtualAllocEx</code>, <code>WriteProcessMemory</code>, <code>SetThreadContext</code>, then <code>ResumeThread</code> respectively.(Citation: Leitch Hollowing)(Citation: Endgame Process Injection July 2017)<br /><br />This is very similar to [Thread Local Storage](https://attack.mitre.org/techniques/T1055/005) but creates a new process rather than targeting an existing process. This behavior will likely not result in elevated privileges since the injected process was spawned from (and thus inherits the security context) of the injecting process. However, execution via process hollowing may also evade detection from security products since the execution is masked under a legitimate process. <br /><br />",
    "technique_references": [
      {
        "source_name": "Leitch Hollowing",
        "url": "http://www.autosectools.com/process-hollowing.pdf",
        "description": "Leitch, J. (n.d.). Process Hollowing. Retrieved November 12, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Endgame Process Injection July 2017",
        "url": "https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process",
        "description": "Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--7007935a-a8a7-4c0b-bd98-4e85be8ed197",
    "platform": "windows",
    "tid": "T1055.013",
    "technique": "Process Doppelgänging",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may inject malicious code into process via process doppelgänging in order to evade process-based defenses as well as possibly elevate privileges. Process doppelgänging is a method of executing arbitrary code in the address space of a separate live process. <br /><br />Windows Transactional NTFS (TxF) was introduced in Vista as a method to perform safe file operations. (Citation: Microsoft TxF) To ensure data integrity, TxF enables only one transacted handle to write to a file at a given time. Until the write handle transaction is terminated, all other handles are isolated from the writer and may only read the committed version of the file that existed at the time the handle was opened. (Citation: Microsoft Basic TxF Concepts) To avoid corruption, TxF performs an automatic rollback if the system or application fails during a write transaction. (Citation: Microsoft Where to use TxF)<br /><br />Although deprecated, the TxF application programming interface (API) is still enabled as of Windows 10. (Citation: BlackHat Process Doppelgänging Dec 2017)<br /><br />Adversaries may abuse TxF to a perform a file-less variation of [Process Injection](https://attack.mitre.org/techniques/T1055). Similar to [Process Hollowing](https://attack.mitre.org/techniques/T1093), process doppelgänging involves replacing the memory of a legitimate process, enabling the veiled execution of malicious code that may evade defenses and detection. Process doppelgänging's use of TxF also avoids the use of highly-monitored API functions such as <code>NtUnmapViewOfSection</code>, <code>VirtualProtectEx</code>, and <code>SetThreadContext</code>. (Citation: BlackHat Process Doppelgänging Dec 2017)<br /><br />Process Doppelgänging is implemented in 4 steps (Citation: BlackHat Process Doppelgänging Dec 2017):<br /><br />* Transact – Create a TxF transaction using a legitimate executable then overwrite the file with malicious code. These changes will be isolated and only visible within the context of the transaction.<br /><br />* Load – Create a shared section of memory and load the malicious executable.<br /><br />* Rollback – Undo changes to original executable, effectively removing malicious code from the file system.<br /><br />* Animate – Create a process from the tainted section of memory and initiate execution.<br /><br />This behavior will likely not result in elevated privileges since the injected process was spawned from (and thus inherits the security context) of the injecting process. However, execution via process doppelgänging may evade detection from security products since the execution is masked under a legitimate process. <br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft TxF",
        "url": "https://msdn.microsoft.com/library/windows/desktop/bb968806.aspx",
        "description": "Microsoft. (n.d.). Transactional NTFS (TxF). Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Basic TxF Concepts",
        "url": "https://msdn.microsoft.com/library/windows/desktop/dd979526.aspx",
        "description": "Microsoft. (n.d.). Basic TxF Concepts. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Where to use TxF",
        "url": "https://msdn.microsoft.com/library/windows/desktop/aa365738.aspx",
        "description": "Microsoft. (n.d.). When to Use Transactional NTFS. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "BlackHat Process Doppelgänging Dec 2017",
        "url": "https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf",
        "description": "Liberman, T. & Kogan, E. (2017, December 7). Lost in Transaction: Process Doppelgänging. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "hasherezade Process Doppelgänging Dec 2017",
        "url": "https://hshrzd.wordpress.com/2017/12/18/process-doppelganging-a-new-way-to-impersonate-a-process/",
        "description": "hasherezade. (2017, December 18). Process Doppelgänging – a new way to impersonate a process. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft PsSetCreateProcessNotifyRoutine routine",
        "url": "https://msdn.microsoft.com/library/windows/hardware/ff559951.aspx",
        "description": "Microsoft. (n.d.). PsSetCreateProcessNotifyRoutine routine. Retrieved December 20, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--98be40f2-c86b-4ade-b6fc-4964932040e5",
    "platform": "linux",
    "tid": "T1055.014",
    "technique": "VDSO Hijacking",
    "tactic": "privilege-escalation",
    "datasources": "process-monitoring|system-calls",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may inject malicious code into processes via VDSO hijacking in order to evade process-based defenses as well as possibly elevate privileges. Virtual dynamic shared object (vdso) hijacking is a method of executing arbitrary code in the address space of a separate live process. <br /><br />VDSO hijacking involves redirecting calls to dynamically linked shared libraries. Memory protections may prevent writing executable code to a process via [Ptrace System Calls](https://attack.mitre.org/techniques/T1055/008). However, an adversary may hijack the syscall interface code stubs mapped into a process from the vdso shared object to execute syscalls to open and map a malicious shared object. This code can then be invoked by redirecting the execution flow of the process via patched memory address references stored in a process' global offset table (which store absolute addresses of mapped library functions).(Citation: ELF Injection May 2009) (Citation: Backtrace VDSO) (Citation: VDSO Aug 2005) (Citation: Syscall 2014)<br /><br />Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via VDSO hijacking may also evade detection from security products since the execution is masked under a legitimate process.  <br /><br />",
    "technique_references": [
      {
        "source_name": "ELF Injection May 2009",
        "url": "https://web.archive.org/web/20150711051625/http://vxer.org/lib/vrn00.html",
        "description": "O'Neill, R. (2009, May). Modern Day ELF Runtime infection via GOT poisoning. Retrieved March 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Backtrace VDSO",
        "url": "https://backtrace.io/blog/backtrace/elf-shared-library-injection-forensics/",
        "description": "backtrace. (2016, April 22). ELF SHARED LIBRARY INJECTION FORENSICS. Retrieved June 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "VDSO Aug 2005",
        "url": "https://web.archive.org/web/20051013084246/http://www.trilithium.com/johan/2005/08/linux-gate/",
        "description": "Petersson, J. (2005, August 14). What is linux-gate.so.1?. Retrieved June 16, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Syscall 2014",
        "url": "https://lwn.net/Articles/604515/",
        "description": "Drysdale, D. (2014, July 16). Anatomy of a system call, part 2. Retrieved June 16, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "ArtOfMemoryForensics",
        "url": "none",
        "description": "Ligh, M.H. et al.. (2014, July). The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and Mac Memory. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "GNU Acct",
        "url": "https://www.gnu.org/software/acct/",
        "description": "GNU. (2010, February 5). The GNU Accounting Utilities. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "RHEL auditd",
        "url": "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing",
        "description": "Jahoda, M. et al.. (2017, March 14). redhat Security Guide - Chapter 7 - System Auditing. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Chokepoint preload rootkits",
        "url": "http://www.chokepoint.net/2014/02/detecting-userland-preload-rootkits.html",
        "description": "stderr. (2014, February 14). Detecting Userland Preload Rootkits. Retrieved December 20, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--6151cbea-819b-455a-9fa6-99a1cc58797d",
    "platform": "linux|macos|windows|aws|gcp|azure|office-365|azure-ad|saas",
    "tid": "T1078.001",
    "technique": "Default Accounts",
    "tactic": "privilege-escalation",
    "datasources": "authentication-logs|aws-cloudtrail-logs|process-monitoring|stackdriver-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems or default factory/provider set accounts on other types of systems, software, or devices.(Citation: Microsoft Local Accounts Feb 2019)<br /><br />Default accounts are not limited to client machines, rather also include accounts that are preset for equipment such as network devices and computer applications whether they are internal, open source, or commercial. Appliances that come preset with a username and password combination pose a serious threat to organizations that do not change it post installation, as they are easy targets for an adversary. Similarly, adversaries may also utilize publicly disclosed or stolen [Private Keys](https://attack.mitre.org/techniques/T1552/004) or credential materials to legitimately connect to remote environments via [Remote Services](https://attack.mitre.org/techniques/T1021).(Citation: Metasploit SSH Module)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/70.html",
        "description": "none",
        "external_id": "CAPEC-70"
      },
      {
        "source_name": "Microsoft Local Accounts Feb 2019",
        "url": "https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts",
        "description": "Microsoft. (2018, December 9). Local Accounts. Retrieved February 11, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Metasploit SSH Module",
        "url": "https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/linux/ssh",
        "description": "undefined. (n.d.). Retrieved April 12, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--c3d4bdd9-2cfe-4a80-9d0c-07a29ecdce8f",
    "platform": "linux|macos|windows",
    "tid": "T1078.002",
    "technique": "Domain Accounts",
    "tactic": "privilege-escalation",
    "datasources": "authentication-logs|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. (Citation: TechNet Credential Theft) Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services.(Citation: Microsoft AD Accounts)<br /><br />Adversaries may compromise domain accounts, some with a high level of privileges, through various means such as [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) or password reuse, allowing access to privileged resources of the domain.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/560.html",
        "description": "none",
        "external_id": "CAPEC-560"
      },
      {
        "source_name": "TechNet Credential Theft",
        "url": "https://technet.microsoft.com/en-us/library/dn535501.aspx",
        "description": "Microsoft. (2016, April 15). Attractive Accounts for Credential Theft. Retrieved June 3, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft AD Accounts",
        "url": "https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-accounts",
        "description": "Microsoft. (2019, August 23). Active Directory Accounts. Retrieved March 13, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Audit Policy",
        "url": "https://technet.microsoft.com/en-us/library/dn487457.aspx",
        "description": "Microsoft. (2016, April 15). Audit Policy Recommendations. Retrieved June 3, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--fdc47f44-dd32-4b99-af5f-209f556f63c2",
    "platform": "linux|macos|windows",
    "tid": "T1078.003",
    "technique": "Local Accounts",
    "tactic": "privilege-escalation",
    "datasources": "authentication-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.<br /><br />Local Accounts may also be abused to elevate privileges and harvest credentials through [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). Password reuse may allow the abuse of local accounts across a set of machines on a network for the purposes of Privilege Escalation and Lateral Movement. <br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--f232fa7a-025c-4d43-abc7-318e81a73d65",
    "platform": "aws|gcp|azure|saas|azure-ad|office-365",
    "tid": "T1078.004",
    "technique": "Cloud Accounts",
    "tactic": "privilege-escalation",
    "datasources": "authentication-logs|aws-cloudtrail-logs|azure-activity-logs|stackdriver-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may obtain and abuse credentials of a cloud account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application. In some cases, cloud accounts may be federated with traditional identity management system, such as Window Active Directory. (Citation: AWS Identity Federation)(Citation: Google Federating GC)(Citation: Microsoft Deploying AD Federation)<br /><br />Compromised credentials for cloud accounts can be used to harvest sensitive data from online storage accounts and databases. Access to cloud accounts can also be abused to gain Initial Access to a network by abusing a [Trusted Relationship](https://attack.mitre.org/techniques/T1199). Similar to [Domain Accounts](https://attack.mitre.org/techniques/T1078/002), compromise of federated cloud accounts may allow adversaries to more easily move laterally within an environment.<br /><br />",
    "technique_references": [
      {
        "source_name": "AWS Identity Federation",
        "url": "https://aws.amazon.com/identity/federation/",
        "description": "Amazon. (n.d.). Identity Federation in AWS. Retrieved March 13, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Google Federating GC",
        "url": "https://cloud.google.com/solutions/federating-gcp-with-active-directory-introduction",
        "description": "Google. (n.d.). Federating Google Cloud with Active Directory. Retrieved March 13, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Deploying AD Federation",
        "url": "https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/how-to-connect-fed-azure-adfs",
        "description": "Microsoft. (n.d.). Deploying Active Directory Federation Services in Azure. Retrieved March 13, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--86850eff-2729-40c3-b85e-c4af26da4a2d",
    "platform": "windows",
    "tid": "T1134.001",
    "technique": "Token Impersonation/Theft",
    "tactic": "privilege-escalation",
    "datasources": "access-tokens|api-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may duplicate then impersonate another user's token to escalate privileges and bypass access controls. An adversary can create a new access token that duplicates an existing token using <code>DuplicateToken(Ex)</code>. The token can then be used with <code>ImpersonateLoggedOnUser</code> to allow the calling thread to impersonate a logged on user's security context, or with <code>SetThreadToken</code> to assign the impersonated token to a thread.<br /><br />An adversary may do this when they have a specific, existing process they want to assign the new token to. For example, this may be useful for when the target user has a non-network logon session on the system.<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft Command-line Logging",
        "url": "https://technet.microsoft.com/en-us/windows-server-docs/identity/ad-ds/manage/component-updates/command-line-process-auditing",
        "description": "Mathers, B. (2017, March 7). Command line process auditing. Retrieved April 21, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--677569f9-a8b0-459e-ab24-7f18091fa7bf",
    "platform": "windows",
    "tid": "T1134.002",
    "technique": "Create Process with Token",
    "tactic": "privilege-escalation",
    "datasources": "access-tokens|api-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may create a new process with a duplicated token to escalate privileges and bypass access controls. An adversary can duplicate a desired access token with <code>DuplicateToken(Ex)</code> and use it with <code>CreateProcessWithTokenW</code> to create a new process running under the security context of the impersonated user. This is useful for creating a new process under the security context of a different user.<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft Command-line Logging",
        "url": "https://technet.microsoft.com/en-us/windows-server-docs/identity/ad-ds/manage/component-updates/command-line-process-auditing",
        "description": "Mathers, B. (2017, March 7). Command line process auditing. Retrieved April 21, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--8cdeb020-e31e-4f88-a582-f53dcfbda819",
    "platform": "windows",
    "tid": "T1134.003",
    "technique": "Make and Impersonate Token",
    "tactic": "privilege-escalation",
    "datasources": "access-tokens|api-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may make and impersonate tokens to escalate privileges and bypass access controls. If an adversary has a username and password but the user is not logged onto the system, the adversary can then create a logon session for the user using the <code>LogonUser</code> function. The function will return a copy of the new session's access token and the adversary can use <code>SetThreadToken</code> to assign the token to a thread.<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft Command-line Logging",
        "url": "https://technet.microsoft.com/en-us/windows-server-docs/identity/ad-ds/manage/component-updates/command-line-process-auditing",
        "description": "Mathers, B. (2017, March 7). Command line process auditing. Retrieved April 21, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--93591901-3172-4e94-abf8-6034ab26f44a",
    "platform": "windows",
    "tid": "T1134.004",
    "technique": "Parent PID Spoofing",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|process-monitoring|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges. New processes are typically spawned directly from their parent, or calling, process unless explicitly specified. One way of explicitly assigning the PPID of a new process is via the <code>CreateProcess</code> API call, which supports a parameter that defines the PPID to use.(Citation: DidierStevens SelectMyParent Nov 2009) This functionality is used by Windows features such as User Account Control (UAC) to correctly set the PPID after a requested elevated process is spawned by SYSTEM (typically via <code>svchost.exe</code> or <code>consent.exe</code>) rather than the current user context.(Citation: Microsoft UAC Nov 2018)<br /><br />Adversaries may abuse these mechanisms to evade defenses, such as those blocking processes spawning directly from Office documents, and analysis targeting unusual/potentially malicious parent-child process relationships, such as spoofing the PPID of [PowerShell](https://attack.mitre.org/techniques/T1086)/[Rundll32](https://attack.mitre.org/techniques/T1085) to be <code>explorer.exe</code> rather than an Office document delivered as part of [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001).(Citation: CounterCept PPID Spoofing Dec 2018) This spoofing could be executed via [Visual Basic](https://attack.mitre.org/techniques/T1059/005) within a malicious Office document or any code that can perform [Native API](https://attack.mitre.org/techniques/T1106).(Citation: CTD PPID Spoofing Macro Mar 2019)(Citation: CounterCept PPID Spoofing Dec 2018)<br /><br />Explicitly assigning the PPID may also enable elevated privileges given appropriate access rights to the parent process. For example, an adversary in a privileged user context (i.e. administrator) may spawn a new process and assign the parent as a process running as SYSTEM (such as <code>lsass.exe</code>), causing the new process to be elevated via the inherited access token.(Citation: XPNSec PPID Nov 2017)<br /><br />",
    "technique_references": [
      {
        "source_name": "DidierStevens SelectMyParent Nov 2009",
        "url": "https://blog.didierstevens.com/2009/11/22/quickpost-selectmyparent-or-playing-with-the-windows-process-tree/",
        "description": "Stevens, D. (2009, November 22). Quickpost: SelectMyParent or Playing With the Windows Process Tree. Retrieved June 3, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft UAC Nov 2018",
        "url": "https://docs.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works",
        "description": "Montemayor, D. et al.. (2018, November 15). How User Account Control works. Retrieved June 3, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "CounterCept PPID Spoofing Dec 2018",
        "url": "https://www.countercept.com/blog/detecting-parent-pid-spoofing/",
        "description": "Loh, I. (2018, December 21). Detecting Parent PID Spoofing. Retrieved June 3, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "CTD PPID Spoofing Macro Mar 2019",
        "url": "https://blog.christophetd.fr/building-an-office-macro-to-spoof-process-parent-and-command-line/",
        "description": "Tafani-Dereeper, C. (2019, March 12). Building an Office macro to spoof parent processes and command line arguments. Retrieved June 3, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "XPNSec PPID Nov 2017",
        "url": "https://blog.xpnsec.com/becoming-system/",
        "description": "Chester, A. (2017, November 20). Alternative methods of becoming SYSTEM. Retrieved June 4, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Process Creation Flags May 2018",
        "url": "https://docs.microsoft.com/windows/desktop/ProcThread/process-creation-flags",
        "description": "Schofield, M. & Satran, M. (2018, May 30). Process Creation Flags. Retrieved June 4, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Secuirtyinbits Ataware3 May 2019",
        "url": "https://www.securityinbits.com/malware-analysis/parent-pid-spoofing-stage-2-ataware-ransomware-part-3",
        "description": "Secuirtyinbits . (2019, May 14). Parent PID Spoofing (Stage 2) Ataware Ransomware Part 3. Retrieved June 6, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b7dc639b-24cd-482d-a7f1-8897eda21023",
    "platform": "windows",
    "tid": "T1134.005",
    "technique": "SID-History Injection",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|authentication-logs|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use SID-History Injection to escalate privileges and bypass access controls. The Windows security identifier (SID) is a unique value that identifies a user or group account. SIDs are used by Windows security in both security descriptors and access tokens. (Citation: Microsoft SID) An account can hold additional SIDs in the SID-History Active Directory attribute (Citation: Microsoft SID-History Attribute), allowing inter-operable account migration between domains (e.g., all values in SID-History are included in access tokens).<br /><br />With Domain Administrator (or equivalent) rights, harvested or well-known SID values (Citation: Microsoft Well Known SIDs Jun 2017) may be inserted into SID-History to enable impersonation of arbitrary users/groups such as Enterprise Administrators. This manipulation may result in elevated access to local resources and/or access to otherwise inaccessible domains via lateral movement techniques such as [Remote Services](https://attack.mitre.org/techniques/T1021), [Windows Admin Shares](https://attack.mitre.org/techniques/T1077), or [Windows Remote Management](https://attack.mitre.org/techniques/T1028).<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft SID",
        "url": "https://msdn.microsoft.com/library/windows/desktop/aa379571.aspx",
        "description": "Microsoft. (n.d.). Security Identifiers. Retrieved November 30, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft SID-History Attribute",
        "url": "https://msdn.microsoft.com/library/ms679833.aspx",
        "description": "Microsoft. (n.d.). Active Directory Schema - SID-History attribute. Retrieved November 30, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Well Known SIDs Jun 2017",
        "url": "https://support.microsoft.com/help/243330/well-known-security-identifiers-in-windows-operating-systems",
        "description": "Microsoft. (2017, June 23). Well-known security identifiers in Windows operating systems. Retrieved November 30, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Get-ADUser",
        "url": "https://technet.microsoft.com/library/ee617241.aspx",
        "description": "Microsoft. (n.d.). Active Directory Cmdlets - Get-ADUser. Retrieved November 30, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "AdSecurity SID History Sept 2015",
        "url": "https://adsecurity.org/?p=1772",
        "description": "Metcalf, S. (2015, September 19). Sneaky Active Directory Persistence #14: SID History. Retrieved November 30, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft DsAddSidHistory",
        "url": "https://msdn.microsoft.com/library/ms677982.aspx",
        "description": "Microsoft. (n.d.). Using DsAddSidHistory. Retrieved November 30, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--5d2be8b9-d24c-4e98-83bf-2f5f79477163",
    "platform": "windows",
    "tid": "T1484.001",
    "technique": "Group Policy Modification",
    "tactic": "privilege-escalation",
    "datasources": "windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may modify Group Policy Objects (GPOs) to subvert the intended discretionary access controls for a domain, usually with the intention of escalating privileges on the domain. Group policy allows for centralized management of user and computer settings in Active Directory (AD). GPOs are containers for group policy settings made up of files stored within a predicable network path <code>\\\\&lt;DOMAIN&gt;\\SYSVOL\\&lt;DOMAIN&gt;\\Policies\\</code>.(Citation: TechNet Group Policy Basics)(Citation: ADSecurity GPO Persistence 2016) <br /><br />Like other objects in AD, GPOs have access controls associated with them. By default all user accounts in the domain have permission to read GPOs. It is possible to delegate GPO access control permissions, e.g. write access, to specific users or groups in the domain.<br /><br />Malicious GPO modifications can be used to implement many other malicious behaviors such as [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053), [Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001), [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105), [Create Account](https://attack.mitre.org/techniques/T1136), [Service Execution](https://attack.mitre.org/techniques/T1035),  and more.(Citation: ADSecurity GPO Persistence 2016)(Citation: Wald0 Guide to GPOs)(Citation: Harmj0y Abusing GPO Permissions)(Citation: Mandiant M Trends 2016)(Citation: Microsoft Hacking Team Breach) Since GPOs can control so many user and machine settings in the AD environment, there are a great number of potential attacks that can stem from this GPO abuse.(Citation: Wald0 Guide to GPOs)<br /><br />For example, publicly available scripts such as <code>New-GPOImmediateTask</code> can be leveraged to automate the creation of a malicious [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) by modifying GPO settings, in this case modifying <code>&lt;GPO_PATH&gt;\\Machine\\Preferences\\ScheduledTasks\\ScheduledTasks.xml</code>.(Citation: Wald0 Guide to GPOs)(Citation: Harmj0y Abusing GPO Permissions) In some cases an adversary might modify specific user rights like SeEnableDelegationPrivilege, set in <code>&lt;GPO_PATH&gt;\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf</code>, to achieve a subtle AD backdoor with complete control of the domain because the user account under the adversary's control would then be able to modify GPOs.(Citation: Harmj0y SeEnableDelegationPrivilege Right)<br /><br />",
    "technique_references": [
      {
        "source_name": "TechNet Group Policy Basics",
        "url": "https://blogs.technet.microsoft.com/musings_of_a_technical_tam/2012/02/13/group-policy-basics-part-1-understanding-the-structure-of-a-group-policy-object/",
        "description": "srachui. (2012, February 13). Group Policy Basics – Part 1: Understanding the Structure of a Group Policy Object. Retrieved March 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "ADSecurity GPO Persistence 2016",
        "url": "https://adsecurity.org/?p=2716",
        "description": "Metcalf, S. (2016, March 14). Sneaky Active Directory Persistence #17: Group Policy. Retrieved March 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Wald0 Guide to GPOs",
        "url": "https://wald0.com/?p=179",
        "description": "Robbins, A. (2018, April 2). A Red Teamer’s Guide to GPOs and OUs. Retrieved March 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Harmj0y Abusing GPO Permissions",
        "url": "http://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/",
        "description": "Schroeder, W. (2016, March 17). Abusing GPO Permissions. Retrieved March 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Mandiant M Trends 2016",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/current-threats/pdfs/rpt-mtrends-2016.pdf",
        "description": "Mandiant. (2016, February 25). Mandiant M-Trends 2016. Retrieved March 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Hacking Team Breach",
        "url": "https://www.microsoft.com/security/blog/2016/06/01/hacking-team-breach-a-cyber-jurassic-park/",
        "description": "Microsoft Secure Team. (2016, June 1). Hacking Team Breach: A Cyber Jurassic Park. Retrieved March 5, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Harmj0y SeEnableDelegationPrivilege Right",
        "url": "http://www.harmj0y.net/blog/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/",
        "description": "Schroeder, W. (2017, January 10). The Most Dangerous User Right You (Probably) Have Never Heard Of. Retrieved March 5, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--24769ab5-14bd-4f4e-a752-cfb185da53ee",
    "platform": "windows|azure-ad",
    "tid": "T1484.002",
    "technique": "Domain Trust Modification",
    "tactic": "privilege-escalation",
    "datasources": "azure-activity-logs|powershell-logs|windows-event-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may add new domain trusts or modify the properties of existing domain trusts to evade defenses and/or elevate privileges. Domain trust details, such as whether or not a domain is federated, allow authentication and authorization properties to apply between domains for the purpose of accessing shared resources.(Citation: Microsoft - Azure AD Federation) These trust objects may include accounts, credentials, and other authentication material applied to servers, tokens, and domains.<br /><br />Manipulating the domain trusts may allow an adversary to escalate privileges and/or evade defenses by modifying settings to add objects which they control. For example, this may be used to forge [SAML Tokens](https://attack.mitre.org/techniques/T1606/002), without the need to compromise the signing certificate to forge new credentials. Instead, an adversary can manipulate domain trusts to add their own signing certificate.<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft - Azure AD Federation",
        "url": "https://docs.microsoft.com/en-us/azure/active-directory/hybrid/whatis-fed",
        "description": "Microsoft. (2018, November 28). What is federation with Azure AD?. Retrieved December 30, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft - Azure Sentinel ADFSDomainTrustMods",
        "url": "https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ADFSDomainTrustMods.yaml",
        "description": "Microsoft. (2020, December). Azure Sentinel Detections. Retrieved December 30, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Sygnia Golden SAML",
        "url": "https://www.sygnia.co/golden-saml-advisory",
        "description": "Sygnia. (2020, December). Detection and Hunting of Golden SAML Attack. Retrieved January 6, 2021.",
        "external_id": "none"
      },
      {
        "source_name": "CISA SolarWinds Cloud Detection",
        "url": "https://us-cert.cisa.gov/ncas/alerts/aa21-008a",
        "description": "CISA. (2021, January 8). Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments. Retrieved January 8, 2021.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft - Update or Repair Federated domain",
        "url": "https://docs.microsoft.com/en-us/office365/troubleshoot/active-directory/update-federated-domain-office-365",
        "description": "Microsoft. (2020, September 14). Update or repair the settings of a federated domain in Office 365, Azure, or Intune. Retrieved December 30, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--d10cbd34-42e3-45c0-84d2-535a09849584",
    "platform": "macos",
    "tid": "T1543.001",
    "technique": "Launch Agent",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may create or modify launch agents to repeatedly execute malicious payloads as part of persistence. Per Apple’s developer documentation, when a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the property list (plist) files found in <code>/System/Library/LaunchAgents</code>, <code>/Library/LaunchAgents</code>, and <code>$HOME/Library/LaunchAgents</code> (Citation: AppleDocs Launch Agent Daemons) (Citation: OSX Keydnap malware) (Citation: Antiquated Mac Malware). These launch agents have property list files which point to the executables that will be launched (Citation: OSX.Dok Malware).<br /><br /> <br /><br />Adversaries may install a new launch agent that can be configured to execute at login by using launchd or launchctl to load a plist into the appropriate directories  (Citation: Sofacy Komplex Trojan)  (Citation: Methods of Mac Malware Persistence). The agent name may be disguised by using a name from a related operating system or benign software. Launch Agents are created with user level privileges and are executed with the privileges of the user when they log in (Citation: OSX Malware Detection) (Citation: OceanLotus for OS X). They can be set up to execute when a specific user logs in (in the specific user’s directory structure) or when any user logs in (which requires administrator privileges).<br /><br />",
    "technique_references": [
      {
        "source_name": "AppleDocs Launch Agent Daemons",
        "url": "https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html",
        "description": "Apple. (n.d.). Creating Launch Daemons and Agents. Retrieved July 10, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "OSX Keydnap malware",
        "url": "https://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-hungry-credentials/",
        "description": "Marc-Etienne M.Leveille. (2016, July 6). New OSX/Keydnap malware is hungry for credentials. Retrieved July 3, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Antiquated Mac Malware",
        "url": "https://blog.malwarebytes.com/threat-analysis/2017/01/new-mac-backdoor-using-antiquated-code/",
        "description": "Thomas Reed. (2017, January 18). New Mac backdoor using antiquated code. Retrieved July 5, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "OSX.Dok Malware",
        "url": "https://blog.malwarebytes.com/threat-analysis/2017/04/new-osx-dok-malware-intercepts-web-traffic/",
        "description": "Thomas Reed. (2017, July 7). New OSX.Dok malware intercepts web traffic. Retrieved July 10, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Sofacy Komplex Trojan",
        "url": "https://researchcenter.paloaltonetworks.com/2016/09/unit42-sofacys-komplex-os-x-trojan/",
        "description": "Dani Creus, Tyler Halfpop, Robert Falcone. (2016, September 26). Sofacy's 'Komplex' OS X Trojan. Retrieved July 8, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Methods of Mac Malware Persistence",
        "url": "https://www.virusbulletin.com/uploads/pdf/conference/vb2014/VB2014-Wardle.pdf",
        "description": "Patrick Wardle. (2014, September). Methods of Malware Persistence on Mac OS X. Retrieved July 5, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "OSX Malware Detection",
        "url": "https://www.synack.com/wp-content/uploads/2016/03/RSA_OSX_Malware.pdf",
        "description": "Patrick Wardle. (2016, February 29). Let's Play Doctor: Practical OS X Malware Detection & Analysis. Retrieved July 10, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "OceanLotus for OS X",
        "url": "https://www.alienvault.com/blogs/labs-research/oceanlotus-for-os-x-an-application-bundle-pretending-to-be-an-adobe-flash-update",
        "description": "Eddie Lee. (2016, February 17). OceanLotus for OS X - an Application Bundle Pretending to be an Adobe Flash Update. Retrieved July 5, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--dfefe2ed-4389-4318-8762-f0272b350a1b",
    "platform": "linux",
    "tid": "T1543.002",
    "technique": "Systemd Service",
    "tactic": "privilege-escalation",
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
    "technique_description": "Adversaries may create or modify systemd services to repeatedly execute malicious payloads as part of persistence. The systemd service manager is commonly used for managing background daemon processes (also known as services) and other system resources.(Citation: Linux man-pages: systemd January 2014)(Citation: Freedesktop.org Linux systemd 29SEP2018) Systemd is the default initialization (init) system on many Linux distributions starting with Debian 8, Ubuntu 15.04, CentOS 7, RHEL 7, Fedora 15, and replaces legacy init systems including SysVinit and Upstart while remaining backwards compatible with the aforementioned init systems.<br /><br />Systemd utilizes configuration files known as service units to control how services boot and under what conditions. By default, these unit files are stored in the <code>/etc/systemd/system</code> and <code>/usr/lib/systemd/system</code> directories and have the file extension <code>.service</code>. Each service unit file may contain numerous directives that can execute system commands:<br /><br />* ExecStart, ExecStartPre, and ExecStartPost directives cover execution of commands when a services is started manually by 'systemctl' or on system start if the service is set to automatically start. <br /><br />* ExecReload directive covers when a service restarts. <br /><br />* ExecStop and ExecStopPost directives cover when a service is stopped or manually by 'systemctl'.<br /><br />Adversaries have used systemd functionality to establish persistent access to victim systems by creating and/or modifying service unit files that cause systemd to execute malicious commands at system boot.(Citation: Anomali Rocke March 2019)<br /><br />While adversaries typically require root privileges to create/modify service unit files in the <code>/etc/systemd/system</code> and <code>/usr/lib/systemd/system</code> directories, low privilege users can create/modify service unit files in directories such as <code>~/.config/systemd/user/</code> to achieve user-level persistence.(Citation: Rapid7 Service Persistence 22JUNE2016)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/550.html",
        "description": "none",
        "external_id": "CAPEC-550"
      },
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/551.html",
        "description": "none",
        "external_id": "CAPEC-551"
      },
      {
        "source_name": "Linux man-pages: systemd January 2014",
        "url": "http://man7.org/linux/man-pages/man1/systemd.1.html",
        "description": "Linux man-pages. (2014, January). systemd(1) - Linux manual page. Retrieved April 23, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Freedesktop.org Linux systemd 29SEP2018",
        "url": "https://www.freedesktop.org/wiki/Software/systemd/",
        "description": "Freedesktop.org. (2018, September 29). systemd System and Service Manager. Retrieved April 23, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Anomali Rocke March 2019",
        "url": "https://www.anomali.com/blog/rocke-evolves-its-arsenal-with-a-new-malware-family-written-in-golang",
        "description": "Anomali Labs. (2019, March 15). Rocke Evolves Its Arsenal With a New Malware Family Written in Golang. Retrieved April 24, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Rapid7 Service Persistence 22JUNE2016",
        "url": "https://www.rapid7.com/db/modules/exploit/linux/local/service_persistence",
        "description": "Rapid7. (2016, June 22). Service Persistence. Retrieved April 23, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--2959d63f-73fd-46a1-abd2-109d7dcede32",
    "platform": "windows",
    "tid": "T1543.003",
    "technique": "Windows Service",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|file-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions.(Citation: TechNet Services) Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Windows Registry. Service configurations can be modified using utilities such as sc.exe and [Reg](https://attack.mitre.org/software/S0075). <br /><br />Adversaries may install a new service or modify an existing service by using system utilities to interact with services, by directly modifying the Registry, or by using custom tools to interact with the Windows API. Adversaries may configure services to execute at startup in order to persist on a system.<br /><br />An adversary may also incorporate [Masquerading](https://attack.mitre.org/techniques/T1036) by using a service name from a related operating system or benign software, or by modifying existing services to make detection analysis more challenging. Modifying existing services may interrupt their functionality or may enable services that are disabled or otherwise not commonly used. <br /><br />Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges from administrator to SYSTEM. Adversaries may also directly start services through [Service Execution](https://attack.mitre.org/techniques/T1569/002). <br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/478.html",
        "description": "none",
        "external_id": "CAPEC-478"
      },
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/550.html",
        "description": "none",
        "external_id": "CAPEC-550"
      },
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/551.html",
        "description": "none",
        "external_id": "CAPEC-551"
      },
      {
        "source_name": "TechNet Services",
        "url": "https://technet.microsoft.com/en-us/library/cc772408.aspx",
        "description": "Microsoft. (n.d.). Services. Retrieved June 7, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Autoruns",
        "url": "https://technet.microsoft.com/en-us/sysinternals/bb963902",
        "description": "Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft 4697 APR 2017",
        "url": "https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4697",
        "description": "Miroshnikov, A. & Hall, J. (2017, April 18). 4697(S): A service was installed in the system. Retrieved August 7, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Windows Event Forwarding FEB 2018",
        "url": "https://docs.microsoft.com/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection",
        "description": "Hardy, T. & Hall, J. (2018, February 15). Use Windows Event Forwarding to help with intrusion detection. Retrieved August 7, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--573ad264-1371-4ae0-8482-d2673b719dba",
    "platform": "macos",
    "tid": "T1543.004",
    "technique": "Launch Daemon",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may create or modify launch daemons to repeatedly execute malicious payloads as part of persistence. Per Apple’s developer documentation, when macOS and OS X boot up, launchd is run to finish system initialization. This process loads the parameters for each launch-on-demand system-level daemon from the property list (plist) files found in <code>/System/Library/LaunchDaemons</code> and <code>/Library/LaunchDaemons</code> (Citation: AppleDocs Launch Agent Daemons). These LaunchDaemons have property list files which point to the executables that will be launched (Citation: Methods of Mac Malware Persistence). <br /><br />Adversaries may install a new launch daemon that can be configured to execute at startup by using launchd or launchctl to load a plist into the appropriate directories  (Citation: OSX Malware Detection). The daemon name may be disguised by using a name from a related operating system or benign software (Citation: WireLurker). Launch Daemons may be created with administrator privileges, but are executed under root privileges, so an adversary may also use a service to escalate privileges from administrator to root. <br /><br />The plist file permissions must be root:wheel, but the script or program that it points to has no such requirement. So, it is possible for poor configurations to allow an adversary to modify a current Launch Daemon’s executable and gain persistence or Privilege Escalation. <br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/550.html",
        "description": "none",
        "external_id": "CAPEC-550"
      },
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/551.html",
        "description": "none",
        "external_id": "CAPEC-551"
      },
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
      },
      {
        "source_name": "OSX Malware Detection",
        "url": "https://www.synack.com/wp-content/uploads/2016/03/RSA_OSX_Malware.pdf",
        "description": "Patrick Wardle. (2016, February 29). Let's Play Doctor: Practical OS X Malware Detection & Analysis. Retrieved July 10, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "WireLurker",
        "url": "https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/reports/Unit_42/unit42-wirelurker.pdf",
        "description": "Claud Xiao. (n.d.). WireLurker: A New Era in iOS and OS X Malware. Retrieved July 10, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--98034fef-d9fb-4667-8dc4-2eab6231724c",
    "platform": "windows",
    "tid": "T1546.001",
    "technique": "Change Default File Association",
    "tactic": "privilege-escalation",
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
    "technique_description": "Adversaries may establish persistence by executing malicious content triggered by a file type association. When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access (Citation: Microsoft Change Default Programs) (Citation: Microsoft File Handlers) or by administrators using the built-in assoc utility. (Citation: Microsoft Assoc Oct 2017) Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.<br /><br />System file associations are listed under <code>HKEY_CLASSES_ROOT\\.[extension]</code>, for example <code>HKEY_CLASSES_ROOT\\.txt</code>. The entries point to a handler for that extension located at <code>HKEY_CLASSES_ROOT\\[handler]</code>. The various commands are then listed as subkeys underneath the shell key at <code>HKEY_CLASSES_ROOT\\[handler]\\shell\\[action]\\command</code>. For example: <br /><br />* <code>HKEY_CLASSES_ROOT\\txtfile\\shell\\open\\command</code><br /><br />* <code>HKEY_CLASSES_ROOT\\txtfile\\shell\\print\\command</code><br /><br />* <code>HKEY_CLASSES_ROOT\\txtfile\\shell\\printto\\command</code><br /><br />The values of the keys listed are commands that are executed when the handler opens the file extension. Adversaries can modify these values to continually execute arbitrary commands. (Citation: TrendMicro TROJ-FAKEAV OCT 2012)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/556.html",
        "description": "none",
        "external_id": "CAPEC-556"
      },
      {
        "source_name": "Microsoft Change Default Programs",
        "url": "https://support.microsoft.com/en-us/help/18539/windows-7-change-default-programs",
        "description": "Microsoft. (n.d.). Change which programs Windows 7 uses by default. Retrieved July 26, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft File Handlers",
        "url": "http://msdn.microsoft.com/en-us/library/bb166549.aspx",
        "description": "Microsoft. (n.d.). Specifying File Handlers for File Name Extensions. Retrieved November 13, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Assoc Oct 2017",
        "url": "https://docs.microsoft.com/windows-server/administration/windows-commands/assoc",
        "description": "Plett, C. et al.. (2017, October 15). assoc. Retrieved August 7, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "TrendMicro TROJ-FAKEAV OCT 2012",
        "url": "https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/troj_fakeav.gzd",
        "description": "Sioting, S. (2012, October 8). TROJ_FAKEAV.GZD. Retrieved August 8, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ce4b7013-640e-48a9-b501-d0025a95f4bf",
    "platform": "windows",
    "tid": "T1546.002",
    "technique": "Screensaver",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may establish persistence by executing malicious content triggered by user inactivity. Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension.(Citation: Wikipedia Screensaver) The Windows screensaver application scrnsave.scr is located in <code>C:\\Windows\\System32\\</code>, and <code>C:\\Windows\\sysWOW64\\</code>  on 64-bit Windows systems, along with screensavers included with base Windows installations.<br /><br />The following screensaver settings are stored in the Registry (<code>HKCU\\Control Panel\\Desktop\\</code>) and could be manipulated to achieve persistence:<br /><br />* <code>SCRNSAVE.exe</code> - set to malicious PE path<br /><br />* <code>ScreenSaveActive</code> - set to '1' to enable the screensaver<br /><br />* <code>ScreenSaverIsSecure</code> - set to '0' to not require a password to unlock<br /><br />* <code>ScreenSaveTimeout</code> - sets user inactivity timeout before screensaver is executed<br /><br />Adversaries can use screensaver settings to maintain persistence by setting the screensaver to run malware after a certain timeframe of user inactivity. (Citation: ESET Gazer Aug 2017)<br /><br />",
    "technique_references": [
      {
        "source_name": "Wikipedia Screensaver",
        "url": "https://en.wikipedia.org/wiki/Screensaver",
        "description": "Wikipedia. (2017, November 22). Screensaver. Retrieved December 5, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "ESET Gazer Aug 2017",
        "url": "https://www.welivesecurity.com/wp-content/uploads/2017/08/eset-gazer.pdf",
        "description": "ESET. (2017, August). Gazing at Gazer: Turla’s new second stage backdoor. Retrieved September 14, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--910906dd-8c0a-475a-9cc1-5e029e2fad58",
    "platform": "windows",
    "tid": "T1546.003",
    "technique": "Windows Management Instrumentation Event Subscription",
    "tactic": "privilege-escalation",
    "datasources": "process-command-line-parameters|process-monitoring|wmi-objects",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription. WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Examples of events that may be subscribed to are the wall clock time, user loging, or the computer's uptime. (Citation: Mandiant M-Trends 2015)<br /><br />Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system. (Citation: FireEye WMI SANS 2015) (Citation: FireEye WMI 2015) Adversaries may also compile WMI scripts into Windows Management Object (MOF) files (.mof extension) that can be used to create a malicious subscription. (Citation: Dell WMI Persistence) (Citation: Microsoft MOF May 2018)<br /><br />WMI subscription execution is proxied by the WMI Provider Host process (WmiPrvSe.exe) and thus may result in elevated SYSTEM privileges.<br /><br />",
    "technique_references": [
      {
        "source_name": "Mandiant M-Trends 2015",
        "url": "https://www2.fireeye.com/rs/fireye/images/rpt-m-trends-2015.pdf",
        "description": "Mandiant. (2015, February 24). M-Trends 2015: A View from the Front Lines. Retrieved May 18, 2016.",
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
      },
      {
        "source_name": "Dell WMI Persistence",
        "url": "https://www.secureworks.com/blog/wmi-persistence",
        "description": "Dell SecureWorks Counter Threat Unit™ (CTU) Research Team. (2016, March 28). A Novel WMI Persistence Implementation. Retrieved March 30, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft MOF May 2018",
        "url": "https://docs.microsoft.com/en-us/windows/win32/wmisdk/managed-object-format--mof-",
        "description": "Satran, M. (2018, May 30). Managed Object Format (MOF). Retrieved January 24, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Autoruns",
        "url": "https://technet.microsoft.com/en-us/sysinternals/bb963902",
        "description": "Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Medium Detecting WMI Persistence",
        "url": "https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96",
        "description": "French, D. (2018, October 9). Detecting & Removing an Attacker’s WMI Persistence. Retrieved October 11, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Register-WmiEvent",
        "url": "https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/register-wmievent?view=powershell-5.1",
        "description": "Microsoft. (n.d.). Retrieved January 24, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b63a34e8-0a61-4c97-a23b-bf8a2ed812e2",
    "platform": "linux|macos",
    "tid": "T1546.004",
    "technique": ".bash_profile and .bashrc",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may establish persistence by executing malicious content triggered by a user’s shell. <code>~/.bash_profile</code> and <code>~/.bashrc</code> are shell scripts that contain shell commands. These files are executed in a user's context when a new shell opens or when a user logs in so that their environment is set correctly.<br /><br /><code>~/.bash_profile</code> is executed for login shells and <code>~/.bashrc</code> is executed for interactive non-login shells. This means that when a user logs in (via username and password) to the console (either locally or remotely via something like SSH), the <code>~/.bash_profile</code> script is executed before the initial command prompt is returned to the user. After that, every time a new shell is opened, the <code>~/.bashrc</code> script is executed. This allows users more fine-grained control over when they want certain commands executed. These shell scripts are meant to be written to by the local user to configure their own environment.<br /><br />The macOS Terminal.app is a little different in that it runs a login shell by default each time a new terminal window is opened, thus calling <code>~/.bash_profile</code> each time instead of <code>~/.bashrc</code>.<br /><br />Adversaries may abuse these shell scripts by inserting arbitrary shell commands that may be used to execute other binaries to gain persistence. Every time the user logs in or opens a new shell, the modified ~/.bash_profile and/or ~/.bashrc scripts will be executed.(Citation: amnesia malware)<br /><br />",
    "technique_references": [
      {
        "source_name": "amnesia malware",
        "url": "https://researchcenter.paloaltonetworks.com/2017/04/unit42-new-iotlinux-malware-targets-dvrs-forms-botnet/",
        "description": "Claud Xiao, Cong Zheng, Yanhui Jia. (2017, April 6). New IoT/Linux Malware Targets DVRs, Forms Botnet. Retrieved February 19, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--63220765-d418-44de-8fae-694b3912317d",
    "platform": "macos|linux",
    "tid": "T1546.005",
    "technique": "Trap",
    "tactic": "privilege-escalation",
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
    "technique_description": "Adversaries may establish persistence by executing malicious content triggered by an interrupt signal. The <code>trap</code> command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like <code>ctrl+c</code> and <code>ctrl+d</code>.<br /><br />Adversaries can use this to register code to be executed when the shell encounters specific interrupts as a persistence mechanism. Trap commands are of the following format <code>trap 'command list' signals</code> where \"command list\" will be executed when \"signals\" are received.(Citation: Trap Manual)(Citation: Cyberciti Trap Statements)<br /><br />",
    "technique_references": [
      {
        "source_name": "Trap Manual",
        "url": "https://ss64.com/bash/trap.html",
        "description": "ss64. (n.d.). trap. Retrieved May 21, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Cyberciti Trap Statements",
        "url": "https://bash.cyberciti.biz/guide/Trap_statement",
        "description": "Cyberciti. (2016, March 29). Trap statement. Retrieved May 21, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--10ff21b9-5a01-4268-a1b5-3b55015f1847",
    "platform": "macos",
    "tid": "T1546.006",
    "technique": "LC_LOAD_DYLIB Addition",
    "tactic": "privilege-escalation",
    "datasources": "binary-file-metadata|file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may establish persistence by executing malicious content triggered by the execution of tainted binaries. Mach-O binaries have a series of headers that are used to perform certain operations when a binary is loaded. The LC_LOAD_DYLIB header in a Mach-O binary tells macOS and OS X which dynamic libraries (dylibs) to load during execution time. These can be added ad-hoc to the compiled binary as long as adjustments are made to the rest of the fields and dependencies. (Citation: Writing Bad Malware for OSX) There are tools available to perform these changes.<br /><br />Adversaries may modify Mach-O binary headers to load and execute malicious dylibs every time the binary is executed. Although any changes will invalidate digital signatures on binaries because the binary is being modified, this can be remediated by simply removing the LC_CODE_SIGNATURE command from the binary so that the signature isn’t checked at load time. (Citation: Malware Persistence on OS X)<br /><br />",
    "technique_references": [
      {
        "source_name": "Writing Bad Malware for OSX",
        "url": "https://www.blackhat.com/docs/us-15/materials/us-15-Wardle-Writing-Bad-A-Malware-For-OS-X.pdf",
        "description": "Patrick Wardle. (2015). Writing Bad @$$ Malware for OS X. Retrieved July 10, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Malware Persistence on OS X",
        "url": "https://www.rsaconference.com/writable/presentations/file_upload/ht-r03-malware-persistence-on-os-x-yosemite_final.pdf",
        "description": "Patrick Wardle. (2015). Malware Persistence on OS X Yosemite. Retrieved July 10, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--f63fe421-b1d1-45c0-b8a7-02cd16ff2bed",
    "platform": "windows",
    "tid": "T1546.007",
    "technique": "Netsh Helper DLL",
    "tactic": "privilege-escalation",
    "datasources": "dll-monitoring|process-command-line-parameters|process-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs. Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility. (Citation: TechNet Netsh) The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at <code>HKLM\\SOFTWARE\\Microsoft\\Netsh</code>.<br /><br />Adversaries can use netsh.exe helper DLLs to trigger execution of arbitrary code in a persistent manner. This execution would take place anytime netsh.exe is executed, which could happen automatically, with another persistence technique, or if other software (ex: VPN) is present on the system that executes netsh.exe as part of its normal functionality. (Citation: Github Netsh Helper CS Beacon)(Citation: Demaske Netsh Persistence)<br /><br />",
    "technique_references": [
      {
        "source_name": "TechNet Netsh",
        "url": "https://technet.microsoft.com/library/bb490939.aspx",
        "description": "Microsoft. (n.d.). Using Netsh. Retrieved February 13, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Github Netsh Helper CS Beacon",
        "url": "https://github.com/outflankbv/NetshHelperBeacon",
        "description": "Smeets, M. (2016, September 26). NetshHelperBeacon. Retrieved February 13, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Demaske Netsh Persistence",
        "url": "https://htmlpreview.github.io/?https://github.com/MatthewDemaske/blogbackup/blob/master/netshell.html",
        "description": "Demaske, M. (2016, September 23). USING NETSHELL TO EXECUTE EVIL DLLS AND PERSIST ON A HOST. Retrieved April 8, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--70e52b04-2a0c-4cea-9d18-7149f1df9dc5",
    "platform": "windows",
    "tid": "T1546.008",
    "technique": "Accessibility Features",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features. Windows contains accessibility features that may be launched with a key combination before a user has logged in (ex: when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system.<br /><br />Two common accessibility programs are <code>C:\\Windows\\System32\\sethc.exe</code>, launched when the shift key is pressed five times and <code>C:\\Windows\\System32\\utilman.exe</code>, launched when the Windows + U key combination is pressed. The sethc.exe program is often referred to as \"sticky keys\", and has been used by adversaries for unauthenticated access through a remote desktop login screen. (Citation: FireEye Hikit Rootkit)<br /><br />Depending on the version of Windows, an adversary may take advantage of these features in different ways. Common methods used by adversaries include replacing accessibility feature binaries or pointers/references to these binaries in the Registry. In newer versions of Windows, the replaced binary needs to be digitally signed for x64 systems, the binary must reside in <code>%systemdir%\\</code>, and it must be protected by Windows File or Resource Protection (WFP/WRP). (Citation: DEFCON2016 Sticky Keys) The [Image File Execution Options Injection](https://attack.mitre.org/techniques/T1546/012) debugger method was likely discovered as a potential workaround because it does not require the corresponding accessibility feature binary to be replaced.<br /><br />For simple binary replacement on Windows XP and later as well as and Windows Server 2003/R2 and later, for example, the program (e.g., <code>C:\\Windows\\System32\\utilman.exe</code>) may be replaced with \"cmd.exe\" (or another program that provides backdoor access). Subsequently, pressing the appropriate key combination at the login screen while sitting at the keyboard or when connected over [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) will cause the replaced file to be executed with SYSTEM privileges. (Citation: Tilbury 2014)<br /><br />Other accessibility features exist that may also be leveraged in a similar fashion: (Citation: DEFCON2016 Sticky Keys)(Citation: Narrator Accessibility Abuse)<br /><br />* On-Screen Keyboard: <code>C:\\Windows\\System32\\osk.exe</code><br /><br />* Magnifier: <code>C:\\Windows\\System32\\Magnify.exe</code><br /><br />* Narrator: <code>C:\\Windows\\System32\\Narrator.exe</code><br /><br />* Display Switcher: <code>C:\\Windows\\System32\\DisplaySwitch.exe</code><br /><br />* App Switcher: <code>C:\\Windows\\System32\\AtBroker.exe</code><br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/558.html",
        "description": "none",
        "external_id": "CAPEC-558"
      },
      {
        "source_name": "FireEye Hikit Rootkit",
        "url": "https://www.fireeye.com/blog/threat-research/2012/08/hikit-rootkit-advanced-persistent-attack-techniques-part-1.html",
        "description": "Glyer, C., Kazanciyan, R. (2012, August 20). The “Hikit” Rootkit: Advanced and Persistent Attack Techniques (Part 1). Retrieved June 6, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "DEFCON2016 Sticky Keys",
        "url": "https://www.slideshare.net/DennisMaldonado5/sticky-keys-to-the-kingdom",
        "description": "Maldonado, D., McGuffin, T. (2016, August 6). Sticky Keys to the Kingdom. Retrieved July 5, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Tilbury 2014",
        "url": "http://blog.crowdstrike.com/registry-analysis-with-crowdresponse/",
        "description": "Tilbury, C. (2014, August 28). Registry Analysis with CrowdResponse. Retrieved November 12, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Narrator Accessibility Abuse",
        "url": "https://giuliocomi.blogspot.com/2019/10/abusing-windows-10-narrators-feedback.html",
        "description": "Comi, G. (2019, October 19). Abusing Windows 10 Narrator's 'Feedback-Hub' URI for Fileless Persistence. Retrieved April 28, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--7d57b371-10c2-45e5-b3cc-83a8fb380e4c",
    "platform": "windows",
    "tid": "T1546.009",
    "technique": "AppCert DLLs",
    "tactic": "privilege-escalation",
    "datasources": "loaded-dlls|process-command-line-parameters|process-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the <code>AppCertDLLs</code> Registry key under <code>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\</code> are loaded into every process that calls the ubiquitously used application programming interface (API) functions <code>CreateProcess</code>, <code>CreateProcessAsUser</code>, <code>CreateProcessWithLoginW</code>, <code>CreateProcessWithTokenW</code>, or <code>WinExec</code>. (Citation: Endgame Process Injection July 2017)<br /><br />Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), this value can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. Malicious AppCert DLLs may also provide persistence by continuously being triggered by API activity. <br /><br />",
    "technique_references": [
      {
        "source_name": "Endgame Process Injection July 2017",
        "url": "https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process",
        "description": "Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Autoruns",
        "url": "https://technet.microsoft.com/en-us/sysinternals/bb963902",
        "description": "Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Sysinternals AppCertDlls Oct 2007",
        "url": "https://forum.sysinternals.com/appcertdlls_topic12546.html",
        "description": "Microsoft. (2007, October 24). Windows Sysinternals - AppCertDlls. Retrieved December 18, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--cc89ecbd-3d33-4a41-bcca-001e702d18fd",
    "platform": "windows",
    "tid": "T1546.010",
    "technique": "AppInit DLLs",
    "tactic": "privilege-escalation",
    "datasources": "loaded-dlls|process-command-line-parameters|process-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the <code>AppInit_DLLs</code> value in the Registry keys <code>HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows</code> or <code>HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows</code> are loaded by user32.dll into every process that loads user32.dll. In practice this is nearly every program, since user32.dll is a very common library. (Citation: Endgame Process Injection July 2017)<br /><br />Similar to Process Injection, these values can be abused to obtain elevated privileges by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. (Citation: AppInit Registry) Malicious AppInit DLLs may also provide persistence by continuously being triggered by API activity. <br /><br />The AppInit DLL functionality is disabled in Windows 8 and later versions when secure boot is enabled. (Citation: AppInit Secure Boot)<br /><br />",
    "technique_references": [
      {
        "source_name": "Endgame Process Injection July 2017",
        "url": "https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process",
        "description": "Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "AppInit Registry",
        "url": "https://support.microsoft.com/en-us/kb/197571",
        "description": "Microsoft. (2006, October). Working with the AppInit_DLLs registry value. Retrieved July 15, 2015.",
        "external_id": "none"
      },
      {
        "source_name": "AppInit Secure Boot",
        "url": "https://msdn.microsoft.com/en-us/library/dn280412",
        "description": "Microsoft. (n.d.). AppInit DLLs and Secure Boot. Retrieved July 15, 2015.",
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
    "id": "attack-pattern--42fe883a-21ea-4cfb-b94a-78b6476dcc83",
    "platform": "windows",
    "tid": "T1546.011",
    "technique": "Application Shimming",
    "tactic": "privilege-escalation",
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
    "technique_description": "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims. The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time. For example, the application shimming feature allows developers to apply fixes to applications (without rewriting code) that were created for Windows XP so that it will work with Windows 10. (Citation: Endgame Process Injection July 2017)<br /><br />Within the framework, shims are created to act as a buffer between the program (or more specifically, the Import Address Table) and the Windows OS. When a program is executed, the shim cache is referenced to determine if the program requires the use of the shim database (.sdb). If so, the shim database uses hooking to redirect the code as necessary in order to communicate with the OS. <br /><br />A list of all shims currently installed by the default Windows installer (sdbinst.exe) is kept in:<br /><br />* <code>%WINDIR%\\AppPatch\\sysmain.sdb</code> and<br /><br />* <code>hklm\\software\\microsoft\\windows nt\\currentversion\\appcompatflags\\installedsdb</code><br /><br />Custom databases are stored in:<br /><br />* <code>%WINDIR%\\AppPatch\\custom & %WINDIR%\\AppPatch\\AppPatch64\\Custom</code> and<br /><br />* <code>hklm\\software\\microsoft\\windows nt\\currentversion\\appcompatflags\\custom</code><br /><br />To keep shims secure, Windows designed them to run in user mode so they cannot modify the kernel and you must have administrator privileges to install a shim. However, certain shims can be used to [Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002) (UAC and RedirectEXE), inject DLLs into processes (InjectDLL), disable Data Execution Prevention (DisableNX) and Structure Exception Handling (DisableSEH), and intercept memory addresses (GetProcAddress).<br /><br />Utilizing these shims may allow an adversary to perform several malicious acts such as elevate privileges, install backdoors, disable defenses like Windows Defender, etc. (Citation: FireEye Application Shimming) Shims can also be abused to establish persistence by continuously being invoked by affected programs.<br /><br />",
    "technique_references": [
      {
        "source_name": "Endgame Process Injection July 2017",
        "url": "https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process",
        "description": "Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye Application Shimming",
        "url": "http://files.brucon.org/2015/Tomczak_and_Ballenthin_Shims_for_the_Win.pdf",
        "description": "Ballenthin, W., Tomczak, J.. (2015). The Real Shim Shary. Retrieved May 4, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Black Hat 2015 App Shim",
        "url": "https://www.blackhat.com/docs/eu-15/materials/eu-15-Pierce-Defending-Against-Malicious-Application-Compatibility-Shims-wp.pdf",
        "description": "Pierce, Sean. (2015, November). Defending Against Malicious Application Compatibility Shims. Retrieved June 22, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--6d4a7fb3-5a24-42be-ae61-6728a2b581f6",
    "platform": "windows",
    "tid": "T1546.012",
    "technique": "Image File Execution Options Injection",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|process-command-line-parameters|process-monitoring|windows-event-logs|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by Image File Execution Options (IFEO) debuggers. IFEOs enable a developer to attach a debugger to an application. When a process is created, a debugger present in an application’s IFEO will be prepended to the application’s name, effectively launching the new process under the debugger (e.g., <code>C:\\dbg\\ntsd.exe -g  notepad.exe</code>). (Citation: Microsoft Dev Blog IFEO Mar 2010)<br /><br />IFEOs can be set directly via the Registry or in Global Flags via the GFlags tool. (Citation: Microsoft GFlags Mar 2017) IFEOs are represented as <code>Debugger</code> values in the Registry under <code>HKLM\\SOFTWARE{\\Wow6432Node}\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\<executable></code> where <code>&lt;executable&gt;</code> is the binary on which the debugger is attached. (Citation: Microsoft Dev Blog IFEO Mar 2010)<br /><br />IFEOs can also enable an arbitrary monitor program to be launched when a specified program silently exits (i.e. is prematurely terminated by itself or a second, non kernel-mode process). (Citation: Microsoft Silent Process Exit NOV 2017) (Citation: Oddvar Moe IFEO APR 2018) Similar to debuggers, silent exit monitoring can be enabled through GFlags and/or by directly modifying IFEO and silent process exit Registry values in <code>HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\</code>. (Citation: Microsoft Silent Process Exit NOV 2017) (Citation: Oddvar Moe IFEO APR 2018)<br /><br />Similar to [Accessibility Features](https://attack.mitre.org/techniques/T1546/008), on Windows Vista and later as well as Windows Server 2008 and later, a Registry key may be modified that configures \"cmd.exe,\" or another program that provides backdoor access, as a \"debugger\" for an accessibility program (ex: utilman.exe). After the Registry is modified, pressing the appropriate key combination at the login screen while at the keyboard or when connected with [Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001) will cause the \"debugger\" program to be executed with SYSTEM privileges. (Citation: Tilbury 2014)<br /><br />Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), these values may also be abused to obtain privilege escalation by causing a malicious executable to be loaded and run in the context of separate processes on the computer. (Citation: Endgame Process Injection July 2017) Installing IFEO mechanisms may also provide Persistence via continuous triggered invocation.<br /><br />Malware may also use IFEO to [Impair Defenses](https://attack.mitre.org/techniques/T1562) by registering invalid debuggers that redirect and effectively disable various system and security applications. (Citation: FSecure Hupigon) (Citation: Symantec Ushedix June 2008)<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft Dev Blog IFEO Mar 2010",
        "url": "https://blogs.msdn.microsoft.com/mithuns/2010/03/24/image-file-execution-options-ifeo/",
        "description": "Shanbhag, M. (2010, March 24). Image File Execution Options (IFEO). Retrieved December 18, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft GFlags Mar 2017",
        "url": "https://docs.microsoft.com/windows-hardware/drivers/debugger/gflags-overview",
        "description": "Microsoft. (2017, May 23). GFlags Overview. Retrieved December 18, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Silent Process Exit NOV 2017",
        "url": "https://docs.microsoft.com/windows-hardware/drivers/debugger/registry-entries-for-silent-process-exit",
        "description": "Marshall, D. & Griffin, S. (2017, November 28). Monitoring Silent Process Exit. Retrieved June 27, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Oddvar Moe IFEO APR 2018",
        "url": "https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/",
        "description": "Moe, O. (2018, April 10). Persistence using GlobalFlags in Image File Execution Options - Hidden from Autoruns.exe. Retrieved June 27, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Tilbury 2014",
        "url": "http://blog.crowdstrike.com/registry-analysis-with-crowdresponse/",
        "description": "Tilbury, C. (2014, August 28). Registry Analysis with CrowdResponse. Retrieved November 12, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Endgame Process Injection July 2017",
        "url": "https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process",
        "description": "Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "FSecure Hupigon",
        "url": "https://www.f-secure.com/v-descs/backdoor_w32_hupigon_emv.shtml",
        "description": "FSecure. (n.d.). Backdoor - W32/Hupigon.EMV - Threat Description. Retrieved December 18, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Symantec Ushedix June 2008",
        "url": "https://www.symantec.com/security_response/writeup.jsp?docid=2008-062807-2501-99&tabid=2",
        "description": "Symantec. (2008, June 28). Trojan.Ushedix. Retrieved December 18, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0f2c410d-d740-4ed9-abb1-b8f4a7faf6c3",
    "platform": "windows",
    "tid": "T1546.013",
    "technique": "PowerShell Profile",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|powershell-logs|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles. A PowerShell profile  (<code>profile.ps1</code>) is a script that runs when [PowerShell](https://attack.mitre.org/techniques/T1059/001) starts and can be used as a logon script to customize user environments.<br /><br />[PowerShell](https://attack.mitre.org/techniques/T1059/001) supports several profiles depending on the user or host program. For example, there can be different profiles for [PowerShell](https://attack.mitre.org/techniques/T1059/001) host programs such as the PowerShell console, PowerShell ISE or Visual Studio Code. An administrator can also configure a profile that applies to all users and host programs on the local computer. (Citation: Microsoft About Profiles) <br /><br />Adversaries may modify these profiles to include arbitrary commands, functions, modules, and/or [PowerShell](https://attack.mitre.org/techniques/T1059/001) drives to gain persistence. Every time a user opens a [PowerShell](https://attack.mitre.org/techniques/T1059/001) session the modified script will be executed unless the <code>-NoProfile</code> flag is used when it is launched. (Citation: ESET Turla PowerShell May 2019) <br /><br />An adversary may also be able to escalate privileges if a script in a PowerShell profile is loaded and executed by an account with higher privileges, such as a domain administrator. (Citation: Wits End and Shady PowerShell Profiles)<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft About Profiles",
        "url": "https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-6",
        "description": "Microsoft. (2017, November 29). About Profiles. Retrieved June 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "ESET Turla PowerShell May 2019",
        "url": "https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/",
        "description": "Faou, M. and Dumont R.. (2019, May 29). A dive into Turla PowerShell usage. Retrieved June 14, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Wits End and Shady PowerShell Profiles",
        "url": "https://witsendandshady.blogspot.com/2019/06/lab-notes-persistence-and-privilege.html",
        "description": "DeRyke, A.. (2019, June 7). Lab Notes: Persistence and Privilege Elevation using the Powershell Profile. Retrieved July 8, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Malware Archaeology PowerShell Cheat Sheet",
        "url": "http://www.malwarearchaeology.com/s/Windows-PowerShell-Logging-Cheat-Sheet-ver-June-2016-v2.pdf",
        "description": "Malware Archaeology. (2016, June). WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later. Retrieved June 24, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--9c45eaa3-8604-4780-8988-b5074dbb9ecd",
    "platform": "macos",
    "tid": "T1546.014",
    "technique": "Emond",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may gain persistence and elevate privileges by executing malicious content triggered by the Event Monitor Daemon (emond). Emond is a [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) that accepts events from various services, runs them through a simple rules engine, and takes action. The emond binary at <code>/sbin/emond</code> will load any rules from the <code>/etc/emond.d/rules/</code> directory and take action once an explicitly defined event takes place.<br /><br />The rule files are in the plist format and define the name, event type, and action to take. Some examples of event types include system startup and user authentication. Examples of actions are to run a system command or send an email. The emond service will not launch if there is no file present in the QueueDirectories path <code>/private/var/db/emondClients</code>, specified in the [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) configuration file at<code>/System/Library/LaunchDaemons/com.apple.emond.plist</code>.(Citation: xorrior emond Jan 2018)(Citation: magnusviri emond Apr 2016)(Citation: sentinelone macos persist Jun 2019)<br /><br />Adversaries may abuse this service by writing a rule to execute commands when a defined event occurs, such as system start up or user authentication.(Citation: xorrior emond Jan 2018)(Citation: magnusviri emond Apr 2016)(Citation: sentinelone macos persist Jun 2019) Adversaries may also be able to escalate privileges from administrator to root as the emond service is executed with root privileges by the [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) service.<br /><br />",
    "technique_references": [
      {
        "source_name": "xorrior emond Jan 2018",
        "url": "https://www.xorrior.com/emond-persistence/",
        "description": "Ross, Chris. (2018, January 17). Leveraging Emond on macOS For Persistence. Retrieved September 10, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "magnusviri emond Apr 2016",
        "url": "http://www.magnusviri.com/Mac/what-is-emond.html",
        "description": "Reynolds, James. (2016, April 7). What is emond?. Retrieved September 10, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "sentinelone macos persist Jun 2019",
        "url": "https://www.sentinelone.com/blog/how-malware-persists-on-macos/",
        "description": "Stokes, Phil. (2019, June 17). HOW MALWARE PERSISTS ON MACOS. Retrieved September 10, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--bc0f5e80-91c0-4e04-9fbb-e4e332c85dae",
    "platform": "windows",
    "tid": "T1546.015",
    "technique": "Component Object Model Hijacking",
    "tactic": "privilege-escalation",
    "datasources": "dll-monitoring|loaded-dlls|process-command-line-parameters|process-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects. COM is a system within Windows to enable interaction between software components through the operating system.(Citation: Microsoft Component Object Model)  References to various COM objects are stored in the Registry. <br /><br />Adversaries can use the COM system to insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships as a means for persistence. Hijacking a COM object requires a change in the Registry to replace a reference to a legitimate system component which may cause that component to not work when executed. When that system component is executed through normal system operation the adversary's code will be executed instead.(Citation: GDATA COM Hijacking) An adversary is likely to hijack objects that are used frequently enough to maintain a consistent level of persistence, but are unlikely to break noticeable functionality within the system as to avoid system instability that could lead to detection. <br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft Component Object Model",
        "url": "https://msdn.microsoft.com/library/ms694363.aspx",
        "description": "Microsoft. (n.d.). The Component Object Model. Retrieved August 18, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "GDATA COM Hijacking",
        "url": "https://blog.gdatasoftware.com/2014/10/23941-com-object-hijacking-the-discreet-way-of-persistence",
        "description": "G DATA. (2014, October). COM Object hijacking: the discreet way of persistence. Retrieved August 13, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Endgame COM Hijacking",
        "url": "https://www.elastic.co/blog/how-hunt-detecting-persistence-evasion-com",
        "description": "Ewing, P. Strom, B. (2016, September 15). How to Hunt: Detecting Persistence & Evasion with the COM. Retrieved September 15, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--9efb1ea7-c37b-4595-9640-b7680cd84279",
    "platform": "windows",
    "tid": "T1547.001",
    "technique": "Registry Run Keys / Startup Folder",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the \"run keys\" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. (Citation: Microsoft Run Key) These programs will be executed under the context of the user and will have the account's associated permissions level.<br /><br />Placing a program within a startup folder will also cause that program to execute when a user logs in. There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in. The startup folder path for the current user is <code>C:\\Users\\[Username]\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup</code>. The startup folder path for all users is <code>C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp</code>.<br /><br />The following run keys are created by default on Windows systems:<br /><br />* <code>HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</code><br /><br />* <code>HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce</code><br /><br />* <code>HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run</code><br /><br />* <code>HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce</code><br /><br />Run keys may exist under multiple hives.(Citation: Microsoft Wow6432Node 2018)(Citation: Malwarebytes Wow6432Node 2016) The <code>HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx</code> is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency. (Citation: Microsoft RunOnceEx APR 2018) For example, it is possible to load a DLL at logon using a \"Depend\" key with RunOnceEx: <code>reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d \"C:\\temp\\evil[.]dll\"</code> (Citation: Oddvar Moe RunOnceEx Mar 2018)<br /><br />The following Registry keys can be used to set startup folder items for persistence:<br /><br />* <code>HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders</code><br /><br />* <code>HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders</code><br /><br />* <code>HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders</code><br /><br />* <code>HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders</code><br /><br />The following Registry keys can control automatic startup of services during boot:<br /><br />* <code>HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce</code><br /><br />* <code>HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce</code><br /><br />* <code>HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices</code><br /><br />* <code>HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices</code><br /><br />Using policy settings to specify startup programs creates corresponding values in either of two Registry keys:<br /><br />* <code>HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run</code><br /><br />* <code>HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run</code><br /><br />The Winlogon key controls actions that occur when a user logs on to a computer running Windows 7. Most of these actions are under the control of the operating system, but you can also add custom actions here. The <code>HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit</code> and <code>HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell</code> subkeys can automatically launch programs.<br /><br />Programs listed in the load value of the registry key <code>HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows</code> run when any user logs on.<br /><br />By default, the multistring <code>BootExecute</code> value of the registry key <code>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager</code> is set to <code>autocheck autochk *</code>. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot.<br /><br />Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use [Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look as if they are associated with legitimate programs.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/270.html",
        "description": "none",
        "external_id": "CAPEC-270"
      },
      {
        "source_name": "Microsoft Run Key",
        "url": "http://msdn.microsoft.com/en-us/library/aa376977",
        "description": "Microsoft. (n.d.). Run and RunOnce Registry Keys. Retrieved November 12, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Wow6432Node 2018",
        "url": "https://docs.microsoft.com/en-us/windows/win32/sysinfo/32-bit-and-64-bit-application-data-in-the-registry",
        "description": "Microsoft. (2018, May 31). 32-bit and 64-bit Application Data in the Registry. Retrieved August 3, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Malwarebytes Wow6432Node 2016",
        "url": "https://blog.malwarebytes.com/cybercrime/2013/10/hiding-in-plain-sight/",
        "description": "Arntz, P. (2016, March 30). Hiding in Plain Sight. Retrieved August 3, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft RunOnceEx APR 2018",
        "url": "https://support.microsoft.com/help/310593/description-of-the-runonceex-registry-key",
        "description": "Microsoft. (2018, August 20). Description of the RunOnceEx Registry Key. Retrieved June 29, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Oddvar Moe RunOnceEx Mar 2018",
        "url": "https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/",
        "description": "Moe, O. (2018, March 21). Persistence using RunOnceEx - Hidden from Autoruns.exe. Retrieved June 29, 2018.",
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
    "id": "attack-pattern--b8cfed42-6a8a-4989-ad72-541af74475ec",
    "platform": "windows",
    "tid": "T1547.002",
    "technique": "Authentication Package",
    "tactic": "privilege-escalation",
    "datasources": "dll-monitoring|loaded-dlls|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse authentication packages to execute DLLs when the system boots. Windows authentication package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system. (Citation: MSDN Authentication Packages)<br /><br />Adversaries can use the autostart mechanism provided by LSA authentication packages for persistence by placing a reference to a binary in the Windows Registry location <code>HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\</code> with the key value of <code>\"Authentication Packages\"=&lt;target binary&gt;</code>. The binary will then be executed by the system when the authentication packages are loaded.<br /><br />",
    "technique_references": [
      {
        "source_name": "MSDN Authentication Packages",
        "url": "https://msdn.microsoft.com/library/windows/desktop/aa374733.aspx",
        "description": "Microsoft. (n.d.). Authentication Packages. Retrieved March 1, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Graeber 2014",
        "url": "http://docplayer.net/20839173-Analysis-of-malicious-security-support-provider-dlls.html",
        "description": "Graeber, M. (2014, October). Analysis of Malicious Security Support Provider DLLs. Retrieved March 1, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Configure LSA",
        "url": "https://technet.microsoft.com/en-us/library/dn408187.aspx",
        "description": "Microsoft. (2013, July 31). Configuring Additional LSA Protection. Retrieved June 24, 2015.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--61afc315-860c-4364-825d-0d62b2e91edc",
    "platform": "windows",
    "tid": "T1547.003",
    "technique": "Time Providers",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|binary-file-metadata|dll-monitoring|file-monitoring|loaded-dlls|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse time providers to execute DLLs when the system boots. The Windows Time service (W32Time) enables time synchronization across and within domains. (Citation: Microsoft W32Time Feb 2018) W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients. (Citation: Microsoft TimeProvider)<br /><br />Time providers are implemented as dynamic-link libraries (DLLs) that are registered in the subkeys of  <code>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\</code>. (Citation: Microsoft TimeProvider) The time provider manager, directed by the service control manager, loads and starts time providers listed and enabled under this key at system startup and/or whenever parameters are changed. (Citation: Microsoft TimeProvider)<br /><br />Adversaries may abuse this architecture to establish persistence, specifically by registering and enabling a malicious DLL as a time provider. Administrator privileges are required for time provider registration, though execution will run in context of the Local Service account. (Citation: Github W32Time Oct 2017)<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft W32Time Feb 2018",
        "url": "https://docs.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-top",
        "description": "Microsoft. (2018, February 1). Windows Time Service (W32Time). Retrieved March 26, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft TimeProvider",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ms725475.aspx",
        "description": "Microsoft. (n.d.). Time Provider. Retrieved March 26, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Github W32Time Oct 2017",
        "url": "https://github.com/scottlundgren/w32time",
        "description": "Lundgren, S. (2017, October 28). w32time. Retrieved March 26, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft W32Time May 2017",
        "url": "https://docs.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings",
        "description": "Mathers, B. (2017, May 31). Windows Time Service Tools and Settings. Retrieved March 26, 2018.",
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
    "id": "attack-pattern--6836813e-8ec8-4375-b459-abb388cb1a35",
    "platform": "windows",
    "tid": "T1547.004",
    "technique": "Winlogon Helper DLL",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in. Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in <code>HKLM\\Software[\\\\Wow6432Node\\\\]\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\</code> and <code>HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\</code> are used to manage additional helper programs and functionalities that support Winlogon. (Citation: Cylance Reg Persistence Sept 2013) <br /><br />Malicious modifications to these Registry keys may cause Winlogon to load and execute malicious DLLs and/or executables. Specifically, the following subkeys have been known to be possibly vulnerable to abuse: (Citation: Cylance Reg Persistence Sept 2013)<br /><br />* Winlogon\\Notify - points to notification package DLLs that handle Winlogon events<br /><br />* Winlogon\\Userinit - points to userinit.exe, the user initialization program executed when a user logs on<br /><br />* Winlogon\\Shell - points to explorer.exe, the system shell executed when a user logs on<br /><br />Adversaries may take advantage of these features to repeatedly execute malicious code and establish persistence.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/579.html",
        "description": "none",
        "external_id": "CAPEC-579"
      },
      {
        "source_name": "Cylance Reg Persistence Sept 2013",
        "url": "https://blog.cylance.com/windows-registry-persistence-part-2-the-run-keys-and-search-order",
        "description": "Langendorf, S. (2013, September 24). Windows Registry Persistence, Part 2: The Run Keys and Search-Order. Retrieved April 11, 2018.",
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
    "id": "attack-pattern--5095a853-299c-4876-abd7-ac0050fb5462",
    "platform": "windows",
    "tid": "T1547.005",
    "technique": "Security Support Provider",
    "tactic": "privilege-escalation",
    "datasources": "dll-monitoring|loaded-dlls|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse security support providers (SSPs) to execute DLLs when the system boots. Windows SSP DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs.<br /><br />The SSP configuration is stored in two Registry keys: <code>HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages</code> and <code>HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.(Citation: Graeber 2014)<br /><br />",
    "technique_references": [
      {
        "source_name": "Graeber 2014",
        "url": "http://docplayer.net/20839173-Analysis-of-malicious-security-support-provider-dlls.html",
        "description": "Graeber, M. (2014, October). Analysis of Malicious Security Support Provider DLLs. Retrieved March 1, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Configure LSA",
        "url": "https://technet.microsoft.com/en-us/library/dn408187.aspx",
        "description": "Microsoft. (2013, July 31). Configuring Additional LSA Protection. Retrieved June 24, 2015.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--a1b52199-c8c5-438a-9ded-656f1d0888c6",
    "platform": "macos|linux",
    "tid": "T1547.006",
    "technique": "Kernel Modules and Extensions",
    "tactic": "privilege-escalation",
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
    "technique_description": "Adversaries may modify the kernel to automatically execute programs on system boot. Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. For example, one type of module is the device driver, which allows the kernel to access hardware connected to the system. (Citation: Linux Kernel Programming) <br /><br />When used maliciously, LKMs can be a type of kernel-mode [Rootkit](https://attack.mitre.org/techniques/T1014) that run with the highest operating system privilege (Ring 0). (Citation: Linux Kernel Module Programming Guide) Common features of LKM based rootkits include: hiding itself, selective hiding of files, processes and network activity, as well as log tampering, providing authenticated backdoors and enabling root access to non-privileged users. (Citation: iDefense Rootkit Overview)<br /><br />Kernel extensions, also called kext, are used for macOS to load functionality onto a system similar to LKMs for Linux. They are loaded and unloaded through <code>kextload</code> and <code>kextunload</code> commands.<br /><br />Adversaries can use LKMs and kexts to covertly persist on a system and elevate privileges. Examples have been found in the wild and there are some open source projects. (Citation: Volatility Phalanx2) (Citation: CrowdStrike Linux Rootkit) (Citation: GitHub Reptile) (Citation: GitHub Diamorphine)(Citation: RSAC 2015 San Francisco Patrick Wardle) (Citation: Synack Secure Kernel Extension Broken)(Citation: Securelist Ventir) (Citation: Trend Micro Skidmap)<br /><br />",
    "technique_references": [
      {
        "source_name": "Linux Kernel Programming",
        "url": "https://www.tldp.org/LDP/lkmpg/2.4/lkmpg.pdf",
        "description": "Pomerantz, O., Salzman, P.. (2003, April 4). The Linux Kernel Module Programming Guide. Retrieved April 6, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Linux Kernel Module Programming Guide",
        "url": "http://www.tldp.org/LDP/lkmpg/2.4/html/x437.html",
        "description": "Pomerantz, O., Salzman, P. (2003, April 4). Modules vs Programs. Retrieved April 6, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "iDefense Rootkit Overview",
        "url": "http://www.megasecurity.org/papers/Rootkits.pdf",
        "description": "Chuvakin, A. (2003, February). An Overview of Rootkits. Retrieved April 6, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Volatility Phalanx2",
        "url": "https://volatility-labs.blogspot.com/2012/10/phalanx-2-revealed-using-volatility-to.html",
        "description": "Case, A. (2012, October 10). Phalanx 2 Revealed: Using Volatility to Analyze an Advanced Linux Rootkit. Retrieved April 9, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "CrowdStrike Linux Rootkit",
        "url": "https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/",
        "description": "Kurtz, G. (2012, November 19). HTTP iframe Injecting Linux Rootkit. Retrieved December 21, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Reptile",
        "url": "https://github.com/f0rb1dd3n/Reptile",
        "description": "Augusto, I. (2018, March 8). Reptile - LMK Linux rootkit. Retrieved April 9, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub Diamorphine",
        "url": "https://github.com/m0nad/Diamorphine",
        "description": "Mello, V. (2018, March 8). Diamorphine - LMK rootkit for Linux Kernels 2.6.x/3.x/4.x (x86 and x86_64). Retrieved April 9, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "RSAC 2015 San Francisco Patrick Wardle",
        "url": "https://www.rsaconference.com/writable/presentations/file_upload/ht-r03-malware-persistence-on-os-x-yosemite_final.pdf",
        "description": "Wardle, P. (2015, April). Malware Persistence on OS X Yosemite. Retrieved April 6, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Synack Secure Kernel Extension Broken",
        "url": "https://www.synack.com/2017/09/08/high-sierras-secure-kernel-extension-loading-is-broken/",
        "description": "Wardle, P. (2017, September 8). High Sierra’s ‘Secure Kernel Extension Loading’ is Broken. Retrieved April 6, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Securelist Ventir",
        "url": "https://securelist.com/the-ventir-trojan-assemble-your-macos-spy/67267/",
        "description": "Mikhail, K. (2014, October 16). The Ventir Trojan: assemble your MacOS spy. Retrieved April 6, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Trend Micro Skidmap",
        "url": "https://blog.trendmicro.com/trendlabs-security-intelligence/skidmap-linux-malware-uses-rootkit-capabilities-to-hide-cryptocurrency-mining-payload/",
        "description": "Remillano, A., Urbanec, J. (2019, September 19). Skidmap Linux Malware Uses Rootkit Capabilities to Hide Cryptocurrency-Mining Payload. Retrieved June 4, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Linux Loadable Kernel Module Insert and Remove LKMs",
        "url": "http://tldp.org/HOWTO/Module-HOWTO/x197.html",
        "description": "Henderson, B. (2006, September 24). How To Insert And Remove LKMs. Retrieved April 9, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Wikipedia Loadable Kernel Module",
        "url": "https://en.wikipedia.org/wiki/Loadable_kernel_module#Linux",
        "description": "Wikipedia. (2018, March 17). Loadable kernel module. Retrieved April 9, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--e5cc9e7a-e61a-46a1-b869-55fb6eab058e",
    "platform": "macos",
    "tid": "T1547.007",
    "technique": "Re-opened Applications",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may modify plist files to automatically run an application when a user logs in. Starting in Mac OS X 10.7 (Lion), users can specify certain applications to be re-opened when a user logs into their machine after reboot. While this is usually done via a Graphical User Interface (GUI) on an app-by-app basis, there are property list files (plist) that contain this information as well located at <code>~/Library/Preferences/com.apple.loginwindow.plist</code> and <code>~/Library/Preferences/ByHost/com.apple.loginwindow.* .plist</code>. <br /><br />An adversary can modify one of these files directly to include a link to their malicious executable to provide a persistence mechanism each time the user reboots their machine (Citation: Methods of Mac Malware Persistence).<br /><br />",
    "technique_references": [
      {
        "source_name": "Methods of Mac Malware Persistence",
        "url": "https://www.virusbulletin.com/uploads/pdf/conference/vb2014/VB2014-Wardle.pdf",
        "description": "Patrick Wardle. (2014, September). Methods of Malware Persistence on Mac OS X. Retrieved July 5, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--f0589bc3-a6ae-425a-a3d5-5659bfee07f4",
    "platform": "windows",
    "tid": "T1547.008",
    "technique": "LSASS Driver",
    "tactic": "privilege-escalation",
    "datasources": "dll-monitoring|file-monitoring|loaded-dlls|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may modify or add LSASS drivers to obtain persistence on compromised systems. The Windows security subsystem is a set of components that manage and enforce the security policy for a computer or domain. The Local Security Authority (LSA) is the main component responsible for local security policy and user authentication. The LSA includes multiple dynamic link libraries (DLLs) associated with various other security functions, all of which run in the context of the LSA Subsystem Service (LSASS) lsass.exe process. (Citation: Microsoft Security Subsystem)<br /><br />Adversaries may target LSASS drivers to obtain persistence. By either replacing or adding illegitimate drivers (e.g., [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574)), an adversary can use LSA operations to continuously execute malicious payloads.<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft Security Subsystem",
        "url": "https://technet.microsoft.com/library/cc961760.aspx",
        "description": "Microsoft. (n.d.). Security Subsystem Architecture. Retrieved November 27, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft LSA Protection Mar 2014",
        "url": "https://technet.microsoft.com/library/dn408187.aspx",
        "description": "Microsoft. (2014, March 12). Configuring Additional LSA Protection. Retrieved November 27, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft DLL Security",
        "url": "https://msdn.microsoft.com/library/windows/desktop/ff919712.aspx",
        "description": "Microsoft. (n.d.). Dynamic-Link Library Security. Retrieved November 27, 2017.",
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
    "id": "attack-pattern--4ab929c6-ee2d-4fb5-aab4-b14be2ed7179",
    "platform": "windows",
    "tid": "T1547.009",
    "technique": "Shortcut Modification",
    "tactic": "privilege-escalation",
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
    "technique_description": "Adversaries may create or edit shortcuts to run a program during system boot or user login. Shortcuts or symbolic links are ways of referencing other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process.<br /><br />Adversaries could use shortcuts to execute their tools for persistence. They may create a new shortcut as a means of indirection that may use [Masquerading](https://attack.mitre.org/techniques/T1036) to look like a legitimate program. Adversaries could also edit the target path or entirely replace an existing shortcut so their tools will be executed instead of the intended legitimate program.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/132.html",
        "description": "none",
        "external_id": "CAPEC-132"
      }
    ]
  },
  {
    "id": "attack-pattern--43881e51-ac74-445b-b4c6-f9f9e9bf23fe",
    "platform": "windows",
    "tid": "T1547.010",
    "technique": "Port Monitors",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|dll-monitoring|file-monitoring|process-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use port monitors to run an attacker supplied DLL during system boot for persistence or privilege escalation. A port monitor can be set through the <code>AddMonitor</code> API call to set a DLL to be loaded at startup. (Citation: AddMonitor) This DLL can be located in <code>C:\\Windows\\System32</code> and will be loaded by the print spooler service, spoolsv.exe, on boot. The spoolsv.exe process also runs under SYSTEM level permissions. (Citation: Bloxham) Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to <code>HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors</code>. <br /><br />The Registry key contains entries for the following:<br /><br />* Local Port<br /><br />* Standard TCP/IP Port<br /><br />* USB Monitor<br /><br />* WSD Port<br /><br />Adversaries can use this technique to load malicious code at startup that will persist on system reboot and execute as SYSTEM.<br /><br />",
    "technique_references": [
      {
        "source_name": "AddMonitor",
        "url": "http://msdn.microsoft.com/en-us/library/dd183341",
        "description": "Microsoft. (n.d.). AddMonitor function. Retrieved November 12, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Bloxham",
        "url": "https://www.defcon.org/images/defcon-22/dc-22-presentations/Bloxham/DEFCON-22-Brady-Bloxham-Windows-API-Abuse-UPDATED.pdf",
        "description": "Bloxham, B. (n.d.). Getting Windows to Play with Itself &#91;PowerPoint slides&#93;. Retrieved November 12, 2014.",
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
    "id": "attack-pattern--6747daa2-3533-4e78-8fb8-446ebb86448a",
    "platform": "macos",
    "tid": "T1547.011",
    "technique": "Plist Modification",
    "tactic": "privilege-escalation",
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
    "technique_description": "Adversaries may modify plist files to run a program during system boot or user login. Property list (plist) files contain all of the information that macOS and OS X uses to configure applications and services. These files are UTF-8 encoded and formatted like XML documents via a series of keys surrounded by < >. They detail when programs should execute, file paths to the executables, program arguments, required OS permissions, and many others. plists are located in certain locations depending on their purpose such as <code>/Library/Preferences</code> (which execute with elevated privileges) and <code>~/Library/Preferences</code> (which execute with a user's privileges). <br /><br />Adversaries can modify plist files to execute their code as part of establishing persistence. plists may also be used to elevate privileges since they may execute in the context of another user.(Citation: Sofacy Komplex Trojan) <br /><br />A specific plist used for execution at login is <code>com.apple.loginitems.plist</code>.(Citation: Methods of Mac Malware Persistence) Applications under this plist run under the logged in user's context, and will be started every time the user logs in. Login items installed using the Service Management Framework are not visible in the System Preferences and can only be removed by the application that created them.(Citation: Adding Login Items) Users have direct control over login items installed using a shared file list which are also visible in System Preferences (Citation: Adding Login Items). Some of these applications can open visible dialogs to the user, but they don’t all have to since there is an option to \"hide\" the window. If an adversary can register their own login item or modified an existing one, then they can use it to execute their code for a persistence mechanism each time the user logs in (Citation: Malware Persistence on OS X) (Citation: OSX.Dok Malware). The API method <code> SMLoginItemSetEnabled</code> can be used to set Login Items, but scripting languages like [AppleScript](https://attack.mitre.org/techniques/T1059/002) can do this as well. (Citation: Adding Login Items)<br /><br />",
    "technique_references": [
      {
        "source_name": "Sofacy Komplex Trojan",
        "url": "https://researchcenter.paloaltonetworks.com/2016/09/unit42-sofacys-komplex-os-x-trojan/",
        "description": "Dani Creus, Tyler Halfpop, Robert Falcone. (2016, September 26). Sofacy's 'Komplex' OS X Trojan. Retrieved July 8, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Methods of Mac Malware Persistence",
        "url": "https://www.virusbulletin.com/uploads/pdf/conference/vb2014/VB2014-Wardle.pdf",
        "description": "Patrick Wardle. (2014, September). Methods of Malware Persistence on Mac OS X. Retrieved July 5, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Adding Login Items",
        "url": "https://developer.apple.com/library/content/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLoginItems.html",
        "description": "Apple. (2016, September 13). Adding Login Items. Retrieved July 11, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Malware Persistence on OS X",
        "url": "https://www.rsaconference.com/writable/presentations/file_upload/ht-r03-malware-persistence-on-os-x-yosemite_final.pdf",
        "description": "Patrick Wardle. (2015). Malware Persistence on OS X Yosemite. Retrieved July 10, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "OSX.Dok Malware",
        "url": "https://blog.malwarebytes.com/threat-analysis/2017/04/new-osx-dok-malware-intercepts-web-traffic/",
        "description": "Thomas Reed. (2017, July 7). New OSX.Dok malware intercepts web traffic. Retrieved July 10, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--2de47683-f398-448f-b947-9abcc3e32fad",
    "platform": "windows",
    "tid": "T1547.012",
    "technique": "Print Processors",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|dll-monitoring|file-monitoring|process-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may abuse print processors to run malicious DLLs during system boot for persistence and/or privilege escalation. Print processors are DLLs that are loaded by the print spooler service, spoolsv.exe, during boot. <br /><br />Adversaries may abuse the print spooler service by adding print processors that load malicious DLLs at startup. A print processor can be installed through the <code>AddPrintProcessor</code> API call with an account that has <code>SeLoadDriverPrivilege</code> enabled. Alternatively, a print processor can be registered to the print spooler service by adding the <code>HKLM\\SYSTEM\\\\[CurrentControlSet or ControlSet001]\\Control\\Print\\Environments\\\\[Windows architecture: e.g., Windows x64]\\Print Processors\\\\[user defined]\\Driver</code> Registry key that points to the DLL. For the print processor to be correctly installed, it must be located in the system print-processor directory that can be found with the <code>GetPrintProcessorDirectory</code> API call.(Citation: Microsoft AddPrintProcessor May 2018) After the print processors are installed, the print spooler service, which starts during boot, must be restarted in order for them to run.(Citation: ESET PipeMon May 2020) The print spooler service runs under SYSTEM level permissions, therefore print processors installed by an adversary may run under elevated privileges.<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft AddPrintProcessor May 2018",
        "url": "https://docs.microsoft.com/en-us/windows/win32/printdocs/addprintprocessor",
        "description": "Microsoft. (2018, May 31). AddPrintProcessor function. Retrieved October 5, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "ESET PipeMon May 2020",
        "url": "https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/",
        "description": "Tartare, M. et al. (2020, May 21). No “Game over” for the Winnti Group. Retrieved August 24, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--6831414d-bb70-42b7-8030-d4e06b2660c9",
    "platform": "linux|macos",
    "tid": "T1548.001",
    "technique": "Setuid and Setgid",
    "tactic": "privilege-escalation",
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
    "technique_description": "An adversary may perform shell escapes or exploit vulnerabilities in an application with the setsuid or setgid bits to get code running in a different user’s context. On Linux or macOS, when the setuid or setgid bits are set for an application, the application will run with the privileges of the owning user or group respectively. (Citation: setuid man page). Normally an application is run in the current user’s context, regardless of which user or group owns the application. However, there are instances where programs need to be executed in an elevated context to function properly, but the user running them doesn’t need the elevated privileges.<br /><br />Instead of creating an entry in the sudoers file, which must be done by root, any user can specify the setuid or setgid flag to be set for their own applications. These bits are indicated with an \"s\" instead of an \"x\" when viewing a file's attributes via <code>ls -l</code>. The <code>chmod</code> program can set these bits with via bitmasking, <code>chmod 4777 [file]</code> or via shorthand naming, <code>chmod u+s [file]</code>.<br /><br />Adversaries can use this mechanism on their own malware to make sure they're able to execute in elevated contexts in the future.(Citation: OSX Keydnap malware).<br /><br />",
    "technique_references": [
      {
        "source_name": "setuid man page",
        "url": "http://man7.org/linux/man-pages/man2/setuid.2.html",
        "description": "Michael Kerrisk. (2017, September 15). Linux Programmer's Manual. Retrieved September 21, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "OSX Keydnap malware",
        "url": "https://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-hungry-credentials/",
        "description": "Marc-Etienne M.Leveille. (2016, July 6). New OSX/Keydnap malware is hungry for credentials. Retrieved July 3, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--120d5519-3098-4e1c-9191-2aa61232f073",
    "platform": "windows",
    "tid": "T1548.002",
    "technique": "Bypass User Account Control",
    "tactic": "privilege-escalation",
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
    "technique_description": "Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate its privileges (tracked as integrity levels ranging from low to high) to perform a task under administrator-level permissions, possibly by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action. (Citation: TechNet How UAC Works)<br /><br />If the UAC protection level of a computer is set to anything but the highest level, certain Windows programs can elevate privileges or execute some elevated [Component Object Model](https://attack.mitre.org/techniques/T1559/001) objects without prompting the user through the UAC notification box. (Citation: TechNet Inside UAC) (Citation: MSDN COM Elevation) An example of this is use of [Rundll32](https://attack.mitre.org/techniques/T1218/011) to load a specifically crafted DLL which loads an auto-elevated [Component Object Model](https://attack.mitre.org/techniques/T1559/001) object and performs a file operation in a protected directory which would typically require elevated access. Malicious software may also be injected into a trusted process to gain elevated privileges without prompting a user.(Citation: Davidson Windows)<br /><br />Many methods have been discovered to bypass UAC. The Github readme page for UACME contains an extensive list of methods(Citation: Github UACMe) that have been discovered and implemented, but may not be a comprehensive list of bypasses. Additional bypass methods are regularly discovered and some used in the wild, such as:<br /><br />* <code>eventvwr.exe</code> can auto-elevate and execute a specified binary or script.(Citation: enigma0x3 Fileless UAC Bypass)(Citation: Fortinet Fareit)<br /><br />Another bypass is possible through some lateral movement techniques if credentials for an account with administrator privileges are known, since UAC is a single system security mechanism, and the privilege or integrity of a process running on one system will be unknown on remote systems and default to high integrity.(Citation: SANS UAC Bypass)<br /><br />",
    "technique_references": [
      {
        "source_name": "TechNet How UAC Works",
        "url": "https://technet.microsoft.com/en-us/itpro/windows/keep-secure/how-user-account-control-works",
        "description": "Lich, B. (2016, May 31). How User Account Control Works. Retrieved June 3, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "TechNet Inside UAC",
        "url": "https://technet.microsoft.com/en-US/magazine/2009.07.uac.aspx",
        "description": "Russinovich, M. (2009, July). User Account Control: Inside Windows 7 User Account Control. Retrieved July 26, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "MSDN COM Elevation",
        "url": "https://msdn.microsoft.com/en-us/library/ms679687.aspx",
        "description": "Microsoft. (n.d.). The COM Elevation Moniker. Retrieved July 26, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Davidson Windows",
        "url": "http://www.pretentiousname.com/misc/win7_uac_whitelist2.html",
        "description": "Davidson, L. (n.d.). Windows 7 UAC whitelist. Retrieved November 12, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Github UACMe",
        "url": "https://github.com/hfiref0x/UACME",
        "description": "UACME Project. (2016, June 16). UACMe. Retrieved July 26, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "enigma0x3 Fileless UAC Bypass",
        "url": "https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/",
        "description": "Nelson, M. (2016, August 15). \"Fileless\" UAC Bypass using eventvwr.exe and Registry Hijacking. Retrieved December 27, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Fortinet Fareit",
        "url": "https://blog.fortinet.com/2016/12/16/malicious-macro-bypasses-uac-to-elevate-privilege-for-fareit-malware",
        "description": "Salvio, J., Joven, R. (2016, December 16). Malicious Macro Bypasses UAC to Elevate Privilege for Fareit Malware. Retrieved December 27, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "SANS UAC Bypass",
        "url": "http://pen-testing.sans.org/blog/pen-testing/2013/08/08/psexec-uac-bypass",
        "description": "Medin, T. (2013, August 8). PsExec UAC Bypass. Retrieved June 3, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "enigma0x3 sdclt app paths",
        "url": "https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/",
        "description": "Nelson, M. (2017, March 14). Bypassing UAC using App Paths. Retrieved May 25, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "enigma0x3 sdclt bypass",
        "url": "https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/",
        "description": "Nelson, M. (2017, March 17). \"Fileless\" UAC Bypass Using sdclt.exe. Retrieved May 25, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--1365fe3b-0f50-455d-b4da-266ce31c23b0",
    "platform": "linux|macos",
    "tid": "T1548.003",
    "technique": "Sudo and Sudo Caching",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-command-line-parameters",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may perform sudo caching and/or use the suoders file to elevate privileges. Adversaries may do this to execute commands as other users or spawn processes with higher privileges.<br /><br />Within Linux and MacOS systems, sudo (sometimes referred to as \"superuser do\") allows users to perform commands from terminals with elevated privileges and to control who can perform these commands on the system. The <code>sudo</code> command \"allows a system administrator to delegate authority to give certain users (or groups of users) the ability to run some (or all) commands as root or another user while providing an audit trail of the commands and their arguments.\"(Citation: sudo man page 2018) Since sudo was made for the system administrator, it has some useful configuration features such as a <code>timestamp_timeout</code>, which is the amount of time in minutes between instances of <code>sudo</code> before it will re-prompt for a password. This is because <code>sudo</code> has the ability to cache credentials for a period of time. Sudo creates (or touches) a file at <code>/var/db/sudo</code> with a timestamp of when sudo was last run to determine this timeout. Additionally, there is a <code>tty_tickets</code> variable that treats each new tty (terminal session) in isolation. This means that, for example, the sudo timeout of one tty will not affect another tty (you will have to type the password again).<br /><br />The sudoers file, <code>/etc/sudoers</code>, describes which users can run which commands and from which terminals. This also describes which commands users can run as other users or groups. This provides the principle of least privilege such that users are running in their lowest possible permissions for most of the time and only elevate to other users or permissions as needed, typically by prompting for a password. However, the sudoers file can also specify when to not prompt users for passwords with a line like <code>user1 ALL=(ALL) NOPASSWD: ALL</code> (Citation: OSX.Dok Malware). Elevated privileges are required to edit this file though.<br /><br />Adversaries can also abuse poor configurations of these mechanisms to escalate privileges without needing the user's password. For example, <code>/var/db/sudo</code>'s timestamp can be monitored to see if it falls within the <code>timestamp_timeout</code> range. If it does, then malware can execute sudo commands without needing to supply the user's password. Additional, if <code>tty_tickets</code> is disabled, adversaries can do this from any tty for that user.<br /><br />In the wild, malware has disabled <code>tty_tickets</code> to potentially make scripting easier by issuing <code>echo \\'Defaults !tty_tickets\\' >> /etc/sudoers</code> (Citation: cybereason osx proton). In order for this change to be reflected, the malware also issued <code>killall Terminal</code>. As of macOS Sierra, the sudoers file has <code>tty_tickets</code> enabled by default.<br /><br />",
    "technique_references": [
      {
        "source_name": "sudo man page 2018",
        "url": "https://www.sudo.ws/",
        "description": "Todd C. Miller. (2018). Sudo Man Page. Retrieved March 19, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "OSX.Dok Malware",
        "url": "https://blog.malwarebytes.com/threat-analysis/2017/04/new-osx-dok-malware-intercepts-web-traffic/",
        "description": "Thomas Reed. (2017, July 7). New OSX.Dok malware intercepts web traffic. Retrieved July 10, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "cybereason osx proton",
        "url": "https://www.cybereason.com/blog/labs-proton-b-what-this-mac-malware-actually-does",
        "description": "Amit Serper. (2018, May 10). ProtonB What this Mac Malware Actually Does. Retrieved March 19, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--b84903f0-c7d5-435d-a69e-de47cc3578c0",
    "platform": "macos",
    "tid": "T1548.004",
    "technique": "Elevated Execution with Prompt",
    "tactic": "privilege-escalation",
    "datasources": "api-monitoring|file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may leverage the <code>AuthorizationExecuteWithPrivileges</code> API to escalate privileges by prompting the user for credentials.(Citation: AppleDocs AuthorizationExecuteWithPrivileges) The purpose of this API is to give application developers an easy way to perform operations with root privileges, such as for application installation or updating. This API does not validate that the program requesting root privileges comes from a reputable source or has been maliciously modified. <br /><br />Although this API is deprecated, it still fully functions in the latest releases of macOS. When calling this API, the user will be prompted to enter their credentials but no checks on the origin or integrity of the program are made. The program calling the API may also load world writable files which can be modified to perform malicious behavior with elevated privileges.<br /><br />Adversaries may abuse <code>AuthorizationExecuteWithPrivileges</code> to obtain root privileges in order to install malicious software on victims and install persistence mechanisms.(Citation: Death by 1000 installers; it's all broken!)(Citation: Carbon Black Shlayer Feb 2019)(Citation: OSX Coldroot RAT) This technique may be combined with [Masquerading](https://attack.mitre.org/techniques/T1036) to trick the user into granting escalated privileges to malicious code.(Citation: Death by 1000 installers; it's all broken!)(Citation: Carbon Black Shlayer Feb 2019) This technique has also been shown to work by modifying legitimate programs present on the machine that make use of this API.(Citation: Death by 1000 installers; it's all broken!)<br /><br />",
    "technique_references": [
      {
        "source_name": "AppleDocs AuthorizationExecuteWithPrivileges",
        "url": "https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg",
        "description": "Apple. (n.d.). Apple Developer Documentation - AuthorizationExecuteWithPrivileges. Retrieved August 8, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Death by 1000 installers; it's all broken!",
        "url": "https://speakerdeck.com/patrickwardle/defcon-2017-death-by-1000-installers-its-all-broken?slide=8",
        "description": "Patrick Wardle. (2017). Death by 1000 installers; it's all broken!. Retrieved August 8, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Carbon Black Shlayer Feb 2019",
        "url": "https://www.carbonblack.com/2019/02/12/tau-threat-intelligence-notification-new-macos-malware-variant-of-shlayer-osx-discovered/",
        "description": "Carbon Black Threat Analysis Unit. (2019, February 12). New macOS Malware Variant of Shlayer (OSX) Discovered. Retrieved August 8, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "OSX Coldroot RAT",
        "url": "https://objective-see.com/blog/blog_0x2A.html",
        "description": "Patrick Wardle. (2018, February 17). Tearing Apart the Undetected (OSX)Coldroot RAT. Retrieved August 8, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--2fee9321-3e71-4cf4-af24-d4d40d355b34",
    "platform": "windows",
    "tid": "T1574.001",
    "technique": "DLL Search Order Hijacking",
    "tactic": "privilege-escalation",
    "datasources": "dll-monitoring|file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs. Windows systems use a common method to look for required DLLs to load into a program. (Citation: Microsoft Dynamic Link Library Search Order) Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution.<br /><br />There are many ways an adversary can hijack DLL loads. Adversaries may plant trojan dynamic-link library files (DLLs) in a directory that will be searched before the location of a legitimate library that will be requested by a program, causing Windows to load their malicious library when it is called for by the victim program. Adversaries may also perform DLL preloading, also called binary planting attacks, (Citation: OWASP Binary Planting) by placing a malicious DLL with the same name as an ambiguously specified DLL in a location that Windows searches before the legitimate DLL. Often this location is the current working directory of the program. Remote DLL preloading attacks occur when a program sets its current directory to a remote location such as a Web share before loading a DLL. (Citation: Microsoft Security Advisory 2269637)<br /><br />Adversaries may also directly modify the way a program loads DLLs by replacing an existing DLL or modifying a .manifest or .local redirection file, directory, or junction to cause the program to load a different DLL. (Citation: Microsoft Dynamic-Link Library Redirection) (Citation: Microsoft Manifests) (Citation: FireEye DLL Search Order Hijacking)<br /><br />If a search order-vulnerable program is configured to run at a higher privilege level, then the adversary-controlled DLL that is loaded will also be executed at the higher level. In this case, the technique could be used for privilege escalation from user to administrator or SYSTEM or from administrator to SYSTEM, depending on the program.<br /><br />Programs that fall victim to path hijacking may appear to behave normally because malicious DLLs may be configured to also load the legitimate DLLs they were meant to replace.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/471.html",
        "description": "none",
        "external_id": "CAPEC-471"
      },
      {
        "source_name": "Microsoft Dynamic Link Library Search Order",
        "url": "https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order?redirectedfrom=MSDN",
        "description": "Microsoft. (2018, May 31). Dynamic-Link Library Search Order. Retrieved November 30, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "OWASP Binary Planting",
        "url": "https://www.owasp.org/index.php/Binary_planting",
        "description": "OWASP. (2013, January 30). Binary planting. Retrieved June 7, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Security Advisory 2269637",
        "url": "https://docs.microsoft.com/en-us/security-updates/securityadvisories/2010/2269637",
        "description": "Microsoft. (, May 23). Microsoft Security Advisory 2269637. Retrieved March 13, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Dynamic-Link Library Redirection",
        "url": "https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection?redirectedfrom=MSDN",
        "description": "Microsoft. (2018, May 31). Dynamic-Link Library Redirection. Retrieved March 13, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Manifests",
        "url": "https://msdn.microsoft.com/en-US/library/aa375365",
        "description": "Microsoft. (n.d.). Manifests. Retrieved December 5, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye DLL Search Order Hijacking",
        "url": "https://www.fireeye.com/blog/threat-research/2010/08/dll-search-order-hijacking-revisited.html",
        "description": "Nick Harbour. (2010, September 1). DLL Search Order Hijacking Revisited. Retrieved March 13, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--e64c62cf-9cd7-4a14-94ec-cdaac43ab44b",
    "platform": "windows",
    "tid": "T1574.002",
    "technique": "DLL Side-Loading",
    "tactic": "privilege-escalation",
    "datasources": "loaded-dlls|process-monitoring|process-use-of-network",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may execute their own malicious payloads by hijacking the library manifest used to load DLLs. Adversaries may take advantage of vague references in the library manifest of a program by replacing a legitimate library with a malicious one, causing the operating system to load their malicious library when it is called for by the victim program.<br /><br />Programs may specify DLLs that are loaded at runtime. Programs that improperly or vaguely specify a required DLL may be open to a vulnerability in which an unintended DLL is loaded. Side-loading vulnerabilities specifically occur when Windows Side-by-Side (WinSxS) manifests (Citation: About Side by Side Assemblies) are not explicit enough about characteristics of the DLL to be loaded. Adversaries may take advantage of a legitimate program that is vulnerable by replacing the legitimate DLL with a malicious one.  (Citation: FireEye DLL Side-Loading)<br /><br />Adversaries likely use this technique as a means of masking actions they perform under a legitimate, trusted system or software process.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/641.html",
        "description": "none",
        "external_id": "CAPEC-641"
      },
      {
        "source_name": "About Side by Side Assemblies",
        "url": "https://docs.microsoft.com/en-us/windows/win32/sbscs/about-side-by-side-assemblies-",
        "description": "Microsoft. (2018, May 31). About Side-by-Side Assemblies. Retrieved March 13, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "FireEye DLL Side-Loading",
        "url": "https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf",
        "description": "Amanda Steward. (2014). FireEye DLL Side-Loading: A Thorn in the Side of the Anti-Virus Industry. Retrieved March 13, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--fc742192-19e3-466c-9eb5-964a97b29490",
    "platform": "macos",
    "tid": "T1574.004",
    "technique": "Dylib Hijacking",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may execute their own malicious payloads by hijacking ambiguous paths  used to load libraries. Adversaries may plant trojan dynamic libraries, in a directory that will be searched by the operating system before the legitimate library specified by the victim program, so that their malicious library will be loaded into the victim program instead.  MacOS and OS X use a common method to look for required dynamic libraries (dylib) to load into a program based on search paths.<br /><br />A common method is to see what dylibs an application uses, then plant a malicious version with the same name higher up in the search path. This typically results in the dylib being in the same folder as the application itself. (Citation: Writing Bad Malware for OSX) (Citation: Malware Persistence on OS X)<br /><br />If the program is configured to run at a higher privilege level than the current user, then when the dylib is loaded into the application, the dylib will also run at that elevated level.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/471.html",
        "description": "none",
        "external_id": "CAPEC-471"
      },
      {
        "source_name": "Writing Bad Malware for OSX",
        "url": "https://www.blackhat.com/docs/us-15/materials/us-15-Wardle-Writing-Bad-A-Malware-For-OS-X.pdf",
        "description": "Patrick Wardle. (2015). Writing Bad @$$ Malware for OS X. Retrieved July 10, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Malware Persistence on OS X",
        "url": "https://www.rsaconference.com/writable/presentations/file_upload/ht-r03-malware-persistence-on-os-x-yosemite_final.pdf",
        "description": "Patrick Wardle. (2015). Malware Persistence on OS X Yosemite. Retrieved July 10, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--70d81154-b187-45f9-8ec5-295d01255979",
    "platform": "windows",
    "tid": "T1574.005",
    "technique": "Executable Installer File Permissions Weakness",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-command-line-parameters",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer. These processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.<br /><br />Another variation of this technique can be performed by taking advantage of a weakness that is common in executable, self-extracting installers. During the installation process, it is common for installers to use a subdirectory within the <code>%TEMP%</code> directory to unpack binaries such as DLLs, EXEs, or other payloads. When installers create subdirectories and files they often do not set appropriate permissions to restrict write access, which allows for execution of untrusted code placed in the subdirectories or overwriting of binaries used in the installation process. This behavior is related to and may take advantage of [DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001).<br /><br />Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. Some installers may also require elevated privileges that will result in privilege escalation when executing adversary controlled code. This behavior is related to [Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002). Several examples of this weakness in existing common installers have been reported to software vendors.(Citation: mozilla_sec_adv_2012)  (Citation: Executable Installers are Vulnerable) If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.<br /><br />",
    "technique_references": [
      {
        "source_name": "mozilla_sec_adv_2012",
        "url": "https://www.mozilla.org/en-US/security/advisories/mfsa2012-98/",
        "description": "Robert Kugler. (2012, November 20). Mozilla Foundation Security Advisory 2012-98. Retrieved March 10, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Executable Installers are Vulnerable",
        "url": "https://seclists.org/fulldisclosure/2015/Dec/34",
        "description": "Stefan Kanthak. (2015, December 8). Executable installers are vulnerable^WEVIL (case 7): 7z*.exe allows remote code execution with escalation of privilege. Retrieved December 4, 2014.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--633a100c-b2c9-41bf-9be5-905c1b16c825",
    "platform": "linux",
    "tid": "T1574.006",
    "technique": "LD_PRELOAD",
    "tactic": "privilege-escalation",
    "datasources": "environment-variable|file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may execute their own malicious payloads by hijacking the dynamic linker used to load libraries. The dynamic linker is used to load shared library dependencies needed by an executing program. The dynamic linker will typically check provided absolute paths and common directories for these dependencies, but can be overridden by shared objects specified by LD_PRELOAD to be loaded before all others.(Citation: Man LD.SO)(Citation: TLDP Shared Libraries)<br /><br />Adversaries may set LD_PRELOAD to point to malicious libraries that match the name of legitimate libraries which are requested by a victim program, causing the operating system to load the adversary's malicious code upon execution of the victim program. LD_PRELOAD can be set via the environment variable or <code>/etc/ld.so.preload</code> file.(Citation: Man LD.SO)(Citation: TLDP Shared Libraries) Libraries specified by LD_PRELOAD with be loaded and mapped into memory by <code>dlopen()</code> and <code>mmap()</code> respectively.(Citation: Code Injection on Linux and macOS) (Citation: Uninformed Needle) (Citation: Phrack halfdead 1997)<br /><br />LD_PRELOAD hijacking may grant access to the victim process's memory, system/network resources, and possibly elevated privileges. Execution via LD_PRELOAD hijacking may also evade detection from security products since the execution is masked under a legitimate process.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/13.html",
        "description": "none",
        "external_id": "CAPEC-13"
      },
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/640.html",
        "description": "none",
        "external_id": "CAPEC-640"
      },
      {
        "source_name": "Man LD.SO",
        "url": "https://www.man7.org/linux/man-pages/man8/ld.so.8.html",
        "description": "Kerrisk, M. (2020, June 13). Linux Programmer's Manual. Retrieved June 15, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "TLDP Shared Libraries",
        "url": "https://www.tldp.org/HOWTO/Program-Library-HOWTO/shared-libraries.html",
        "description": "The Linux Documentation Project. (n.d.). Shared Libraries. Retrieved January 31, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Code Injection on Linux and macOS",
        "url": "https://www.datawire.io/code-injection-on-linux-and-macos/",
        "description": "Itamar Turner-Trauring. (2017, April 18). “This will only hurt for a moment”: code injection on Linux and macOS with LD_PRELOAD. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Uninformed Needle",
        "url": "http://hick.org/code/skape/papers/needle.txt",
        "description": "skape. (2003, January 19). Linux x86 run-time process manipulation. Retrieved December 20, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Phrack halfdead 1997",
        "url": "http://phrack.org/issues/51/8.html",
        "description": "halflife. (1997, September 1). Shared Library Redirection Techniques. Retrieved December 20, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0c2d00da-7742-49e7-9928-4514e5075d32",
    "platform": "windows",
    "tid": "T1574.007",
    "technique": "Path Interception by PATH Environment Variable",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries. Adversaries may place a program in an earlier entry in the list of directories stored in the PATH environment variable, which Windows will then execute when it searches sequentially through that PATH listing in search of the binary that was called from a script or the command line.<br /><br />The PATH environment variable contains a list of directories. Certain methods of executing a program (namely using cmd.exe or the command-line) rely solely on the PATH environment variable to determine the locations that are searched for a program when the path for the program is not given. If any directories are listed in the PATH environment variable before the Windows directory, <code>%SystemRoot%\\system32</code> (e.g., <code>C:\\Windows\\system32</code>), a program may be placed in the preceding directory that is named the same as a Windows program (such as cmd, PowerShell, or Python), which will be executed when that command is executed from a script or command-line.<br /><br />For example, if <code>C:\\example path</code> precedes </code>C:\\Windows\\system32</code> is in the PATH environment variable, a program that is named net.exe and placed in <code>C:\\example path</code> will be called instead of the Windows system \"net\" when \"net\" is executed from the command-line.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/13.html",
        "description": "none",
        "external_id": "CAPEC-13"
      },
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/38.html",
        "description": "none",
        "external_id": "CAPEC-38"
      }
    ]
  },
  {
    "id": "attack-pattern--58af3705-8740-4c68-9329-ec015a7013c2",
    "platform": "windows",
    "tid": "T1574.008",
    "technique": "Path Interception by Search Order Hijacking",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the operating system to launch their malicious software at the request of the calling program.<br /><br />Search order hijacking occurs when an adversary abuses the order in which Windows searches for programs that are not given a path. Unlike [DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001), the search order differs depending on the method that is used to execute the program. (Citation: Microsoft CreateProcess) (Citation: Windows NT Command Shell) (Citation: Microsoft WinExec) However, it is common for Windows to search in the directory of the initiating program before searching through the Windows system directory. An adversary who finds a program vulnerable to search order hijacking (i.e., a program that does not specify the path to an executable) may take advantage of this vulnerability by creating a program named after the improperly specified program and placing it within the initiating program's directory.<br /><br />For example, \"example.exe\" runs \"cmd.exe\" with the command-line argument <code>net user</code>. An adversary may place a program called \"net.exe\" within the same directory as example.exe, \"net.exe\" will be run instead of the Windows system utility net. In addition, if an adversary places a program called \"net.com\" in the same directory as \"net.exe\", then <code>cmd.exe /C net user</code> will execute \"net.com\" instead of \"net.exe\" due to the order of executable extensions defined under PATHEXT. (Citation: Microsoft Environment Property)<br /><br />Search order hijacking is also a common practice for hijacking DLL loads and is covered in [DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001).<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/159.html",
        "description": "none",
        "external_id": "CAPEC-159"
      },
      {
        "source_name": "Microsoft CreateProcess",
        "url": "http://msdn.microsoft.com/en-us/library/ms682425",
        "description": "Microsoft. (n.d.). CreateProcess function. Retrieved December 5, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Windows NT Command Shell",
        "url": "https://docs.microsoft.com/en-us/previous-versions//cc723564(v=technet.10)?redirectedfrom=MSDN#XSLTsection127121120120",
        "description": "Tim Hill. (2014, February 2). The Windows NT Command Shell. Retrieved December 5, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft WinExec",
        "url": "http://msdn.microsoft.com/en-us/library/ms687393",
        "description": "Microsoft. (n.d.). WinExec function. Retrieved December 5, 2014.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Environment Property",
        "url": "https://docs.microsoft.com/en-us/previous-versions//fd7hxfdd(v=vs.85)?redirectedfrom=MSDN",
        "description": "Microsoft. (2011, October 24). Environment Property. Retrieved July 27, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--bf96a5a3-3bce-43b7-8597-88545984c07b",
    "platform": "windows",
    "tid": "T1574.009",
    "technique": "Path Interception by Unquoted Path",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may execute their own malicious payloads by hijacking vulnerable file path references. Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch.<br /><br />Service paths (Citation: Microsoft CurrentControlSet Services) and shortcut paths may also be vulnerable to path interception if the path has one or more spaces and is not surrounded by quotation marks (e.g., <code>C:\\unsafe path with space\\program.exe</code> vs. <code>\"C:\\safe path with space\\program.exe\"</code>). (Citation: Help eliminate unquoted path) (stored in Windows Registry keys) An adversary can place an executable in a higher level directory of the path, and Windows will resolve that executable instead of the intended executable. For example, if the path in a shortcut is <code>C:\\program files\\myapp.exe</code>, an adversary may create a program at <code>C:\\program.exe</code> that will be run instead of the intended program. (Citation: Windows Unquoted Services) (Citation: Windows Privilege Escalation Guide)<br /><br />This technique can be used for persistence if executables are called on a regular basis, as well as privilege escalation if intercepted executables are started by a higher privileged process.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/38.html",
        "description": "none",
        "external_id": "CAPEC-38"
      },
      {
        "source_name": "Microsoft CurrentControlSet Services",
        "url": "https://docs.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree",
        "description": "Microsoft. (2017, April 20). HKLM\\SYSTEM\\CurrentControlSet\\Services Registry Tree. Retrieved March 16, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Help eliminate unquoted path",
        "url": "https://isc.sans.edu/diary/Help+eliminate+unquoted+path+vulnerabilities/14464",
        "description": "Mark Baggett. (2012, November 8). Help eliminate unquoted path vulnerabilities. Retrieved November 8, 2012.",
        "external_id": "none"
      },
      {
        "source_name": "Windows Unquoted Services",
        "url": "https://securityboulevard.com/2018/04/windows-privilege-escalation-unquoted-services/",
        "description": "HackHappy. (2018, April 23). Windows Privilege Escalation – Unquoted Services. Retrieved August 10, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Windows Privilege Escalation Guide",
        "url": "https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/",
        "description": "absolomb. (2018, January 26). Windows Privilege Escalation Guide. Retrieved August 10, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--9e8b28c9-35fe-48ac-a14d-e6cc032dcbcd",
    "platform": "windows",
    "tid": "T1574.010",
    "technique": "Services File Permissions Weakness",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-command-line-parameters|services",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.<br /><br />Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/17.html",
        "description": "none",
        "external_id": "CAPEC-17"
      }
    ]
  },
  {
    "id": "attack-pattern--17cc750b-e95b-4d7d-9dde-49e0de24148c",
    "platform": "windows",
    "tid": "T1574.011",
    "technique": "Services Registry Permissions Weakness",
    "tactic": "privilege-escalation",
    "datasources": "process-command-line-parameters|services|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services. Adversaries may use flaws in the permissions for registry to redirect from the originally specified executable to one that they control, in order to launch their own code at Service start.  Windows stores local service configuration information in the Registry under <code>HKLM\\SYSTEM\\CurrentControlSet\\Services</code>. The information stored under a service's Registry keys can be manipulated to modify a service's execution parameters through tools such as the service controller, sc.exe,  [PowerShell](https://attack.mitre.org/techniques/T1059/001), or [Reg](https://attack.mitre.org/software/S0075). Access to Registry keys is controlled through Access Control Lists and permissions. (Citation: Registry Key Security)<br /><br />If the permissions for users and groups are not properly set and allow access to the Registry keys for a service, then adversaries can change the service binPath/ImagePath to point to a different executable under their control. When the service starts or is restarted, then the adversary-controlled program will execute, allowing the adversary to gain persistence and/or privilege escalation to the account context the service is set to execute under (local/domain account, SYSTEM, LocalService, or NetworkService).<br /><br />Adversaries may also alter Registry keys associated with service failure parameters (such as <code>FailureCommand</code>) that may be executed in an elevated context anytime the service fails or is intentionally corrupted.(Citation: Kansa Service related collectors)(Citation: Tweet Registry Perms Weakness) <br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/478.html",
        "description": "none",
        "external_id": "CAPEC-478"
      },
      {
        "source_name": "Registry Key Security",
        "url": "https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights?redirectedfrom=MSDN",
        "description": "Microsoft. (2018, May 31). Registry Key Security and Access Rights. Retrieved March 16, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Kansa Service related collectors",
        "url": "https://trustedsignal.blogspot.com/2014/05/kansa-service-related-collectors-and.html",
        "description": "Hull, D.. (2014, May 3). Kansa: Service related collectors and analysis. Retrieved October 10, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Tweet Registry Perms Weakness",
        "url": "https://twitter.com/r0wdy_/status/936365549553991680",
        "description": "@r0wdy_. (2017, November 30). Service Recovery Parameters. Retrieved April 9, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Autoruns for Windows",
        "url": "https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns",
        "description": "Mark Russinovich. (2019, June 28). Autoruns for Windows v13.96. Retrieved March 13, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--ffeb0780-356e-4261-b036-cfb6bd234335",
    "platform": "windows",
    "tid": "T1574.012",
    "technique": "COR_PROFILER",
    "tactic": "privilege-escalation",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring|windows-registry",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR. The COR_PROFILER is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR). These profiliers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR.(Citation: Microsoft Profiling Mar 2017)(Citation: Microsoft COR_PROFILER Feb 2013)<br /><br />The COR_PROFILER environment variable can be set at various scopes (system, user, or process) resulting in different levels of influence. System and user-wide environment variable scopes are specified in the Registry, where a [Component Object Model](https://attack.mitre.org/techniques/T1559/001) (COM) object can be registered as a profiler DLL. A process scope COR_PROFILER can also be created in-memory without modifying the Registry. Starting with .NET Framework 4, the profiling DLL does not need to be registered as long as the location of the DLL is specified in the COR_PROFILER_PATH environment variable.(Citation: Microsoft COR_PROFILER Feb 2013)<br /><br />Adversaries may abuse COR_PROFILER to establish persistence that executes a malicious DLL in the context of all .NET processes every time the CLR is invoked. The COR_PROFILER can also be used to elevate privileges (ex: [Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002)) if the victim .NET process executes at a higher permission level, as well as to hook and [Impair Defenses](https://attack.mitre.org/techniques/T1562) provided by .NET processes.(Citation: RedCanary Mockingbird May 2020)(Citation: Red Canary COR_PROFILER May 2020)(Citation: Almond COR_PROFILER Apr 2019)(Citation: GitHub OmerYa Invisi-Shell)(Citation: subTee .NET Profilers May 2017)<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft Profiling Mar 2017",
        "url": "https://docs.microsoft.com/en-us/dotnet/framework/unmanaged-api/profiling/profiling-overview",
        "description": "Microsoft. (2017, March 30). Profiling Overview. Retrieved June 24, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft COR_PROFILER Feb 2013",
        "url": "https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-4.0/ee471451(v=vs.100)",
        "description": "Microsoft. (2013, February 4). Registry-Free Profiler Startup and Attach. Retrieved June 24, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "RedCanary Mockingbird May 2020",
        "url": "https://redcanary.com/blog/blue-mockingbird-cryptominer/",
        "description": "Lambert, T. (2020, May 7). Introducing Blue Mockingbird. Retrieved May 26, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Red Canary COR_PROFILER May 2020",
        "url": "https://redcanary.com/blog/cor_profiler-for-persistence/",
        "description": "Brown, J. (2020, May 7). Detecting COR_PROFILER manipulation for persistence. Retrieved June 24, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Almond COR_PROFILER Apr 2019",
        "url": "https://offsec.almond.consulting/UAC-bypass-dotnet.html",
        "description": "Almond. (2019, April 30). UAC bypass via elevated .NET applications. Retrieved June 24, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "GitHub OmerYa Invisi-Shell",
        "url": "https://github.com/OmerYa/Invisi-Shell",
        "description": "Yair, O. (2019, August 19). Invisi-Shell. Retrieved June 24, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "subTee .NET Profilers May 2017",
        "url": "https://web.archive.org/web/20170720041203/http://subt0x10.blogspot.com/2017/05/subvert-clr-process-listing-with-net.html",
        "description": "Smith, C. (2017, May 18). Subvert CLR Process Listing With .NET Profilers. Retrieved June 24, 2020.",
        "external_id": "none"
      }
    ]
  }
]
