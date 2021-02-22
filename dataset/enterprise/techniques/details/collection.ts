 [
  {
    "id": "attack-pattern--3c4a2599-71ee-4405-ba1e-0e28414b4bc5",
    "platform": "linux|macos|windows",
    "tid": "T1005",
    "technique": "Data from Local System",
    "tactic": "collection",
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
    "technique_description": "Adversaries may search local system sources, such as file systems or local databases, to find files of interest and sensitive data prior to Exfiltration.<br /><br />Adversaries may do this using a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059), such as [cmd](https://attack.mitre.org/software/S0106), which has functionality to interact with the file system to gather information. Some adversaries may also use [Automated Collection](https://attack.mitre.org/techniques/T1119) on the local system.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--1b7ba276-eedc-4951-a762-0ceea2c030ec",
    "platform": "linux|macos|windows",
    "tid": "T1025",
    "technique": "Data from Removable Media",
    "tactic": "collection",
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
    "technique_description": "Adversaries may search connected removable media on computers they have compromised to find files of interest. Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration. Interactive command shells may be in use, and common functionality within [cmd](https://attack.mitre.org/software/S0106) may be used to gather information. <br /><br />Some adversaries may also use [Automated Collection](https://attack.mitre.org/techniques/T1119) on removable media.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--ae676644-d2d2-41b7-af7e-9bed1b55898c",
    "platform": "linux|macos|windows",
    "tid": "T1039",
    "technique": "Data from Network Shared Drive",
    "tactic": "collection",
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
    "technique_description": "Adversaries may search network shares on computers they have compromised to find files of interest. Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration. Interactive command shells may be in use, and common functionality within [cmd](https://attack.mitre.org/software/S0106) may be used to gather information.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/639.html",
        "description": "none",
        "external_id": "CAPEC-639"
      }
    ]
  },
  {
    "id": "attack-pattern--bb5a00de-e086-4859-a231-fa793f6797e2",
    "platform": "linux|macos|windows|network",
    "tid": "T1056",
    "technique": "Input Capture",
    "tactic": "collection",
    "datasources": "api-monitoring|binary-file-metadata|dll-monitoring|kernel-drivers|loaded-dlls|powershell-logs|process-command-line-parameters|process-monitoring|user-interface|windows-event-logs|windows-registry",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1056.001",
      "T1056.002",
      "T1056.003",
      "T1056.004"
    ],
    "count_subtechniques": 4,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. [Credential API Hooking](https://attack.mitre.org/techniques/T1056/004)) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. [Web Portal Capture](https://attack.mitre.org/techniques/T1056/003)).<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/569.html",
        "description": "none",
        "external_id": "CAPEC-569"
      },
      {
        "source_name": "Adventures of a Keystroke",
        "url": "http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf",
        "description": "Tinaztepe,  E. (n.d.). The Adventures of a Keystroke:  An in-depth look into keyloggers on Windows. Retrieved April 27, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--7dd95ff6-712e-4056-9626-312ea4ab4c5e",
    "platform": "linux|macos|windows|aws|gcp|azure",
    "tid": "T1074",
    "technique": "Data Staged",
    "tactic": "collection",
    "datasources": "file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1074.001",
      "T1074.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may stage collected data in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitre.org/techniques/T1560). Interactive command shells may be used, and common functionality within [cmd](https://attack.mitre.org/software/S0106) and bash may be used to copy data into a staging location.(Citation: PWC Cloud Hopper April 2017)<br /><br />In cloud environments, adversaries may stage data within a particular instance or virtual machine before exfiltration. An adversary may [Create Cloud Instance](https://attack.mitre.org/techniques/T1578/002) and stage data in that instance.(Citation: Mandiant M-Trends 2020)<br /><br />Adversaries may choose to stage data from a victim network in a centralized location prior to Exfiltration to minimize the number of connections made to their C2 server and better evade detection.<br /><br />",
    "technique_references": [
      {
        "source_name": "PWC Cloud Hopper April 2017",
        "url": "https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf",
        "description": "PwC and BAE Systems. (2017, April). Operation Cloud Hopper. Retrieved April 5, 2017.",
        "external_id": "none"
      },
      {
        "source_name": "Mandiant M-Trends 2020",
        "url": "https://content.fireeye.com/m-trends/rpt-m-trends-2020",
        "description": "Mandiant. (2020, February). M-Trends 2020. Retrieved April 24, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0259baeb-9f63-4c69-bf10-eb038c390688",
    "platform": "linux|macos|windows",
    "tid": "T1113",
    "technique": "Screen Capture",
    "tactic": "collection",
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
    "technique_description": "Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. Taking a screenshot is also typically possible through native utilities or API calls, such as <code>CopyFromScreen</code>, <code>xwd</code>, or <code>screencapture</code>.(Citation: CopyFromScreen .NET)(Citation: Antiquated Mac Malware)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/648.html",
        "description": "none",
        "external_id": "CAPEC-648"
      },
      {
        "source_name": "CopyFromScreen .NET",
        "url": "https://docs.microsoft.com/en-us/dotnet/api/system.drawing.graphics.copyfromscreen?view=netframework-4.8",
        "description": "Microsoft. (n.d.). Graphics.CopyFromScreen Method. Retrieved March 24, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Antiquated Mac Malware",
        "url": "https://blog.malwarebytes.com/threat-analysis/2017/01/new-mac-backdoor-using-antiquated-code/",
        "description": "Thomas Reed. (2017, January 18). New Mac backdoor using antiquated code. Retrieved July 5, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--1608f3e1-598a-42f4-a01a-2e252e81728f",
    "platform": "windows|office-365",
    "tid": "T1114",
    "technique": "Email Collection",
    "tactic": "collection",
    "datasources": "authentication-logs|email-gateway|file-monitoring|mail-server|office-365-trace-logs|process-monitoring|process-use-of-network",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1114.001",
      "T1114.002",
      "T1114.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may target user email to collect sensitive information. Emails may contain sensitive data, including trade secrets or personal information, that can prove valuable to adversaries. Adversaries can collect or forward email from mail servers or clients. <br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft Tim McMichael Exchange Mail Forwarding 2",
        "url": "https://blogs.technet.microsoft.com/timmcmic/2015/06/08/exchange-and-office-365-mail-forwarding-2/",
        "description": "McMichael, T.. (2015, June 8). Exchange and Office 365 Mail Forwarding. Retrieved October 8, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--30973a08-aed9-4edf-8604-9084ce1b5c4f",
    "platform": "linux|windows|macos",
    "tid": "T1115",
    "technique": "Clipboard Data",
    "tactic": "collection",
    "datasources": "api-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may collect data stored in the clipboard from users copying information within or between applications. <br /><br />In Windows, Applications can access clipboard data by using the Windows API.(Citation: MSDN Clipboard) OSX provides a native command, <code>pbpaste</code>, to grab clipboard contents.(Citation: Operating with EmPyre)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/637.html",
        "description": "none",
        "external_id": "CAPEC-637"
      },
      {
        "source_name": "MSDN Clipboard",
        "url": "https://msdn.microsoft.com/en-us/library/ms649012",
        "description": "Microsoft. (n.d.). About the Clipboard. Retrieved March 29, 2016.",
        "external_id": "none"
      },
      {
        "source_name": "Operating with EmPyre",
        "url": "https://medium.com/rvrsh3ll/operating-with-empyre-ea764eda3363",
        "description": "rvrsh3ll. (2016, May 18). Operating with EmPyre. Retrieved July 12, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--30208d3e-0d6b-43c8-883e-44462a514619",
    "platform": "linux|macos|windows",
    "tid": "T1119",
    "technique": "Automated Collection",
    "tactic": "collection",
    "datasources": "data-loss-prevention|file-monitoring|process-command-line-parameters",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals. This functionality could also be built into remote access tools. <br /><br />This technique may incorporate use of other techniques such as [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) and [Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570) to identify and move files.<br /><br />",
    "technique_references": []
  },
  {
    "id": "attack-pattern--1035cdf2-3e5f-446f-a7a7-e8f6d7925967",
    "platform": "linux|macos|windows",
    "tid": "T1123",
    "technique": "Audio Capture",
    "tactic": "collection",
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
    "technique_description": "An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.<br /><br />Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture audio. Audio files may be written to disk and exfiltrated later.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/634.html",
        "description": "none",
        "external_id": "CAPEC-634"
      }
    ]
  },
  {
    "id": "attack-pattern--6faf650d-bf31-4eb4-802d-1000cf38efaf",
    "platform": "windows|macos",
    "tid": "T1125",
    "technique": "Video Capture",
    "tactic": "collection",
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
    "technique_description": "An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information. Images may also be captured from devices or applications, potentially in specified intervals, in lieu of video files.<br /><br />Malware or scripts may be used to interact with the devices through an available API provided by the operating system or an application to capture video or images. Video or image files may be written to disk and exfiltrated later. This technique differs from [Screen Capture](https://attack.mitre.org/techniques/T1113) due to use of specific devices or applications for video recording rather than capturing the victim's screen.<br /><br />In macOS, there are a few different malware samples that record the user's webcam such as FruitFly and Proton. (Citation: objective-see 2017 review)<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/634.html",
        "description": "none",
        "external_id": "CAPEC-634"
      },
      {
        "source_name": "objective-see 2017 review",
        "url": "https://objective-see.com/blog/blog_0x25.html",
        "description": "Patrick Wardle. (n.d.). Retrieved March 20, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--544b0346-29ad-41e1-a808-501bb4193f47",
    "platform": "windows",
    "tid": "T1185",
    "technique": "Man in the Browser",
    "tactic": "collection",
    "datasources": "api-monitoring|authentication-logs|packet-capture|process-monitoring",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries can take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify behavior, and intercept information as part of various man in the browser techniques. (Citation: Wikipedia Man in the Browser)<br /><br />A specific example is when an adversary injects software into a browser that allows an them to inherit cookies, HTTP sessions, and SSL client certificates of a user and use the browser as a way to pivot into an authenticated intranet. (Citation: Cobalt Strike Browser Pivot) (Citation: ICEBRG Chrome Extensions)<br /><br />Browser pivoting requires the SeDebugPrivilege and a high-integrity process to execute. Browser traffic is pivoted from the adversary's browser through the user's browser by setting up an HTTP proxy which will redirect any HTTP and HTTPS traffic. This does not alter the user's traffic in any way. The proxy connection is severed as soon as the browser is closed. Whichever browser process the proxy is injected into, the adversary assumes the security context of that process. Browsers typically create a new process for each tab that is opened and permissions and certificates are separated accordingly. With these permissions, an adversary could browse to any resource on an intranet that is accessible through the browser and which the browser has sufficient permissions, such as Sharepoint or webmail. Browser pivoting also eliminates the security provided by 2-factor authentication. (Citation: cobaltstrike manual)<br /><br />",
    "technique_references": [
      {
        "source_name": "Wikipedia Man in the Browser",
        "url": "https://en.wikipedia.org/wiki/Man-in-the-browser",
        "description": "Wikipedia. (2017, October 28). Man-in-the-browser. Retrieved January 10, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Cobalt Strike Browser Pivot",
        "url": "https://www.cobaltstrike.com/help-browser-pivoting",
        "description": "Mudge, R. (n.d.). Browser Pivoting. Retrieved January 10, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "ICEBRG Chrome Extensions",
        "url": "https://www.icebrg.io/blog/malicious-chrome-extensions-enable-criminals-to-impact-over-half-a-million-users-and-global-businesses",
        "description": "De Tore, M., Warner, J. (2018, January 15). MALICIOUS CHROME EXTENSIONS ENABLE CRIMINALS TO IMPACT OVER HALF A MILLION USERS AND GLOBAL BUSINESSES. Retrieved January 17, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "cobaltstrike manual",
        "url": "https://cobaltstrike.com/downloads/csmanual38.pdf",
        "description": "Strategic Cyber LLC. (2017, March 14). Cobalt Strike Manual. Retrieved May 24, 2017.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--d28ef391-8ed4-45dc-bc4a-2f43abf54416",
    "platform": "linux|windows|macos|saas|office-365",
    "tid": "T1213",
    "technique": "Data from Information Repositories",
    "tactic": "collection",
    "datasources": "application-logs|authentication-logs|data-loss-prevention|oauth-audit-logs|third-party-application-logs",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1213.001",
      "T1213.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may leverage information repositories to mine valuable information. Information repositories are tools that allow for storage of information, typically to facilitate collaboration or information sharing between users, and can store a wide variety of data that may aid adversaries in further objectives, or direct access to the target information.<br /><br />The following is a brief list of example information that may hold potential value to an adversary and may also be found on an information repository:<br /><br />* Policies, procedures, and standards<br /><br />* Physical / logical network diagrams<br /><br />* System architecture diagrams<br /><br />* Technical system documentation<br /><br />* Testing / development credentials<br /><br />* Work / project schedules<br /><br />* Source code snippets<br /><br />* Links to network shares and other internal resources<br /><br />Information stored in a repository may vary based on the specific instance or environment. Specific common information repositories include [Sharepoint](https://attack.mitre.org/techniques/T1213/002), [Confluence](https://attack.mitre.org/techniques/T1213/001), and enterprise databases such as SQL Server.<br /><br />",
    "technique_references": [
      {
        "source_name": "Microsoft SharePoint Logging",
        "url": "https://support.office.com/en-us/article/configure-audit-settings-for-a-site-collection-a9920c97-38c0-44f2-8bcb-4cf1e2ae22d2",
        "description": "Microsoft. (2017, July 19). Configure audit settings for a site collection. Retrieved April 4, 2018.",
        "external_id": "none"
      },
      {
        "source_name": "Atlassian Confluence Logging",
        "url": "https://confluence.atlassian.com/confkb/how-to-enable-user-access-logging-182943.html",
        "description": "Atlassian. (2018, January 9). How to Enable User Access Logging. Retrieved April 4, 2018.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--3298ce88-1628-43b1-87d9-0b5336b193d7",
    "platform": "aws|gcp|azure",
    "tid": "T1530",
    "technique": "Data from Cloud Storage Object",
    "tactic": "collection",
    "datasources": "aws-cloudtrail-logs|azure-activity-logs|stackdriver-logs",
    "has_subtechniques": false,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [],
    "count_subtechniques": 0,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may access data objects from improperly secured cloud storage.<br /><br />Many cloud service providers offer solutions for online data storage such as Amazon S3, Azure Storage, and Google Cloud Storage. These solutions differ from other storage solutions (such as SQL or Elasticsearch) in that there is no overarching application. Data from these solutions can be retrieved directly using the cloud provider's APIs. Solution providers typically offer security guides to help end users configure systems.(Citation: Amazon S3 Security, 2019)(Citation: Microsoft Azure Storage Security, 2019)(Citation: Google Cloud Storage Best Practices, 2019)<br /><br />Misconfiguration by end users is a common problem. There have been numerous incidents where cloud storage has been improperly secured (typically by unintentionally allowing public access by unauthenticated users or overly-broad access by all users), allowing open access to credit cards, personally identifiable information, medical records, and other sensitive information.(Citation: Trend Micro S3 Exposed PII, 2017)(Citation: Wired Magecart S3 Buckets, 2019)(Citation: HIPAA Journal S3 Breach, 2017) Adversaries may also obtain leaked credentials in source repositories, logs, or other means as a way to gain access to cloud storage objects that have access permission controls.<br /><br />",
    "technique_references": [
      {
        "source_name": "Amazon S3 Security, 2019",
        "url": "https://aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/",
        "description": "Amazon. (2019, May 17). How can I secure the files in my Amazon S3 bucket?. Retrieved October 4, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Microsoft Azure Storage Security, 2019",
        "url": "https://docs.microsoft.com/en-us/azure/storage/common/storage-security-guide",
        "description": "Amlekar, M., Brooks, C., Claman, L., et. al.. (2019, March 20). Azure Storage security guide. Retrieved October 4, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Google Cloud Storage Best Practices, 2019",
        "url": "https://cloud.google.com/storage/docs/best-practices",
        "description": "Google. (2019, September 16). Best practices for Cloud Storage. Retrieved October 4, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Trend Micro S3 Exposed PII, 2017",
        "url": "https://www.trendmicro.com/vinfo/us/security/news/virtualization-and-cloud/a-misconfigured-amazon-s3-exposed-almost-50-thousand-pii-in-australia",
        "description": "Trend Micro. (2017, November 6). A Misconfigured Amazon S3 Exposed Almost 50 Thousand PII in Australia. Retrieved October 4, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "Wired Magecart S3 Buckets, 2019",
        "url": "https://www.wired.com/story/magecart-amazon-cloud-hacks/",
        "description": "Barrett, B.. (2019, July 11). Hack Brief: A Card-Skimming Hacker Group Hit 17K Domains—and Counting. Retrieved October 4, 2019.",
        "external_id": "none"
      },
      {
        "source_name": "HIPAA Journal S3 Breach, 2017",
        "url": "https://www.hipaajournal.com/47gb-medical-records-unsecured-amazon-s3-bucket/",
        "description": "HIPAA Journal. (2017, October 11). 47GB of Medical Records and Test Results Found in Unsecured Amazon S3 Bucket. Retrieved October 4, 2019.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--035bb001-ab69-4a0b-9f6c-2de8b09e1b9d",
    "platform": "windows|macos|linux",
    "tid": "T1557",
    "technique": "Man-in-the-Middle",
    "tactic": "collection",
    "datasources": "file-monitoring|netflow-enclave-netflow|packet-capture",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1557.001",
      "T1557.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may attempt to position themselves between two or more networked devices using a man-in-the-middle (MiTM) technique to support follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040) or [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002). By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions.(Citation: Rapid7 MiTM Basics)<br /><br />Adversaries may leverage the MiTM position to attempt to modify traffic, such as in [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002). Adversaries can also stop traffic from flowing to the appropriate destination, causing denial of service.<br /><br />",
    "technique_references": [
      {
        "source_name": "capec",
        "url": "https://capec.mitre.org/data/definitions/94.html",
        "description": "none",
        "external_id": "CAPEC-94"
      },
      {
        "source_name": "Rapid7 MiTM Basics",
        "url": "https://www.rapid7.com/fundamentals/man-in-the-middle-attacks/",
        "description": "Rapid7. (n.d.). Man-in-the-Middle (MITM) Attacks. Retrieved March 2, 2020.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--53ac20cd-aca3-406e-9aa0-9fc7fdc60a5a",
    "platform": "linux|macos|windows",
    "tid": "T1560",
    "technique": "Archive Collected Data",
    "tactic": "collection",
    "datasources": "binary-file-metadata|file-monitoring|process-command-line-parameters|process-monitoring",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1560.001",
      "T1560.002",
      "T1560.003"
    ],
    "count_subtechniques": 3,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network. Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less conspicuous upon inspection by a defender.<br /><br />Both compression and encryption are done prior to exfiltration, and can be performed using a utility, 3rd party library, or custom method.<br /><br />",
    "technique_references": [
      {
        "source_name": "Wikipedia File Header Signatures",
        "url": "https://en.wikipedia.org/wiki/List_of_file_signatures",
        "description": "Wikipedia. (2016, March 31). List of file signatures. Retrieved April 22, 2016.",
        "external_id": "none"
      }
    ]
  },
  {
    "id": "attack-pattern--0ad7bc5c-235a-4048-944b-3b286676cb74",
    "platform": "network",
    "tid": "T1602",
    "technique": "Data from Configuration Repository",
    "tactic": "collection",
    "datasources": "netflow-enclave-netflow|network-protocol-analysis|packet-capture",
    "has_subtechniques": true,
    "is_deprecated": false,
    "is_revoked": false,
    "subtechniques": [
      "T1602.001",
      "T1602.002"
    ],
    "count_subtechniques": 2,
    "correlation_adversary": "none",
    "correlation_malware": "none",
    "correlation_tool": "none",
    "correlation_gid": "none",
    "technique_description": "Adversaries may collect data related to managed devices from configuration repositories. Configuration repositories are used by management systems in order to configure, manage, and control data on remote systems. Configuration repositories may also facilitate remote access and administration of devices.<br /><br />Adversaries may target these repositories in order to collect large quantities of sensitive system administration data. Data from configuration repositories may be exposed by various protocols and software and can store a wide variety of data, much of which may align with adversary Discovery objectives.(Citation: US-CERT-TA18-106A)(Citation: US-CERT TA17-156A SNMP Abuse 2017)<br /><br />",
    "technique_references": [
      {
        "source_name": "US-CERT-TA18-106A",
        "url": "https://www.us-cert.gov/ncas/alerts/TA18-106A",
        "description": "US-CERT. (2018, April 20). Alert (TA18-106A) Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "US-CERT TA17-156A SNMP Abuse 2017",
        "url": "https://us-cert.cisa.gov/ncas/alerts/TA17-156A",
        "description": "US-CERT. (2017, June 5). Reducing the Risk of SNMP Abuse. Retrieved October 19, 2020.",
        "external_id": "none"
      },
      {
        "source_name": "Cisco Advisory SNMP v3 Authentication Vulnerabilities",
        "url": "https://tools.cisco.com/security/center/content/CiscoAppliedMitigationBulletin/cisco-amb-20080610-SNMPv3",
        "description": "Cisco. (2008, June 10). Identifying and Mitigating Exploitation of the SNMP Version 3 Authentication Vulnerabilities. Retrieved October 19, 2020.",
        "external_id": "none"
      }
    ]
  }
]
