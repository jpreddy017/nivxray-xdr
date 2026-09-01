/**
 * Shared MITRE ATT&CK link resolver.
 *
 * Owner rule: never ship a broken deep-link, and never ship a
 * search-fallback masquerading as a technique link.  Every
 * consumer must route through `attackHrefFor()` so the entire
 * cockpit gets the same behaviour:
 *
 *   1. Canonical `T####` / `T####.###` in any candidate field →
 *      direct  https://attack.mitre.org/techniques/T####/###/  URL.
 *   2. Recognised technique NAME (catalogue) → direct URL.
 *   3. Neither → null.  The caller MUST render an honest
 *      "no attack id" pill.  We do NOT fall back to Google
 *      searches or any other indirect resolver — those
 *      previously shipped as `Find` buttons and were unreliable.
 *
 * Because the resolver is now id-or-nothing, every consumer that
 * used to render two labels (`Open` / `Find`) should render a
 * single `Open` label whenever `attackHrefFor` returns a URL.
 */
const ATTACK_ID_RE = /\b(T\d{4})(?:\.(\d{3}))?\b/i;

/* Name → canonical ATT&CK id.  The backend attack-chain composer
   sometimes emits the technique NAME in the id slot; these
   mappings recover the real id so the analyst still lands on the
   correct attack.mitre.org page in one click.

   All entries map to a live, published ATT&CK technique (id set
   from https://attack.mitre.org/techniques/enterprise/).  Only
   canonical technique names are indexed; unknown names fall
   through to the honest "no attack id" pill. */
export const ATTACK_NAME_INDEX = {
  /* --- Execution (TA0002) --- */
  "COMMAND AND SCRIPTING INTERPRETER":                  "T1059",
  "POWERSHELL":                                         "T1059/001",
  "POWERSHELL (HIDDEN)":                                "T1059/001",
  "APPLESCRIPT":                                        "T1059/002",
  "WINDOWS COMMAND SHELL":                              "T1059/003",
  "CMD":                                                "T1059/003",
  "UNIX SHELL":                                         "T1059/004",
  "VISUAL BASIC":                                       "T1059/005",
  "PYTHON":                                             "T1059/006",
  "JAVASCRIPT":                                         "T1059/007",
  "NETWORK DEVICE CLI":                                 "T1059/008",
  "CLOUD API":                                          "T1059/009",
  "AUTOHOTKEY & AUTOIT":                                "T1059/010",
  "LUA":                                                "T1059/011",
  "HYPERVISOR CLI":                                     "T1059/012",
  "USER EXECUTION":                                     "T1204",
  "MALICIOUS LINK":                                     "T1204/001",
  "MALICIOUS FILE":                                     "T1204/002",
  "MALICIOUS IMAGE":                                    "T1204/003",
  "WINDOWS MANAGEMENT INSTRUMENTATION":                 "T1047",
  "WMI":                                                "T1047",
  "SOFTWARE DEPLOYMENT TOOLS":                          "T1072",
  "SYSTEM SERVICES":                                    "T1569",
  "SERVICE EXECUTION":                                  "T1569/002",
  "INTER-PROCESS COMMUNICATION":                        "T1559",
  "COMPONENT OBJECT MODEL":                             "T1559/001",
  "DYNAMIC DATA EXCHANGE":                              "T1559/002",
  "SHARED MODULES":                                     "T1129",
  "SERVERLESS EXECUTION":                               "T1648",
  "CONTAINER ADMINISTRATION COMMAND":                   "T1609",
  "DEPLOY CONTAINER":                                   "T1610",
  "SCHEDULED TASK/JOB":                                 "T1053",
  "SCHEDULED TASK":                                     "T1053/005",
  "AT":                                                 "T1053/002",
  "AT (ATSVC)":                                         "T1053/002",
  "CRON":                                               "T1053/003",
  "SYSTEMD TIMERS":                                     "T1053/006",
  "CONTAINER ORCHESTRATION JOB":                        "T1053/007",

  /* --- Defense Evasion (TA0005) --- */
  "OBFUSCATED FILES OR INFORMATION":                    "T1027",
  "BINARY PADDING":                                     "T1027/001",
  "SOFTWARE PACKING":                                   "T1027/002",
  "STEGANOGRAPHY":                                      "T1027/003",
  "COMPILE AFTER DELIVERY":                             "T1027/004",
  "INDICATOR REMOVAL FROM TOOLS":                       "T1027/005",
  "HTML SMUGGLING":                                     "T1027/006",
  "DYNAMIC API RESOLUTION":                             "T1027/007",
  "STRIPPED PAYLOADS":                                  "T1027/008",
  "EMBEDDED PAYLOADS":                                  "T1027/009",
  "COMMAND OBFUSCATION":                                "T1027/010",
  "COMMAND OBFUSCATION: BASE64/ENCODED COMMAND":        "T1027/010",
  "STANDALONE LONG BASE64 BLOB (>=200 CHARS) — LIKELY ENCODED PAYLOAD":
                                                        "T1027/010",
  "FILELESS STORAGE":                                   "T1027/011",
  "LNK ICON SMUGGLING":                                 "T1027/012",
  "ENCRYPTED/ENCODED FILE":                             "T1027/013",
  "POLYMORPHIC CODE":                                   "T1027/014",
  "DEOBFUSCATE/DECODE FILES OR INFORMATION":            "T1140",
  "MASQUERADING":                                       "T1036",
  "INVALID CODE SIGNATURE":                             "T1036/001",
  "RIGHT-TO-LEFT OVERRIDE":                             "T1036/002",
  "RENAME SYSTEM UTILITIES":                            "T1036/003",
  "MASQUERADE TASK OR SERVICE":                         "T1036/004",
  "MATCH LEGITIMATE NAME OR LOCATION":                  "T1036/005",
  "SPACE AFTER FILENAME":                               "T1036/006",
  "DOUBLE FILE EXTENSION":                              "T1036/007",
  "MASQUERADE FILE TYPE":                               "T1036/008",
  "BREAK PROCESS TREES":                                "T1036/009",
  "SIGNED BINARY PROXY EXECUTION":                      "T1218",
  "SYSTEM BINARY PROXY EXECUTION":                      "T1218",
  "COMPILED HTML FILE":                                 "T1218/001",
  "CONTROL PANEL":                                      "T1218/002",
  "CMSTP":                                              "T1218/003",
  "INSTALLUTIL":                                        "T1218/004",
  "MSHTA":                                              "T1218/005",
  "MSIEXEC":                                            "T1218/007",
  "ODBCCONF":                                           "T1218/008",
  "REGSVCS/REGASM":                                     "T1218/009",
  "REGSVR32":                                           "T1218/010",
  "RUNDLL32":                                           "T1218/011",
  "SIGNED BINARY PROXY EXECUTION: RUNDLL32":            "T1218/011",
  "VERCLSID":                                           "T1218/012",
  "MAVINJECT":                                          "T1218/013",
  "MMC":                                                "T1218/014",
  "ELECTRON APPLICATIONS":                              "T1218/015",
  "IMPAIR DEFENSES":                                    "T1562",
  "DISABLE OR MODIFY TOOLS":                            "T1562/001",
  "DISABLE WINDOWS EVENT LOGGING":                      "T1562/002",
  "IMPAIR COMMAND HISTORY LOGGING":                     "T1562/003",
  "DISABLE OR MODIFY SYSTEM FIREWALL":                  "T1562/004",
  "INDICATOR BLOCKING":                                 "T1562/006",
  "DISABLE OR MODIFY CLOUD FIREWALL":                   "T1562/007",
  "DISABLE OR MODIFY CLOUD LOGS":                       "T1562/008",
  "SAFE MODE BOOT":                                     "T1562/009",
  "DOWNGRADE ATTACK":                                   "T1562/010",
  "SPOOF SECURITY ALERTING":                            "T1562/011",
  "DISABLE OR MODIFY LINUX AUDIT SYSTEM":               "T1562/012",
  "INDICATOR REMOVAL":                                  "T1070",
  "CLEAR WINDOWS EVENT LOGS":                           "T1070/001",
  "CLEAR LINUX OR MAC SYSTEM LOGS":                     "T1070/002",
  "CLEAR COMMAND HISTORY":                              "T1070/003",
  "FILE DELETION":                                      "T1070/004",
  "NETWORK SHARE CONNECTION REMOVAL":                   "T1070/005",
  "TIMESTOMP":                                          "T1070/006",
  "CLEAR NETWORK CONNECTION HISTORY":                   "T1070/007",
  "CLEAR MAILBOX DATA":                                 "T1070/008",
  "CLEAR PERSISTENCE":                                  "T1070/009",
  "PROCESS INJECTION":                                  "T1055",
  "DYNAMIC-LINK LIBRARY INJECTION":                     "T1055/001",
  "PORTABLE EXECUTABLE INJECTION":                      "T1055/002",
  "THREAD EXECUTION HIJACKING":                         "T1055/003",
  "ASYNCHRONOUS PROCEDURE CALL":                        "T1055/004",
  "THREAD LOCAL STORAGE":                               "T1055/005",
  "PTRACE SYSTEM CALLS":                                "T1055/008",
  "PROC MEMORY":                                        "T1055/009",
  "EXTRA WINDOW MEMORY INJECTION":                      "T1055/011",
  "PROCESS HOLLOWING":                                  "T1055/012",
  "PROCESS DOPPELGANGING":                              "T1055/013",
  "VDSO HIJACKING":                                     "T1055/014",
  "LISTPLANTING":                                       "T1055/015",
  "SANDBOX EVASION":                                    "T1497",
  "VIRTUALIZATION/SANDBOX EVASION":                     "T1497",
  "SYSTEM CHECKS":                                      "T1497/001",
  "USER ACTIVITY BASED CHECKS":                         "T1497/002",
  "TIME BASED EVASION":                                 "T1497/003",
  "SANDBOX EVASION: TIME BASED EVASION":                "T1497/003",
  "REFLECTIVE CODE LOADING":                            "T1620",
  "HIDE ARTIFACTS":                                     "T1564",
  "HIDDEN FILES AND DIRECTORIES":                       "T1564/001",
  "HIDDEN USERS":                                       "T1564/002",
  "HIDDEN WINDOW":                                      "T1564/003",
  "NTFS FILE ATTRIBUTES":                               "T1564/004",
  "HIDDEN FILE SYSTEM":                                 "T1564/005",
  "RUN VIRTUAL INSTANCE":                               "T1564/006",
  "VBA STOMPING":                                       "T1564/007",
  "EMAIL HIDING RULES":                                 "T1564/008",
  "RESOURCE FORKING":                                   "T1564/009",
  "PROCESS ARGUMENT SPOOFING":                          "T1564/010",
  "IGNORE PROCESS INTERRUPTS":                          "T1564/011",
  "FILE/PATH EXCLUSIONS":                               "T1564/012",
  "BYPASS USER ACCOUNT CONTROL":                        "T1548/002",
  "ABUSE ELEVATION CONTROL MECHANISM":                  "T1548",

  /* --- Persistence (TA0003) --- */
  "BOOT OR LOGON AUTOSTART EXECUTION":                  "T1547",
  "REGISTRY RUN KEYS / STARTUP FOLDER":                 "T1547/001",
  "AUTHENTICATION PACKAGE":                             "T1547/002",
  "TIME PROVIDERS":                                     "T1547/003",
  "WINLOGON HELPER DLL":                                "T1547/004",
  "SECURITY SUPPORT PROVIDER":                          "T1547/005",
  "KERNEL MODULES AND EXTENSIONS":                      "T1547/006",
  "SHORTCUT MODIFICATION":                              "T1547/009",
  "PORT MONITORS":                                      "T1547/010",
  "PRINT PROCESSORS":                                   "T1547/012",
  "XDG AUTOSTART ENTRIES":                              "T1547/013",
  "ACTIVE SETUP":                                       "T1547/014",
  "LOGIN ITEMS":                                        "T1547/015",
  "CREATE OR MODIFY SYSTEM PROCESS":                    "T1543",
  "LAUNCH AGENT":                                       "T1543/001",
  "SYSTEMD SERVICE":                                    "T1543/002",
  "WINDOWS SERVICE":                                    "T1543/003",
  "LAUNCH DAEMON":                                      "T1543/004",
  "CONTAINER SERVICE":                                  "T1543/005",
  "EVENT TRIGGERED EXECUTION":                          "T1546",
  "CHANGE DEFAULT FILE ASSOCIATION":                    "T1546/001",
  "SCREENSAVER":                                        "T1546/002",
  "WINDOWS MANAGEMENT INSTRUMENTATION EVENT SUBSCRIPTION":
                                                        "T1546/003",
  "UNIX SHELL CONFIGURATION MODIFICATION":              "T1546/004",
  "TRAP":                                               "T1546/005",
  "LC_LOAD_DYLIB ADDITION":                             "T1546/006",
  "NETSH HELPER DLL":                                   "T1546/007",
  "ACCESSIBILITY FEATURES":                             "T1546/008",
  "APPCERT DLLS":                                       "T1546/009",
  "APPINIT DLLS":                                       "T1546/010",
  "APPLICATION SHIMMING":                               "T1546/011",
  "IMAGE FILE EXECUTION OPTIONS INJECTION":             "T1546/012",
  "POWERSHELL PROFILE":                                 "T1546/013",
  "EMOND":                                              "T1546/014",
  "COMPONENT OBJECT MODEL HIJACKING":                   "T1546/015",
  "INSTALLER PACKAGES":                                 "T1546/016",
  "SERVER SOFTWARE COMPONENT":                          "T1505",
  "SQL STORED PROCEDURES":                              "T1505/001",
  "TRANSPORT AGENT":                                    "T1505/002",
  "WEB SHELL":                                          "T1505/003",
  "IIS COMPONENTS":                                     "T1505/004",
  "TERMINAL SERVICES DLL":                              "T1505/005",
  "OFFICE APPLICATION STARTUP":                         "T1137",
  "OFFICE TEMPLATE MACROS":                             "T1137/001",
  "OFFICE TEST":                                        "T1137/002",
  "OUTLOOK FORMS":                                      "T1137/003",
  "OUTLOOK HOME PAGE":                                  "T1137/004",
  "OUTLOOK RULES":                                      "T1137/005",
  "ADD-INS":                                            "T1137/006",
  "BROWSER EXTENSIONS":                                 "T1176",
  "BITS JOBS":                                          "T1197",
  "CREATE ACCOUNT":                                     "T1136",
  "LOCAL ACCOUNT":                                      "T1136/001",
  "DOMAIN ACCOUNT":                                     "T1136/002",
  "CLOUD ACCOUNT":                                      "T1136/003",
  "ACCOUNT MANIPULATION":                               "T1098",
  "IMPLANT INTERNAL IMAGE":                             "T1525",
  "PRE-OS BOOT":                                        "T1542",
  "TRAFFIC SIGNALING":                                  "T1205",

  /* --- Privilege Escalation (TA0004) --- */
  "EXPLOITATION FOR PRIVILEGE ESCALATION":              "T1068",
  "ACCESS TOKEN MANIPULATION":                          "T1134",
  "TOKEN IMPERSONATION/THEFT":                          "T1134/001",
  "CREATE PROCESS WITH TOKEN":                          "T1134/002",
  "MAKE AND IMPERSONATE TOKEN":                         "T1134/003",
  "PARENT PID SPOOFING":                                "T1134/004",
  "SID-HISTORY INJECTION":                              "T1134/005",
  "HIJACK EXECUTION FLOW":                              "T1574",
  "DLL SEARCH ORDER HIJACKING":                         "T1574/001",
  "DLL SIDE-LOADING":                                   "T1574/002",
  "PATH INTERCEPTION BY PATH ENVIRONMENT VARIABLE":     "T1574/007",
  "PATH INTERCEPTION BY SEARCH ORDER HIJACKING":        "T1574/008",
  "PATH INTERCEPTION BY UNQUOTED PATH":                 "T1574/009",
  "SERVICES FILE PERMISSIONS WEAKNESS":                 "T1574/010",
  "SERVICES REGISTRY PERMISSIONS WEAKNESS":             "T1574/011",
  "COR_PROFILER":                                       "T1574/012",
  "KERNELCALLBACKTABLE":                                "T1574/013",
  "DOMAIN POLICY MODIFICATION":                         "T1484",
  "GROUP POLICY MODIFICATION":                          "T1484/001",
  "DOMAIN TRUST MODIFICATION":                          "T1484/002",
  "ESCAPE TO HOST":                                     "T1611",

  /* --- Credential Access (TA0006) --- */
  "OS CREDENTIAL DUMPING":                              "T1003",
  "CREDENTIAL DUMPING":                                 "T1003",
  "LSASS MEMORY":                                       "T1003/001",
  "SECURITY ACCOUNT MANAGER":                           "T1003/002",
  "NTDS":                                               "T1003/003",
  "LSA SECRETS":                                        "T1003/004",
  "CACHED DOMAIN CREDENTIALS":                          "T1003/005",
  "DCSYNC":                                             "T1003/006",
  "PROC FILESYSTEM":                                    "T1003/007",
  "/ETC/PASSWD AND /ETC/SHADOW":                        "T1003/008",
  "CREDENTIALS FROM PASSWORD STORES":                   "T1555",
  "KEYCHAIN":                                           "T1555/001",
  "SECURITYD MEMORY":                                   "T1555/002",
  "CREDENTIALS FROM WEB BROWSERS":                      "T1555/003",
  "WINDOWS CREDENTIAL MANAGER":                         "T1555/004",
  "PASSWORD MANAGERS":                                  "T1555/005",
  "CLOUD SECRETS MANAGEMENT STORES":                    "T1555/006",
  "UNSECURED CREDENTIALS":                              "T1552",
  "CREDENTIALS IN FILES":                               "T1552/001",
  "CREDENTIALS IN REGISTRY":                            "T1552/002",
  "BASH HISTORY":                                       "T1552/003",
  "PRIVATE KEYS":                                       "T1552/004",
  "CLOUD INSTANCE METADATA API":                        "T1552/005",
  "GROUP POLICY PREFERENCES":                           "T1552/006",
  "CREDENTIALS FROM CONTAINER API":                     "T1552/007",
  "CHAT MESSAGES":                                      "T1552/008",
  "INPUT CAPTURE":                                      "T1056",
  "KEYLOGGING":                                         "T1056/001",
  "GUI INPUT CAPTURE":                                  "T1056/002",
  "WEB PORTAL CAPTURE":                                 "T1056/003",
  "CREDENTIAL API HOOKING":                             "T1056/004",
  "BRUTE FORCE":                                        "T1110",
  "PASSWORD GUESSING":                                  "T1110/001",
  "PASSWORD CRACKING":                                  "T1110/002",
  "PASSWORD SPRAYING":                                  "T1110/003",
  "CREDENTIAL STUFFING":                                "T1110/004",
  "STEAL WEB SESSION COOKIE":                           "T1539",
  "STEAL APPLICATION ACCESS TOKEN":                     "T1528",
  "MULTI-FACTOR AUTHENTICATION REQUEST GENERATION":     "T1621",
  "MULTI-FACTOR AUTHENTICATION INTERCEPTION":           "T1111",
  "FORGE WEB CREDENTIALS":                              "T1606",
  "WEB COOKIES":                                        "T1606/001",
  "SAML TOKENS":                                        "T1606/002",
  "STEAL OR FORGE KERBEROS TICKETS":                    "T1558",
  "GOLDEN TICKET":                                      "T1558/001",
  "SILVER TICKET":                                      "T1558/002",
  "KERBEROASTING":                                      "T1558/003",
  "AS-REP ROASTING":                                    "T1558/004",
  "CCACHE FILES":                                       "T1558/005",
  "ADVERSARY-IN-THE-MIDDLE":                            "T1557",
  "LLMNR/NBT-NS POISONING AND SMB RELAY":               "T1557/001",
  "ARP CACHE POISONING":                                "T1557/002",
  "DHCP SPOOFING":                                      "T1557/003",
  "EVIL TWIN":                                          "T1557/004",

  /* --- Discovery (TA0007) --- */
  "SYSTEM INFORMATION DISCOVERY":                       "T1082",
  "SYSTEM NETWORK CONFIGURATION DISCOVERY":             "T1016",
  "INTERNET CONNECTION DISCOVERY":                      "T1016/001",
  "SYSTEM NETWORK CONNECTIONS DISCOVERY":               "T1049",
  "SYSTEM OWNER/USER DISCOVERY":                        "T1033",
  "SYSTEM SERVICE DISCOVERY":                           "T1007",
  "SYSTEM LOCATION DISCOVERY":                          "T1614",
  "SYSTEM TIME DISCOVERY":                              "T1124",
  "PROCESS DISCOVERY":                                  "T1057",
  "ACCOUNT DISCOVERY":                                  "T1087",
  "LOCAL ACCOUNT DISCOVERY":                            "T1087/001",
  "DOMAIN ACCOUNT DISCOVERY":                           "T1087/002",
  "EMAIL ACCOUNT DISCOVERY":                            "T1087/003",
  "CLOUD ACCOUNT DISCOVERY":                            "T1087/004",
  "PERMISSION GROUPS DISCOVERY":                        "T1069",
  "LOCAL GROUPS":                                       "T1069/001",
  "DOMAIN GROUPS":                                      "T1069/002",
  "CLOUD GROUPS":                                       "T1069/003",
  "REMOTE SYSTEM DISCOVERY":                            "T1018",
  "NETWORK SHARE DISCOVERY":                            "T1135",
  "FILE AND DIRECTORY DISCOVERY":                       "T1083",
  "SOFTWARE DISCOVERY":                                 "T1518",
  "SECURITY SOFTWARE DISCOVERY":                        "T1518/001",
  "QUERY REGISTRY":                                     "T1012",
  "DOMAIN TRUST DISCOVERY":                             "T1482",
  "PERIPHERAL DEVICE DISCOVERY":                        "T1120",
  "APPLICATION WINDOW DISCOVERY":                       "T1010",
  "CONTAINER AND RESOURCE DISCOVERY":                   "T1613",
  "CLOUD SERVICE DISCOVERY":                            "T1526",
  "CLOUD SERVICE DASHBOARD":                            "T1538",
  "CLOUD INFRASTRUCTURE DISCOVERY":                     "T1580",
  "CLOUD STORAGE OBJECT DISCOVERY":                     "T1619",
  "NETWORK SNIFFING":                                   "T1040",
  "NETWORK SERVICE DISCOVERY":                          "T1046",
  "GATHER VICTIM HOST INFORMATION":                     "T1592",
  "GATHER VICTIM IDENTITY INFORMATION":                 "T1589",
  "GATHER VICTIM NETWORK INFORMATION":                  "T1590",
  "GATHER VICTIM ORG INFORMATION":                      "T1591",

  /* --- Lateral Movement (TA0008) --- */
  "REMOTE SERVICES":                                    "T1021",
  "RDP":                                                "T1021/001",
  "REMOTE DESKTOP PROTOCOL":                            "T1021/001",
  "SMB/WINDOWS ADMIN SHARES":                           "T1021/002",
  "DISTRIBUTED COMPONENT OBJECT MODEL":                 "T1021/003",
  "SSH":                                                "T1021/004",
  "VNC":                                                "T1021/005",
  "WINDOWS REMOTE MANAGEMENT":                          "T1021/006",
  "CLOUD SERVICES":                                     "T1021/007",
  "DIRECT CLOUD VM CONNECTIONS":                        "T1021/008",
  "LATERAL TOOL TRANSFER":                              "T1570",
  "REPLICATION THROUGH REMOVABLE MEDIA":                "T1091",
  "USE ALTERNATE AUTHENTICATION MATERIAL":              "T1550",
  "APPLICATION ACCESS TOKEN":                           "T1550/001",
  "PASS THE HASH":                                      "T1550/002",
  "PASS THE TICKET":                                    "T1550/003",
  "WEB SESSION COOKIE":                                 "T1550/004",
  "INTERNAL SPEARPHISHING":                             "T1534",
  "EXPLOITATION OF REMOTE SERVICES":                    "T1210",
  "TAINT SHARED CONTENT":                               "T1080",

  /* --- Collection (TA0009) --- */
  "AUDIO CAPTURE":                                      "T1123",
  "VIDEO CAPTURE":                                      "T1125",
  "SCREEN CAPTURE":                                     "T1113",
  "CLIPBOARD DATA":                                     "T1115",
  "ARCHIVE COLLECTED DATA":                             "T1560",
  "ARCHIVE VIA UTILITY":                                "T1560/001",
  "ARCHIVE VIA LIBRARY":                                "T1560/002",
  "ARCHIVE VIA CUSTOM METHOD":                          "T1560/003",
  "AUTOMATED COLLECTION":                               "T1119",
  "BROWSER SESSION HIJACKING":                          "T1185",
  "DATA FROM CLOUD STORAGE":                            "T1530",
  "DATA FROM CONFIGURATION REPOSITORY":                 "T1602",
  "DATA FROM INFORMATION REPOSITORIES":                 "T1213",
  "DATA FROM LOCAL SYSTEM":                             "T1005",
  "DATA FROM NETWORK SHARED DRIVE":                     "T1039",
  "DATA FROM REMOVABLE MEDIA":                          "T1025",
  "DATA STAGED":                                        "T1074",
  "LOCAL DATA STAGING":                                 "T1074/001",
  "REMOTE DATA STAGING":                                "T1074/002",
  "EMAIL COLLECTION":                                   "T1114",
  "LOCAL EMAIL COLLECTION":                             "T1114/001",
  "REMOTE EMAIL COLLECTION":                            "T1114/002",
  "EMAIL FORWARDING RULE":                              "T1114/003",

  /* --- Command and Control (TA0011) --- */
  "APPLICATION LAYER PROTOCOL":                         "T1071",
  "WEB PROTOCOLS":                                      "T1071/001",
  "FILE TRANSFER PROTOCOLS":                            "T1071/002",
  "MAIL PROTOCOLS":                                     "T1071/003",
  "DNS":                                                "T1071/004",
  "PUBLISH/SUBSCRIBE PROTOCOLS":                        "T1071/005",
  "INGRESS TOOL TRANSFER":                              "T1105",
  "REMOTE ACCESS SOFTWARE":                             "T1219",
  "WEB SERVICE":                                        "T1102",
  "DEAD DROP RESOLVER":                                 "T1102/001",
  "BIDIRECTIONAL COMMUNICATION":                        "T1102/002",
  "ONE-WAY COMMUNICATION":                              "T1102/003",
  "PROXY":                                              "T1090",
  "INTERNAL PROXY":                                     "T1090/001",
  "EXTERNAL PROXY":                                     "T1090/002",
  "MULTI-HOP PROXY":                                    "T1090/003",
  "DOMAIN FRONTING":                                    "T1090/004",
  "DYNAMIC RESOLUTION":                                 "T1568",
  "FAST FLUX DNS":                                      "T1568/001",
  "DOMAIN GENERATION ALGORITHMS":                       "T1568/002",
  "DNS CALCULATION":                                    "T1568/003",
  "ENCRYPTED CHANNEL":                                  "T1573",
  "SYMMETRIC CRYPTOGRAPHY":                             "T1573/001",
  "ASYMMETRIC CRYPTOGRAPHY":                            "T1573/002",
  "NON-APPLICATION LAYER PROTOCOL":                     "T1095",
  "NON-STANDARD PORT":                                  "T1571",
  "PROTOCOL TUNNELING":                                 "T1572",
  "COMMUNICATION THROUGH REMOVABLE MEDIA":              "T1092",
  "DATA OBFUSCATION":                                   "T1001",
  "JUNK DATA":                                          "T1001/001",
  "STEGANOGRAPHY (C2)":                                 "T1001/002",
  "PROTOCOL IMPERSONATION":                             "T1001/003",

  /* --- Exfiltration (TA0010) --- */
  "EXFILTRATION OVER C2 CHANNEL":                       "T1041",
  "EXFILTRATION OVER ALTERNATIVE PROTOCOL":             "T1048",
  "EXFILTRATION OVER WEB SERVICE":                      "T1567",
  "EXFILTRATION TO CLOUD STORAGE":                      "T1567/002",
  "EXFILTRATION TO CODE REPOSITORY":                    "T1567/001",
  "EXFILTRATION OVER PHYSICAL MEDIUM":                  "T1052",
  "AUTOMATED EXFILTRATION":                             "T1020",
  "SCHEDULED TRANSFER":                                 "T1029",
  "DATA TRANSFER SIZE LIMITS":                          "T1030",

  /* --- Impact (TA0040) --- */
  "DATA ENCRYPTED FOR IMPACT":                          "T1486",
  "DATA DESTRUCTION":                                   "T1485",
  "DISK WIPE":                                          "T1561",
  "DISK CONTENT WIPE":                                  "T1561/001",
  "DISK STRUCTURE WIPE":                                "T1561/002",
  "SERVICE STOP":                                       "T1489",
  "SYSTEM SHUTDOWN/REBOOT":                             "T1529",
  "INHIBIT SYSTEM RECOVERY":                            "T1490",
  "DEFACEMENT":                                         "T1491",
  "INTERNAL DEFACEMENT":                                "T1491/001",
  "EXTERNAL DEFACEMENT":                                "T1491/002",
  "ENDPOINT DENIAL OF SERVICE":                         "T1499",
  "NETWORK DENIAL OF SERVICE":                          "T1498",
  "RESOURCE HIJACKING":                                 "T1496",
  "FIRMWARE CORRUPTION":                                "T1495",
  "ACCOUNT ACCESS REMOVAL":                             "T1531",
  "DATA MANIPULATION":                                  "T1565",
  "FINANCIAL THEFT":                                    "T1657",

  /* --- Initial Access (TA0001) --- */
  "PHISHING":                                           "T1566",
  "SPEARPHISHING ATTACHMENT":                           "T1566/001",
  "SPEARPHISHING LINK":                                 "T1566/002",
  "SPEARPHISHING VIA SERVICE":                          "T1566/003",
  "SPEARPHISHING VOICE":                                "T1566/004",
  "EXPLOIT PUBLIC-FACING APPLICATION":                  "T1190",
  "EXTERNAL REMOTE SERVICES":                           "T1133",
  "TRUSTED RELATIONSHIP":                               "T1199",
  "VALID ACCOUNTS":                                     "T1078",
  "DEFAULT ACCOUNTS":                                   "T1078/001",
  "DOMAIN ACCOUNTS":                                    "T1078/002",
  "LOCAL ACCOUNTS":                                     "T1078/003",
  "CLOUD ACCOUNTS":                                     "T1078/004",
  "DRIVE-BY COMPROMISE":                                "T1189",
  "SUPPLY CHAIN COMPROMISE":                            "T1195",
  "HARDWARE ADDITIONS":                                 "T1200",
  "CONTENT INJECTION":                                  "T1659",
  "REPLICATION THROUGH REMOVABLE MEDIA (IA)":           "T1091",

  /* --- Reconnaissance / Resource Dev (TA0043 / TA0042) --- */
  "ACTIVE SCANNING":                                    "T1595",
  "SEARCH OPEN WEBSITES/DOMAINS":                       "T1593",
  "SEARCH VICTIM-OWNED WEBSITES":                       "T1594",
  "ACQUIRE INFRASTRUCTURE":                             "T1583",
  "COMPROMISE INFRASTRUCTURE":                          "T1584",
  "DEVELOP CAPABILITIES":                               "T1587",
  "OBTAIN CAPABILITIES":                                "T1588",
  "STAGE CAPABILITIES":                                 "T1608",
};


export function extractAttackId(node) {
  if (!node) return null;
  const candidates = [node.attack_id, node.technique_id, node.tid,
                              node.object_id, node.id, node.title,
                              node.object_name, node.name, node.label,
                              node.technique_name];
  // Pass 1 — real ATT&CK id anywhere.
  for (const cand of candidates) {
    const m = ATTACK_ID_RE.exec(String(cand || ""));
    if (m) {
      const base = m[1].toUpperCase();
      return m[2] ? `${base}/${m[2]}` : base;
    }
  }
  // Pass 2 — name catalogue.
  for (const cand of candidates) {
    const key = String(cand || "").trim().toUpperCase();
    if (key && ATTACK_NAME_INDEX[key]) return ATTACK_NAME_INDEX[key];
  }
  return null;
}


export function extractAttackName(node) {
  if (!node) return null;
  for (const cand of [node.object_name, node.name, node.label,
                                 node.technique_name, node.title, node.id]) {
    const s = String(cand || "").trim();
    if (s && s.toUpperCase() !== "NOT_APPLICABLE"
             && !ATTACK_ID_RE.test(s)) {
      return s;
    }
  }
  return null;
}


export function attackHrefFor(node) {
  const id = extractAttackId(node);
  if (id) return `https://attack.mitre.org/techniques/${id}/`;
  // No canonical id and no recognised name → honest null.
  // We deliberately do NOT fall back to Google `site:attack.mitre.org`
  // searches here — every caller must render an honest "no attack id"
  // pill so the analyst is never handed a search page dressed up as
  // a technique link.
  return null;
}


export function attackLinkTitle(node) {
  if (extractAttackId(node)) return "Open technique on attack.mitre.org";
  return "No ATT&CK identifier resolvable for this row";
}
