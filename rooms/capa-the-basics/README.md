# capa — Study Notes and Report Interpretation

**Room** — [TryHackMe · CAPA: The Basics](https://tryhackme.com/room/capabasics)  
**Study period** — November 11–12, 2026  
**Room status** — Completed on TryHackMe  
**Focus** — Static analysis, report interpretation, and evidence-based reasoning  
**Practical status** — Pending due to a lab VM loading issue.

## About this study

I completed CAPA: The Basics to understand how capa identifies program capabilities and how to read its results. The most useful lesson for me was learning to separate what the code appears capable of doing from what has actually been observed during execution.

The lab VM stayed on a black screen, so I studied the room's explanations and supplied output for `cryptbot.bin`, then worked through review questions. This entry records that study, including the concepts I needed to revisit. Running capa and documenting my own results is the next step.

## Contents

- [How capa works](#how-capa-works)
- [File metadata](#file-metadata)
- [MITRE ATT&CK](#mitre-attck)
- [MAEC categories](#maec-categories)
- [Malware Behavior Catalog](#malware-behavior-catalog)
- [Capabilities and namespaces](#capabilities-and-namespaces)
- [Tracing a capability to its rule](#tracing-a-capability-to-its-rule)
- [Interpreting the supplied findings](#interpreting-the-supplied-findings)
- [Static and dynamic evidence](#static-and-dynamic-evidence)
- [Review questions](#review-questions)
- [Reference commands and next steps](#reference-commands-and-next-steps)

## How capa works

capa is an open-source tool developed by the FLARE team. It identifies capabilities such as file manipulation, process creation, and network communication. I see its results as a starting point for deciding which parts of a program to investigate.

During static analysis, an analysis backend examines the executable and extracts features. These can include API references, strings, constants, and code characteristics. An API gives a program access to functions provided by another component, such as the operating system.

Rules describe combinations of features. When their conditions are satisfied, capa reports the corresponding capability. Some rules combine other rule matches to describe more complex functionality.

```text
Executable → extracted features → rule evaluation → capability matches
```

A rule's scope determines where features are evaluated. A function-scoped rule, for example, evaluates features within a function. This gives context to a match, because the location and relationship of the clues matter as well as their presence.

capa also accepts reports from supported sandboxes. In that workflow, the available features depend on what the report contains, including recorded runtime activity.

Sources — [capa project](https://github.com/mandiant/capa), [rule format](https://github.com/mandiant/capa-rules/blob/master/doc/format.md).

## File metadata

Before interpreting the capabilities, I need to understand the file and the analysis mode. In the supplied example, `cryptbot.bin` is identified as a Windows PE file with `i386` architecture, analyzed statically.

| Field | What it tells me |
| --- | --- |
| `md5`, `sha1`, `sha256` | Hash values used to identify and correlate the file |
| `analysis` | The analysis mode, shown as `static` in the example |
| `os` | The operating-system context of the analyzed program |
| `format` | The file format, shown as `pe` |
| `arch` | The target architecture, with `i386` indicating 32-bit x86 |
| `path` | The location from which the analyzed file was loaded |

A hash helps associate findings with a particular file. It does not explain its behavior or establish malicious intent. In a future practical report, I would record SHA-256 alongside the command and tool version.

PE means Portable Executable, a Windows executable-image format. The example helped clarify why I should check the metadata when identifying a sample. Its `.bin` extension does not override the detected format. A Linux-style path describes where the sample was loaded in the analysis environment, while the sample itself can still target Windows.

Source — [Microsoft PE format documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

## MITRE ATT&CK

ATT&CK provides a shared vocabulary for adversary activity. A tactic describes a goal, a technique describes a way to pursue that goal, and a sub-technique describes a more specific form.

The PowerShell entry made this hierarchy easier to follow.

| Level | Example | Interpretation |
| --- | --- | --- |
| Tactic | Execution | The goal of running code or commands |
| Technique | Command and Scripting Interpreter, `T1059` | Using an interpreter to execute commands |
| Sub-technique | PowerShell, `T1059.001` | The PowerShell-specific form |

The report also places Scheduled Task, `T1053.005`, under Persistence. A task can arrange for a program to run at a particular time or trigger. To investigate that finding, I would want to inspect the configured command and the trigger.

The room's identifier questions also distinguished Obfuscated Files or Information, `T1027`, from its Indicator Removal from Tools sub-technique, `T1027.005`. The suffix identifies a more specific entry within the parent technique. Keeping the full identifier helps avoid losing that detail when documenting a mapping.

Other mappings in the room include the following investigation leads.

| Mapping in the supplied report | What I would examine next |
| --- | --- |
| Obfuscated Files or Information, `T1027` | The concealed code or data and how it is recovered |
| Virtualization/Sandbox Evasion · System Checks, `T1497.001` | The environmental checks and branches they influence |
| File and Directory Discovery, `T1083` | The locations enumerated and how the results are used |
| Resource Hijacking, `T1496` | Evidence of computing resources being used for an unauthorized purpose |

For the Resource Hijacking entry, I would look for evidence of how computing resources are used. Cryptocurrency strings alone would leave that question open.

These mappings connect matched functionality to investigation terminology. They do not establish actor attribution or prove that every mapped behavior occurred. Labels in an older report reflect its rule and framework versions.

Sources — [Execution](https://attack.mitre.org/tactics/TA0002/), [PowerShell](https://attack.mitre.org/techniques/T1059/001/), [Scheduled Task](https://attack.mitre.org/techniques/T1053/005/).

## MAEC categories

MAEC stands for Malware Attribute Enumeration and Characterization. It provides a structured language for describing and exchanging malware information.

In the supplied report, `malware-category` has the value `launcher`. The room connects this to writing and executing a file. Comparing it with the downloader pattern helped explain what the category adds to the report.

| Category discussed in the room | Interpretation | Follow-up question |
| --- | --- | --- |
| Launcher | Features suggest writing a file and launching it | Which file would be written, and what would execute it? |
| Downloader | Features suggest retrieving data and writing it to disk | What is the source, and what happens to the saved content? |

For example, a program might save an embedded component and start it. Another might retrieve a component from a server before saving it. These hypothetical patterns suggest different follow-up questions about the component's origin and use. I would still need to examine the relevant code and execution evidence to determine what happened in a particular case.

Source — [MAEC overview](https://maecproject.github.io/documentation/overview/).

## Malware Behavior Catalog

The Malware Behavior Catalog, or MBC, organizes malware objectives and behaviors for analysis and reporting. It complements ATT&CK with malware-focused details and low-level operations.

Its objectives are based on ATT&CK tactics and adapted to malware characterization. Anti-Behavioral Analysis and Anti-Static Analysis add goals specific to the analysis context.

| Term | Meaning | Example |
| --- | --- | --- |
| Objective | A broad goal or purpose | Anti-Static Analysis |
| Behavior | A defined behavior within that context | Executable Code Obfuscation |
| Method | A refinement or implementation of a behavior | Argument Obfuscation |
| Micro-objective | A category for low-level operations | File System or Communication |
| Micro-behavior | A low-level operation supporting different purposes | Read File or HTTP Communication |

Micro-behaviors can also have methods. This level of detail helps explain why the report lists ordinary operations such as reading files and allocating memory. Their significance comes from how the program uses them.

The room questions covered several identifiers that make this distinction concrete.

| Entry | Identifier | How I read it |
| --- | --- | --- |
| Create Process | `C0017` | A micro-behavior describing process creation |
| Virtual Machine Detection | `B0009` | A behavior associated with checking for a virtual environment |
| Encode Data | `C0026` | A micro-behavior refined by methods such as Base64 and XOR |
| HTTP Communication | `C0002` | A micro-behavior covering HTTP-related operations |

Base64 and XOR appear as `C0026.001` and `C0026.002`. For example, identifying XOR encoding tells me about a data transformation. To explain its purpose, I would need to inspect the input, output, and surrounding code. Similarly, a process-creation finding leaves questions about the executable and arguments, while a VM-detection finding leads to questions about how the check affects execution.

Sources — [Create Process](https://github.com/MBCProject/mbc-markdown/blob/main/micro-behaviors/process/create-process.md), [Virtual Machine Detection](https://github.com/MBCProject/mbc-markdown/blob/main/anti-behavioral-analysis/virtual-machine-detection.md), [Encode Data](https://github.com/MBCProject/mbc-markdown/blob/main/micro-behaviors/data/encode-data.md).

Sources — [MBC structure](https://github.com/MBCProject/mbc-markdown), [micro-behaviors](https://github.com/MBCProject/mbc-markdown/blob/main/micro-behaviors/README.md).

### Reading an entry

MBC entries can include an objective, a behavior, and an optional method.

```text
ANTI-STATIC ANALYSIS::Executable Code Obfuscation::Argument Obfuscation [B0032.020]
COMMUNICATION::HTTP Communication [C0002]
COMMUNICATION::HTTP Communication::Read Header [C0002.014]
```

Breaking the first entry into its parts gives me Anti-Static Analysis as the objective, Executable Code Obfuscation as the behavior, and Argument Obfuscation as the method.

For example, an API argument may be calculated at runtime instead of appearing as a readily visible constant. That makes the call harder to interpret statically. The room also includes Stack Strings, `B0032.017`, where strings are constructed on the stack and may be harder to recover with a simple string listing.

In the HTTP examples, `C0002` identifies HTTP Communication and `C0002.014` refines it to reading a header. Headers carry information associated with requests or responses. Finding header-reading functionality helps identify part of the communication logic. Determining the destination and transferred content requires further investigation.

Sources — [Executable Code Obfuscation](https://github.com/MBCProject/mbc-markdown/blob/main/anti-static-analysis/executable-code-obfuscation.md), [HTTP Communication](https://github.com/MBCProject/mbc-markdown/blob/main/micro-behaviors/communication/http-communication.md).

### Objectives in context

| Objective | What it describes |
| --- | --- |
| Anti-Behavioral Analysis | Obstructing observation during execution, such as through analysis-environment checks |
| Anti-Static Analysis | Making inspection of the file or code more difficult |
| Collection | Gathering information from a system or network |
| Command and Control | Communication supporting remote control or coordination |
| Credential Access | Obtaining credentials or access to accounts |
| Defense Evasion | Avoiding detection or defensive controls |
| Discovery | Learning about the system or environment |
| Execution | Running code or commands |
| Exfiltration | Transferring information out of the system |
| Impact | Disrupting or manipulating systems and data |
| Lateral Movement | Moving or propagating through an environment |
| Persistence | Maintaining a presence on a system |
| Privilege Escalation | Obtaining higher permissions |

I use these objectives to organize questions about purpose. The low-level operations provide details to examine, and the surrounding code or runtime activity helps connect them to a possible goal.

Source — [MBC objective descriptions](https://github.com/MBCProject/mbc-markdown/blob/main/mbc_summary.md).

## Capabilities and namespaces

A capability describes the functionality recognized by a matched rule. A namespace groups related capabilities in a hierarchy.

For example, `host-interaction/file-system/write` places a capability within host interaction, then file-system activity, then writing. This is a classification path. The metadata's `path` field separately describes a file location.

The namespace questions reinforced the difference between a top-level group and a more specific branch. In `anti-analysis/anti-vm/vm-detection`, `anti-analysis` is the top-level namespace and `anti-vm/vm-detection` is the nested path within it.

```text
anti-analysis
├── anti-vm
│   └── vm-detection
└── obfuscation
```

| Namespace covered in the room | What it groups |
| --- | --- |
| `anti-analysis` | Functionality related to obstructing analysis, including packing, obfuscation, and anti-debugging |
| `anti-analysis/obfuscation` | Obfuscation-related rules, including rules associated with tools such as Dotfuscator and SmartAssembly |
| `persistence` | Functionality associated with maintaining access or a presence |
| `load-code` | Runtime loading and execution of code, including the room's PowerShell-expression example |
| `data-manipulation` | Transformations such as encoding, hashing, and encryption |
| `nursery` | A staging area for rules that need further refinement, such as more complete metadata or examples |

The nursery entry also introduced a rule-maintenance detail. Rules can still match while they are in this staging area, so their supporting metadata and examples deserve inspection.

| Capability shown in the room | Namespace | Investigation focus |
| --- | --- | --- |
| Check HTTP status code | `communication/http/client` | Response-handling logic |
| Read file on Windows | `host-interaction/file-system/read` | Targeted files and paths |
| Create process on Windows | `host-interaction/process/create` | Executable and arguments |
| Schedule task via schtasks | `persistence/scheduled-tasks` | Task command and trigger |
| Reference anti-VM strings | `anti-analysis/anti-vm/vm-detection` | How the strings are used |

A label such as `read file on Windows (4 matches)` needs careful reading. The count refers to rule matches in the analyzed material. To determine how many files were actually read, I would need runtime evidence. Matching code might never execute, execute once, or execute repeatedly.

Sources — [namespace organization](https://github.com/mandiant/capa-rules#namespace-organization), [rule scopes](https://github.com/mandiant/capa-rules/blob/master/doc/format.md#meta-block).

## Tracing a capability to its rule

The room linked capability names to their YAML rule files. A rule contains metadata describing its name, namespace, and scope, followed by features that define its matching conditions.

| Capability or example | Rule file or namespace |
| --- | --- |
| `check HTTP status code` | `check-http-status-code.yml` |
| `reference anti-VM strings` | `reference-anti-vm-strings.yml` |
| `reference Base64 string` | `reference-base64-string.yml` in `data-manipulation/encoding/base64` |
| `run PowerShell expression` | A capability in the `load-code` top-level namespace |

The filenames illustrate a naming convention, with words commonly separated by hyphens. For a real investigation, I would check the actual file and its `meta.name` field when connecting a report entry to its definition.

The Base64 example gives a useful distinction between a clue and the operation it may suggest. The rule looks for a standard or URL-safe Base64 alphabet string. That reference supports a hypothesis about Base64-related functionality. Inspecting how the string is used is the next step in determining whether the code performs encoding or decoding.

Sources — [HTTP status rule](https://github.com/mandiant/capa-rules/blob/master/communication/http/client/check-http-status-code.yml), [Base64-string rule](https://github.com/mandiant/capa-rules/blob/master/data-manipulation/encoding/base64/reference-base64-string.yml).

### Example — A Windows Sandbox registry check

One exercise asked about an API in `check-for-windows-sandbox-via-registry.yml`. The answer was `RegOpenKeyEx`, a Windows API used to open a registry key. The registry stores configuration information for Windows and applications.

Reading the rule adds context to that API name. Its conditions combine `RegOpenKeyEx`, `RegEnumValue`, a registry-path substring, and a string referring to the `WDAGUtilityAccount` account. These conditions sit under an `and` statement within a function-scoped static rule.

That combination describes a more specific pattern than the presence of a registry API alone. `RegOpenKeyEx` is also used by legitimate software. A static match identifies features consistent with the check, while confirming the environment detected and the effect on execution requires further evidence.

Sources — [Windows Sandbox registry rule](https://github.com/mandiant/capa-rules/blob/master/anti-analysis/anti-vm/vm-detection/check-for-windows-sandbox-via-registry.yml), [RegOpenKeyEx documentation](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexa).

## Interpreting the supplied findings

The following entries stood out in the supplied output. I have paired each one with a question I would investigate when working with the sample.

| Displayed finding | Interpretation and follow-up |
| --- | --- |
| VMware or VirtualBox string references | Investigate possible environment checks and whether they affect control flow. |
| A Base64 string reference | Inspect where the text is used. A reference alone does not establish an encoding or decoding operation. |
| XOR encoding | Determine what data is transformed and how the result is used. |
| PowerShell-related functionality | Inspect the expression and its execution path before concluding that it ran. |
| Scheduled-task functionality | Inspect task creation logic, commands, and triggers. |
| Cryptocurrency-related strings | Investigate their use. A reference alone does not establish mining activity. |
| Allocation or modification of RWX memory | Investigate why memory is readable, writable, and executable. This finding alone does not establish process injection. |

For a practical follow-up, I would start with the scheduling logic and check which program it launches. I would then investigate whether the PowerShell and network findings belong to that same path. At this stage, that is a plan for testing a possible relationship. The summary does not establish the connection between those findings.

## Static and dynamic evidence

A sandbox provides an isolated, monitored environment for executing a sample. It can collect information about files, processes, and network activity. A virtual machine often supplies the guest operating system, while the sandbox coordinates execution and collection.

capa can analyze reports from compatible sandboxes, including CAPE. The conclusions depend on report coverage and on what occurred during the observation window.

Source — [CAPE sandboxing](https://capev2.readthedocs.io/en/latest/introduction/sandboxing.html).

### Example — Creating a TCP socket

```c
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
```

The arguments select IPv4, a byte-stream socket type, and TCP. This example helped me clarify the role of arguments, which supply values that configure an operation. A successful call creates a communication resource that the program can subsequently use to attempt a connection.

Finding related code statically does not demonstrate that the call ran. Even observed successful socket creation leaves connection establishment and data transfer to be investigated.

Source — [Windows socket function](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket).

## Review questions

I used the following hypothetical scenarios to check my understanding of capabilities, observations, and conclusions.

### What can I conclude if capa detects a file-writing capability during static analysis?

The code contains features associated with writing files. That alone does not show that a file was created or changed during execution. I would need execution evidence to confirm that the operation happened.

### What can be concluded when a sandbox records a file modification?

The file was modified during the monitored run. I cannot assume the same change happens every time the program runs. I would also need more context to understand why it changed the file.

### Why might capa detect a network capability while a sandbox records no communication?

A connection attempt could have failed. I would check the report for attempts and errors before accepting that explanation. The network code might also depend on a user action or a delay, so it may never have run during the test.

### Does creating a TCP socket mean a connection has been established?

No. Creating the socket provides a resource for communication. The program can then use it to attempt a connection, which may succeed or fail. Finding socket-related code during static analysis does not confirm that either operation took place.

### Learning reflection

My first answer about sockets went too far. I treated creating a TCP socket as if a connection had already been established. Working through the example helped me distinguish the creation of the resource, the connection attempt, and the successful connection.

I made a similar assumption when explaining why a sandbox might record no communication. A failed connection was one possible explanation, but the network code might also have depended on a user action that never happened. I need evidence to choose between those explanations.

These questions gave me a clearer way to read the room's output. My next step is to apply that reasoning to a report I generate myself.

## Reference commands and next steps

I collected these commands for the Windows lab session I still need to complete. They are reference examples, with `sample.exe` standing in for the file to be analyzed.

| Command | Purpose |
| --- | --- |
| `.\capa.exe -h` | Check options supported by the installed version |
| `.\capa.exe .\sample.exe` | Obtain the default summary |
| `.\capa.exe -v .\sample.exe` | Include additional matches, including nested rules |
| `.\capa.exe -vv .\sample.exe` | Examine how rules matched |
| `.\capa.exe -j .\sample.exe > .\capa-results.json` | Save structured JSON output |
| `.\capa.exe -t communication .\sample.exe` | Run rules matching the metadata term |

The room also provides saved reports. Its `Get-Content .\cryptbot.txt` example reads an existing report. This distinction matters when documenting the work, because reading saved output and generating a new analysis are separate activities. Verbose output helps connect a summary label to features and match locations. JSON supports further processing and exploration.

Source — [Official usage guide](https://github.com/mandiant/capa/blob/master/doc/usage.md).

### Exploring a JSON report

The final room questions connected JSON output to capa Explorer Web. The `-j` option produces structured results that the explorer can import for interactive navigation. The room calls the main filtering control the Global Search Box.

For a future review, I would import a compatible JSON report, search for a capability or namespace, expand its matches, and inspect the available evidence. Searching for a term such as `communication` helps narrow the displayed results. It does not run a new analysis or change which rules matched.

The explorer also provides a hierarchical view and grouping by function for static reports or by process for dynamic reports. This offers another way to follow the relationship between a summary finding and the details behind it.

Sources — [capa Explorer Web](https://mandiant.github.io/capa/explorer/), [explorer documentation](https://github.com/mandiant/capa/blob/master/web/explorer/README.md).

### Planned practical validation

When the lab becomes available, I plan to record the tool version and rules revision, identify the sample with SHA-256, capture the exact command and warnings, and trace one capability from its summary to the matching evidence. I will document the conclusion that evidence supports and any open questions.

Packing, obfuscation, and unsupported or insufficiently modeled functionality can leave results incomplete. Limited findings therefore need to be assessed alongside warnings and file context.

Source — [capa limitations](https://github.com/mandiant/capa/blob/master/doc/limitations.md).

## Use of AI assistance

AI assistance supported theoretical study and the organization of these notes.
