
    function createD3fCompletion(range) {
        return [
        {
            label: 'Defensive Technique',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "A method which makes a computer system more difficult to attack.",
            insertText: 'DefensiveTechnique',
            range: range,
        }
        ,
        {
            label: 'File Eviction',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "File eviction techniques evict files from system storage.",
            insertText: 'FileEviction',
            range: range,
        }
        ,
        {
            label: 'File Removal',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "The file removal technique deletes malicious artifacts or programs from a computer system.",
            insertText: 'FileRemoval',
            range: range,
        }
        ,
        {
            label: 'Email Removal',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "The email removal technique deletes email files from system storage.",
            insertText: 'EmailRemoval',
            range: range,
        }
        ,
        {
            label: 'Restore Access',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restoring an entity's access to resources.",
            insertText: 'RestoreAccess',
            range: range,
        }
        ,
        {
            label: 'Restore Network Access',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restoring a entity's access to a computer network.",
            insertText: 'RestoreNetworkAccess',
            range: range,
        }
        ,
        {
            label: 'Restore User Account Access',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restoring a user account's access to resources.",
            insertText: 'RestoreUserAccountAccess',
            range: range,
        }
        ,
        {
            label: 'Unlock Account',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restoring a user account's access to resources by unlocking a locked User Account.",
            insertText: 'UnlockAccount',
            range: range,
        }
        ,
        {
            label: 'Process Eviction',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Process eviction techniques terminate or remove running process.",
            insertText: 'ProcessEviction',
            range: range,
        }
        ,
        {
            label: 'Process Suspension',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Suspending a running process on a computer system.",
            insertText: 'ProcessSuspension',
            range: range,
        }
        ,
        {
            label: 'Process Termination',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Terminating a running application process on a computer system.",
            insertText: 'ProcessTermination',
            range: range,
        }
        ,
        {
            label: 'Message Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing email or instant message content to detect unauthorized activity.",
            insertText: 'MessageAnalysis',
            range: range,
        }
        ,
        {
            label: 'Sender MTA Reputation Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Characterizing the reputation of mail transfer agents (MTA) to determine the security risk in emails.",
            insertText: 'SenderMTAReputationAnalysis',
            range: range,
        }
        ,
        {
            label: 'Sender Reputation Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Ascertaining sender reputation based on information associated with a message (e.g. email/instant messaging).",
            insertText: 'SenderReputationAnalysis',
            range: range,
        }
        ,
        {
            label: 'Message Hardening',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Email or Messaging Hardening includes measures taken to ensure the confidentiality and integrity of user to user computer messages.",
            insertText: 'MessageHardening',
            range: range,
        }
        ,
        {
            label: 'Message Encryption',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Encrypting a message body using a cryptographic key.",
            insertText: 'MessageEncryption',
            range: range,
        }
        ,
        {
            label: 'Message Authentication',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Authenticating the sender of a message and ensuring message integrity.",
            insertText: 'MessageAuthentication',
            range: range,
        }
        ,
        {
            label: 'Transfer Agent Authentication',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Validating that server components of a messaging infrastructure are authorized to send a particular message.",
            insertText: 'TransferAgentAuthentication',
            range: range,
        }
        ,
        {
            label: 'Credential Eviction',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Credential Eviction techniques disable or remove compromised credentials from a computer network.",
            insertText: 'CredentialEviction',
            range: range,
        }
        ,
        {
            label: 'Credential Revoking',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Deleting a set of credentials permanently to prevent them from being used to authenticate.",
            insertText: 'CredentialRevoking',
            range: range,
        }
        ,
        {
            label: 'Authentication Cache Invalidation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Removing tokens or credentials from an authentication cache to prevent further user associated account accesses.",
            insertText: 'AuthenticationCacheInvalidation',
            range: range,
        }
        ,
        {
            label: 'Account Locking',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "The process of temporarily disabling user accounts on a system or domain.",
            insertText: 'AccountLocking',
            range: range,
        }
        ,
        {
            label: 'System Mapping',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "System mapping encompasses the techniques to identify the organization's systems, how they are configured and decomposed into subsystems and components, how they are dependent on one another, and where they are physically located.",
            insertText: 'SystemMapping',
            range: range,
        }
        ,
        {
            label: 'System Vulnerability Assessment',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "System vulnerability assessment relates all the vulnerabilities of a system's components in the context of their configuration and internal dependencies and can also include assessing risk emerging from the system's design as a whole, not just the sum of individual component vulnerabilities.",
            insertText: 'SystemVulnerabilityAssessment',
            range: range,
        }
        ,
        {
            label: 'Data Exchange Mapping',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Data exchange mapping identifies and models the organization's intended design for the flows of the data types, formats, and volumes between systems at the application layer.",
            insertText: 'DataExchangeMapping',
            range: range,
        }
        ,
        {
            label: 'Service Dependency Mapping',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Service dependency mapping determines the services on which each given service relies.",
            insertText: 'ServiceDependencyMapping',
            range: range,
        }
        ,
        {
            label: 'System Dependency Mapping',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "System dependency mapping identifies and models the dependencies of system components on each other to carry out their function.",
            insertText: 'SystemDependencyMapping',
            range: range,
        }
        ,
        {
            label: 'Decoy Environment',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "A Decoy Environment comprises hosts and networks for the purposes of deceiving an attacker.",
            insertText: 'DecoyEnvironment',
            range: range,
        }
        ,
        {
            label: 'Connected Honeynet',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "A decoy service, system, or environment, that is connected to the enterprise network, and simulates or emulates certain functionality to the network, without exposing full access to a production system.",
            insertText: 'ConnectedHoneynet',
            range: range,
        }
        ,
        {
            label: 'Integrated Honeynet',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "The practice of setting decoys in a production environment to entice interaction from attackers.",
            insertText: 'IntegratedHoneynet',
            range: range,
        }
        ,
        {
            label: 'Standalone Honeynet',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "An environment created for the purpose of attracting attackers and eliciting their behaviors that is not connected to any production enterprise systems.",
            insertText: 'StandaloneHoneynet',
            range: range,
        }
        ,
        {
            label: 'Network Mapping',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Network mapping encompasses the techniques to identify and model the physical layer, network layer, and data exchange layers of the organization's network and their physical location, and determine allowed pathways through that network.",
            insertText: 'NetworkMapping',
            range: range,
        }
        ,
        {
            label: 'Network Traffic Policy Mapping',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Network traffic policy mapping identifies and models the allowed pathways of data at the network, tranport, and/or application levels.",
            insertText: 'NetworkTrafficPolicyMapping',
            range: range,
        }
        ,
        {
            label: 'Network Vulnerability Assessment',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Network vulnerability assessment relates all the vulnerabilities of a network's components in the context of their configuration and interdependencies and can also include assessing risk emerging from the network's design as a whole, not just the sum of individual network node or network segment vulnerabilities.",
            insertText: 'NetworkVulnerabilityAssessment',
            range: range,
        }
        ,
        {
            label: 'Logical Link Mapping',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Logical link mapping creates a model of existing or previous node-to-node connections using network-layer data or metadata.",
            insertText: 'LogicalLinkMapping',
            range: range,
        }
        ,
        {
            label: 'Active Logical Link Mapping',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Active logical link mapping sends and receives network traffic as a means to map the whole data link layer, where the links represent logical data flows rather than physical connection",
            insertText: 'ActiveLogicalLinkMapping',
            range: range,
        }
        ,
        {
            label: 'Passive Logical Link Mapping',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Passive logical link mapping only listens to network traffic as a means to map the the whole data link layer, where the links represent logical data flows rather than physical connections.",
            insertText: 'PassiveLogicalLinkMapping',
            range: range,
        }
        ,
        {
            label: 'Physical Link Mapping',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Physical link mapping identifies and models the link connectivity of the network devices within a physical network.",
            insertText: 'PhysicalLinkMapping',
            range: range,
        }
        ,
        {
            label: 'Active Physical Link Mapping',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Active physical link mapping sends and receives network traffic as a means to map the physical layer.",
            insertText: 'ActivePhysicalLinkMapping',
            range: range,
        }
        ,
        {
            label: 'Passive Physical Link Mapping',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Passive physical link mapping only listens to network traffic as a means to map the physical layer.",
            insertText: 'PassivePhysicalLinkMapping',
            range: range,
        }
        ,
        {
            label: 'Identifier Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing identifier artifacts such as IP address, domain names, or URL(I)s.",
            insertText: 'IdentifierAnalysis',
            range: range,
        }
        ,
        {
            label: 'Identifier Activity Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Taking known malicious identifiers and determining if they are present in a system.",
            insertText: 'IdentifierActivityAnalysis',
            range: range,
        }
        ,
        {
            label: 'Homoglyph Detection',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Comparing strings using a variety of techniques to determine if a deceptive or malicious string is being presented to a user.",
            insertText: 'HomoglyphDetection',
            range: range,
        }
        ,
        {
            label: 'URL Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Determining if a URL is benign or malicious by analyzing the URL or its components.",
            insertText: 'URLAnalysis',
            range: range,
        }
        ,
        {
            label: 'Identifier Reputation Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing the reputation of an identifier.",
            insertText: 'IdentifierReputationAnalysis',
            range: range,
        }
        ,
        {
            label: 'File Hash Reputation Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing the reputation of a file hash.",
            insertText: 'FileHashReputationAnalysis',
            range: range,
        }
        ,
        {
            label: 'URL Reputation Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing the reputation of a URL.",
            insertText: 'URLReputationAnalysis',
            range: range,
        }
        ,
        {
            label: 'Domain Name Reputation Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing the reputation of a domain name.",
            insertText: 'DomainNameReputationAnalysis',
            range: range,
        }
        ,
        {
            label: 'IP Reputation Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing the reputation of an IP address.",
            insertText: 'IPReputationAnalysis',
            range: range,
        }
        ,
        {
            label: 'Operational Activity Mapping',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Operational activity mapping identifies activities of the organization and the organization's suborganizations, groups, roles, and individuals that carry out the activities and then establishes the dependencies of the activities on the systems and people that perform those activities.",
            insertText: 'OperationalActivityMapping',
            range: range,
        }
        ,
        {
            label: 'Access Modeling',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Access modeling identifies and records the access permissions granted to administrators, users, groups, and systems.",
            insertText: 'AccessModeling',
            range: range,
        }
        ,
        {
            label: 'Organization Mapping',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Organization mapping identifies and models the people, roles, and groups with an organization and the relations between them.",
            insertText: 'OrganizationMapping',
            range: range,
        }
        ,
        {
            label: 'Operational Dependency Mapping',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Operational dependency mapping identifies and models the dependencies of the organization's activities on each other and on the organization's performers (people, systems, and services.)  This may include modeling the higher- and lower-level activities of an organization forming a hierarchy, or layering, of the dependencies in an organization's activities.",
            insertText: 'OperationalDependencyMapping',
            range: range,
        }
        ,
        {
            label: 'Operational Risk Assessment',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Operational risk assessment identifies and models the vulnerabilities of, and risks to, an organization's activities individually and as a whole.",
            insertText: 'OperationalRiskAssessment',
            range: range,
        }
        ,
        {
            label: 'Asset Inventory',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Asset inventorying identifies and records the organization's assets and enriches each inventory item with knowledge about their vulnerabilities.",
            insertText: 'AssetInventory',
            range: range,
        }
        ,
        {
            label: 'Data Inventory',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Data inventorying identifies and records the schemas, formats, volumes, and locations of data stored and used on the organization's architecture.",
            insertText: 'DataInventory',
            range: range,
        }
        ,
        {
            label: 'Configuration Inventory',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Configuration inventory identifies and records the configuration of software and hardware and their components throughout the organization.",
            insertText: 'ConfigurationInventory',
            range: range,
        }
        ,
        {
            label: 'Software Inventory',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Software inventorying identifies and records the software items in the organization's architecture.",
            insertText: 'SoftwareInventory',
            range: range,
        }
        ,
        {
            label: 'Network Node Inventory',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Network node inventorying identifies and records all the network nodes (hosts, routers, switches, firewalls, etc.) in the organization's architecture.",
            insertText: 'NetworkNodeInventory',
            range: range,
        }
        ,
        {
            label: 'Asset Vulnerability Enumeration',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Asset vulnerability enumeration enriches inventory items with knowledge identifying their vulnerabilities.",
            insertText: 'AssetVulnerabilityEnumeration',
            range: range,
        }
        ,
        {
            label: 'Container Image Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing a Container Image with respect to a set of policies.",
            insertText: 'ContainerImageAnalysis',
            range: range,
        }
        ,
        {
            label: 'Hardware Component Inventory',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Hardware component inventorying identifies and records the hardware items in the organization's architecture.",
            insertText: 'HardwareComponentInventory',
            range: range,
        }
        ,
        {
            label: 'Restore Object',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restoring an object for an entity to access. This is the broadest class for object restoral.",
            insertText: 'RestoreObject',
            range: range,
        }
        ,
        {
            label: 'Reissue Credential',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Issue a new credential to a user which supercedes their old credential.",
            insertText: 'ReissueCredential',
            range: range,
        }
        ,
        {
            label: 'Restore Configuration',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restoring an software configuration.",
            insertText: 'RestoreConfiguration',
            range: range,
        }
        ,
        {
            label: 'Restore Database',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restoring the data in a database.",
            insertText: 'RestoreDatabase',
            range: range,
        }
        ,
        {
            label: 'Restore Disk Image',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restoring a previously captured disk image a hard drive.",
            insertText: 'RestoreDiskImage',
            range: range,
        }
        ,
        {
            label: 'Restore Software',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restoring software to a host.",
            insertText: 'RestoreSoftware',
            range: range,
        }
        ,
        {
            label: 'Restore File',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restoring a file for an entity to access.",
            insertText: 'RestoreFile',
            range: range,
        }
        ,
        {
            label: 'Restore Email',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restoring an email for an entity to access.",
            insertText: 'RestoreEmail',
            range: range,
        }
        ,
        {
            label: 'Execution Isolation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Execution Isolation techniques prevent application processes from accessing non-essential system resources, such as memory, devices, or files.",
            insertText: 'ExecutionIsolation',
            range: range,
        }
        ,
        {
            label: 'IO Port Restriction',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Limiting access to computer input/output (IO) ports to restrict unauthorized devices.",
            insertText: 'IOPortRestriction',
            range: range,
        }
        ,
        {
            label: 'Kernel-based Process Isolation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Using kernel-level capabilities to isolate processes.",
            insertText: 'Kernel-basedProcessIsolation',
            range: range,
        }
        ,
        {
            label: 'System Call Filtering',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Configuring a kernel to use an allow or deny list to filter kernel api calls.",
            insertText: 'SystemCallFiltering',
            range: range,
        }
        ,
        {
            label: 'Mandatory Access Control',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Controlling access to local computer system resources with kernel-level capabilities.",
            insertText: 'MandatoryAccessControl',
            range: range,
        }
        ,
        {
            label: 'Hardware-based Process Isolation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Preventing one process from writing to the memory space of another process through hardware based address manager implementations.",
            insertText: 'Hardware-basedProcessIsolation',
            range: range,
        }
        ,
        {
            label: 'Executable Allowlisting',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Using a digital signature to authenticate a file before opening.",
            insertText: 'ExecutableAllowlisting',
            range: range,
        }
        ,
        {
            label: 'Executable Denylisting',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Blocking the execution of files on a host in accordance with defined application policy rules.",
            insertText: 'ExecutableDenylisting',
            range: range,
        }
        ,
        {
            label: 'Decoy Object',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "A Decoy Object is created and deployed for the purposes of deceiving attackers.",
            insertText: 'DecoyObject',
            range: range,
        }
        ,
        {
            label: 'Decoy Public Release',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Issuing publicly released media to deceive adversaries.",
            insertText: 'DecoyPublicRelease',
            range: range,
        }
        ,
        {
            label: 'Decoy Session Token',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "An authentication token created for the purposes of deceiving an adversary.",
            insertText: 'DecoySessionToken',
            range: range,
        }
        ,
        {
            label: 'Decoy Persona',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Establishing a fake online identity to misdirect, deceive, and or interact with adversaries.",
            insertText: 'DecoyPersona',
            range: range,
        }
        ,
        {
            label: 'Decoy User Credential',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "A Credential created for the purpose of deceiving an adversary.",
            insertText: 'DecoyUserCredential',
            range: range,
        }
        ,
        {
            label: 'Decoy File',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "A file created for the purposes of deceiving an adversary.",
            insertText: 'DecoyFile',
            range: range,
        }
        ,
        {
            label: 'Decoy Network Resource',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Deploying a network resource for the purposes of deceiving an adversary.",
            insertText: 'DecoyNetworkResource',
            range: range,
        }
        ,
        {
            label: 'File Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "File Analysis is an analytic process to determine a file's status. For example: virus, trojan, benign, malicious, trusted, unauthorized, sensitive, etc.",
            insertText: 'FileAnalysis',
            range: range,
        }
        ,
        {
            label: 'Emulated File Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Emulating instructions in a file looking for specific patterns.",
            insertText: 'EmulatedFileAnalysis',
            range: range,
        }
        ,
        {
            label: 'File Content Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Employing a pattern matching algorithm to statically analyze the content of files.",
            insertText: 'FileContentAnalysis',
            range: range,
        }
        ,
        {
            label: 'File Content Rules',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Employing a pattern matching rule language to analyze the content of files.",
            insertText: 'FileContentRules',
            range: range,
        }
        ,
        {
            label: 'Dynamic Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Executing or opening a file in a synthetic \"sandbox\" environment to determine if the file is a malicious program or if the file exploits another program such as a document reader.",
            insertText: 'DynamicAnalysis',
            range: range,
        }
        ,
        {
            label: 'File Hashing',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Employing file hash comparisons to detect known malware.",
            insertText: 'FileHashing',
            range: range,
        }
        ,
        {
            label: 'Network Isolation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Network Isolation techniques prevent network hosts from accessing non-essential system network resources.",
            insertText: 'NetworkIsolation',
            range: range,
        }
        ,
        {
            label: 'DNS Allowlisting',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Permitting only approved domains and their subdomains to be resolved.",
            insertText: 'DNSAllowlisting',
            range: range,
        }
        ,
        {
            label: 'Broadcast Domain Isolation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Broadcast isolation restricts the number of computers a host can contact on their LAN.",
            insertText: 'BroadcastDomainIsolation',
            range: range,
        }
        ,
        {
            label: 'Network Traffic Filtering',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restricting network traffic originating from any location.",
            insertText: 'NetworkTrafficFiltering',
            range: range,
        }
        ,
        {
            label: 'Outbound Traffic Filtering',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restricting network traffic originating from a private host or enclave destined towards untrusted networks.",
            insertText: 'OutboundTrafficFiltering',
            range: range,
        }
        ,
        {
            label: 'Inbound Traffic Filtering',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restricting network traffic originating from untrusted networks destined towards a private host or enclave.",
            insertText: 'InboundTrafficFiltering',
            range: range,
        }
        ,
        {
            label: 'Email Filtering',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Filtering incoming email traffic based on specific criteria.",
            insertText: 'EmailFiltering',
            range: range,
        }
        ,
        {
            label: 'DNS Denylisting',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Blocking DNS Network Traffic based on criteria such as IP address, domain name, or DNS query type.",
            insertText: 'DNSDenylisting',
            range: range,
        }
        ,
        {
            label: 'Forward Resolution IP Denylisting',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Blocking a DNS lookup's answer's IP address value.",
            insertText: 'ForwardResolutionIPDenylisting',
            range: range,
        }
        ,
        {
            label: 'Reverse Resolution IP Denylisting',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Blocking a reverse lookup based on the query's IP address value.",
            insertText: 'ReverseResolutionIPDenylisting',
            range: range,
        }
        ,
        {
            label: 'Reverse Resolution Domain Denylisting',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Blocking a reverse DNS lookup's answer's domain name value.",
            insertText: 'ReverseResolutionDomainDenylisting',
            range: range,
        }
        ,
        {
            label: 'Forward Resolution Domain Denylisting',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Blocking a lookup based on the query's domain name value.",
            insertText: 'ForwardResolutionDomainDenylisting',
            range: range,
        }
        ,
        {
            label: 'Hierarchical Domain Denylisting',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Blocking the resolution of any subdomain of a specified domain name.",
            insertText: 'HierarchicalDomainDenylisting',
            range: range,
        }
        ,
        {
            label: 'Homoglyph Denylisting',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Blocking DNS queries that are deceptively similar to legitimate domain names.",
            insertText: 'HomoglyphDenylisting',
            range: range,
        }
        ,
        {
            label: 'Encrypted Tunnels',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Encrypted encapsulation of routable network traffic.",
            insertText: 'EncryptedTunnels',
            range: range,
        }
        ,
        {
            label: 'Platform Monitoring',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Monitoring platform components such as operating systems software, hardware devices, or firmware.",
            insertText: 'PlatformMonitoring',
            range: range,
        }
        ,
        {
            label: 'Firmware Behavior Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing the behavior of embedded code in firmware and looking for anomalous behavior and suspicious activity.",
            insertText: 'FirmwareBehaviorAnalysis',
            range: range,
        }
        ,
        {
            label: 'Firmware Embedded Monitoring Code',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Monitoring code is injected into firmware for integrity monitoring of firmware and firmware data.",
            insertText: 'FirmwareEmbeddedMonitoringCode',
            range: range,
        }
        ,
        {
            label: 'File Integrity Monitoring',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Detecting any suspicious changes to files in a computer system.",
            insertText: 'FileIntegrityMonitoring',
            range: range,
        }
        ,
        {
            label: 'Firmware Verification',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Cryptographically verifying firmware integrity.",
            insertText: 'FirmwareVerification',
            range: range,
        }
        ,
        {
            label: 'Peripheral Firmware Verification',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Cryptographically verifying peripheral firmware integrity.",
            insertText: 'PeripheralFirmwareVerification',
            range: range,
        }
        ,
        {
            label: 'System Firmware Verification',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Cryptographically verifying installed system firmware integrity.",
            insertText: 'SystemFirmwareVerification',
            range: range,
        }
        ,
        {
            label: 'Operating System Monitoring',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "The operating system software, for D3FEND's purposes, includes the kernel and its process management functions, hardware drivers, initialization or boot logic. It also includes and other key system daemons and their configuration. The monitoring or analysis of these components for unauthorized activity constitute **Operating System Monitoring**.",
            insertText: 'OperatingSystemMonitoring',
            range: range,
        }
        ,
        {
            label: 'Memory Boundary Tracking',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing a call stack for return addresses which point to unexpected  memory locations.",
            insertText: 'MemoryBoundaryTracking',
            range: range,
        }
        ,
        {
            label: 'System Init Config Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analysis of any system process startup configuration.",
            insertText: 'SystemInitConfigAnalysis',
            range: range,
        }
        ,
        {
            label: 'Endpoint Health Beacon',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Monitoring the security status of an endpoint by sending periodic messages with health status, where absence of a response may indicate that the endpoint has been compromised.",
            insertText: 'EndpointHealthBeacon',
            range: range,
        }
        ,
        {
            label: 'Input Device Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Operating system level mechanisms to prevent abusive input device exploitation.",
            insertText: 'InputDeviceAnalysis',
            range: range,
        }
        ,
        {
            label: 'Scheduled Job Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analysis of source files, processes, destination files, or destination servers associated with a scheduled job to detect unauthorized use of job scheduling.",
            insertText: 'ScheduledJobAnalysis',
            range: range,
        }
        ,
        {
            label: 'User Session Init Config Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing modifications to user session config files such as .bashrc or .bash_profile.",
            insertText: 'UserSessionInitConfigAnalysis',
            range: range,
        }
        ,
        {
            label: 'System File Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Monitoring system files such as authentication databases, configuration files, system logs, and system executables for modification or tampering.",
            insertText: 'SystemFileAnalysis',
            range: range,
        }
        ,
        {
            label: 'Service Binary Verification',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing changes in service binary files by comparing to a source of truth.",
            insertText: 'ServiceBinaryVerification',
            range: range,
        }
        ,
        {
            label: 'System Daemon Monitoring',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Tracking changes to the state or configuration of critical system level processes.",
            insertText: 'SystemDaemonMonitoring',
            range: range,
        }
        ,
        {
            label: 'Application Hardening',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Application Hardening makes an executable application more resilient to a class of exploits which either introduce new code or execute unwanted existing code. These techniques may be applied at compile-time or on an application binary.",
            insertText: 'ApplicationHardening',
            range: range,
        }
        ,
        {
            label: 'Dead Code Elimination',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Removing unreachable or \"dead code\" from compiled source code.",
            insertText: 'DeadCodeElimination',
            range: range,
        }
        ,
        {
            label: 'Exception Handler Pointer Validation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Validates that a referenced exception handler pointer is a valid exception handler.",
            insertText: 'ExceptionHandlerPointerValidation',
            range: range,
        }
        ,
        {
            label: 'Segment Address Offset Randomization',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Randomizing the base (start) address of one or more segments of memory during the initialization of a process.",
            insertText: 'SegmentAddressOffsetRandomization',
            range: range,
        }
        ,
        {
            label: 'Process Segment Execution Prevention',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Preventing execution of any address in a memory region other than the code segment.",
            insertText: 'ProcessSegmentExecutionPrevention',
            range: range,
        }
        ,
        {
            label: 'Stack Frame Canary Validation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Comparing a value stored in a stack frame with a known good value in order to prevent or detect a memory segment overwrite.",
            insertText: 'StackFrameCanaryValidation',
            range: range,
        }
        ,
        {
            label: 'Application Configuration Hardening',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Modifying an application's configuration to reduce its attack surface.",
            insertText: 'ApplicationConfigurationHardening',
            range: range,
        }
        ,
        {
            label: 'Pointer Authentication',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Comparing the cryptographic hash or derivative of a pointer's value to an expected value.",
            insertText: 'PointerAuthentication',
            range: range,
        }
        ,
        {
            label: 'Process Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Process Analysis consists of observing a running application process and analyzing it to watch for certain behaviors or conditions which may indicate adversary activity. Analysis can occur inside of the process or through a third-party monitoring application. Examples include monitoring system and privileged calls, monitoring process initiation chains, and memory boundary allocations.",
            insertText: 'ProcessAnalysis',
            range: range,
        }
        ,
        {
            label: 'Indirect Branch Call Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing vendor specific branch call recording in order to detect ROP style attacks.",
            insertText: 'IndirectBranchCallAnalysis',
            range: range,
        }
        ,
        {
            label: 'Process Self-Modification Detection',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Detects processes that modify, change, or replace their own code at runtime.",
            insertText: 'ProcessSelf-ModificationDetection',
            range: range,
        }
        ,
        {
            label: 'File Access Pattern Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing the files accessed by a process to identify unauthorized activity.",
            insertText: 'FileAccessPatternAnalysis',
            range: range,
        }
        ,
        {
            label: 'Shadow Stack Comparisons',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Comparing a call stack in system memory with a shadow call stack maintained by the processor to determine unauthorized shellcode activity.",
            insertText: 'ShadowStackComparisons',
            range: range,
        }
        ,
        {
            label: 'Script Execution Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing the execution of a script to detect unauthorized user activity.",
            insertText: 'ScriptExecutionAnalysis',
            range: range,
        }
        ,
        {
            label: 'Database Query String Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing database queries to detect [SQL Injection](https://capec.mitre.org/data/definitions/66.html).",
            insertText: 'DatabaseQueryStringAnalysis',
            range: range,
        }
        ,
        {
            label: 'Process Code Segment Verification',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Comparing the \"text\" or \"code\" memory segments to a source of truth.",
            insertText: 'ProcessCodeSegmentVerification',
            range: range,
        }
        ,
        {
            label: 'System Call Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing system calls to determine whether a process is exhibiting unauthorized behavior.",
            insertText: 'SystemCallAnalysis',
            range: range,
        }
        ,
        {
            label: 'File Creation Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing the properties of file create system call invocations.",
            insertText: 'FileCreationAnalysis',
            range: range,
        }
        ,
        {
            label: 'Process Spawn Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing spawn arguments or attributes of a process to detect processes that are unauthorized.",
            insertText: 'ProcessSpawnAnalysis',
            range: range,
        }
        ,
        {
            label: 'Process Lineage Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Identification of suspicious processes executing on an end-point device by examining the ancestry and siblings of a process, and the associated metadata of each node on the tree, such as process execution, duration, and order relative to siblings and ancestors.",
            insertText: 'ProcessLineageAnalysis',
            range: range,
        }
        ,
        {
            label: 'Credential Hardening',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Credential Hardening techniques modify system or network properties in order to protect system or network/domain credentials.",
            insertText: 'CredentialHardening',
            range: range,
        }
        ,
        {
            label: 'Credential Transmission Scoping',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Limiting the transmission of a credential to a scoped set of relying parties.",
            insertText: 'CredentialTransmissionScoping',
            range: range,
        }
        ,
        {
            label: 'Credential Rotation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Expiring an existing set of credentials and reissuing a new valid set",
            insertText: 'CredentialRotation',
            range: range,
        }
        ,
        {
            label: 'Certificate Pinning',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Persisting either a server's X.509 certificate or their public key and comparing that to server's presented identity to allow for greater client confidence in the remote server's identity for SSL connections.",
            insertText: 'CertificatePinning',
            range: range,
        }
        ,
        {
            label: 'One-time Password',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "A one-time password is valid for only one user authentication.",
            insertText: 'One-timePassword',
            range: range,
        }
        ,
        {
            label: 'Certificate-based Authentication',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Requiring a digital certificate in order to authenticate a user.",
            insertText: 'Certificate-basedAuthentication',
            range: range,
        }
        ,
        {
            label: 'Biometric Authentication',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Using biological measures in order to authenticate a user.",
            insertText: 'BiometricAuthentication',
            range: range,
        }
        ,
        {
            label: 'Strong Password Policy',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Modifying system configuration to increase password strength.",
            insertText: 'StrongPasswordPolicy',
            range: range,
        }
        ,
        {
            label: 'Domain Trust Policy',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restricting inter-domain trust by modifying domain configuration.",
            insertText: 'DomainTrustPolicy',
            range: range,
        }
        ,
        {
            label: 'Multi-factor Authentication',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Requiring proof of two or more pieces of evidence in order to authenticate a user.",
            insertText: 'Multi-factorAuthentication',
            range: range,
        }
        ,
        {
            label: 'User Account Permissions',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restricting a user account's access to resources.",
            insertText: 'UserAccountPermissions',
            range: range,
        }
        ,
        {
            label: 'User Behavior Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "User behavior analytics (\"UBA\") as defined by Gartner, is a cybersecurity process about detection of insider threats, targeted attacks, and financial fraud. UBA solutions look at patterns of human behavior, and then apply algorithms and statistical analysis to detect meaningful anomalies from those patterns-anomalies that indicate potential threats.' Instead of tracking devices or security events, UBA tracks a system's users. Big data platforms are increasing UBA functionality by allowing them to analyze petabytes worth of data to detect insider threats and advanced persistent threats.",
            insertText: 'UserBehaviorAnalysis',
            range: range,
        }
        ,
        {
            label: 'Credential Compromise Scope Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Determining which credentials may have been compromised by analyzing the user logon history of a particular system.",
            insertText: 'CredentialCompromiseScopeAnalysis',
            range: range,
        }
        ,
        {
            label: 'Job Function Access Pattern Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Detecting anomalies in user access patterns by comparing user access activity to behavioral profiles that categorize users by role such as job title, function, department.",
            insertText: 'JobFunctionAccessPatternAnalysis',
            range: range,
        }
        ,
        {
            label: 'User Geolocation Logon Pattern Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Monitoring geolocation data of user logon attempts and comparing it to a baseline user behavior profile to identify anomalies in logon location.",
            insertText: 'UserGeolocationLogonPatternAnalysis',
            range: range,
        }
        ,
        {
            label: 'Session Duration Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing the duration of user sessions in order to detect unauthorized  activity.",
            insertText: 'SessionDurationAnalysis',
            range: range,
        }
        ,
        {
            label: 'User Data Transfer Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing the amount of data transferred by a user.",
            insertText: 'UserDataTransferAnalysis',
            range: range,
        }
        ,
        {
            label: 'Web Session Activity Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Monitoring changes in user web session behavior by comparing current web session activity to a baseline behavior profile or a catalog of predetermined malicious behavior.",
            insertText: 'WebSessionActivityAnalysis',
            range: range,
        }
        ,
        {
            label: 'Authorization Event Thresholding',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Collecting authorization events, creating a baseline user profile, and determining whether authorization events are consistent with the baseline profile.",
            insertText: 'AuthorizationEventThresholding',
            range: range,
        }
        ,
        {
            label: 'Authentication Event Thresholding',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Collecting authentication events, creating a baseline user profile, and determining whether authentication events are consistent with the baseline profile.",
            insertText: 'AuthenticationEventThresholding',
            range: range,
        }
        ,
        {
            label: 'Resource Access Pattern Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing the resources accessed by a user to identify unauthorized activity.",
            insertText: 'ResourceAccessPatternAnalysis',
            range: range,
        }
        ,
        {
            label: 'Domain Account Monitoring',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Monitoring the existence of or changes to Domain User Accounts.",
            insertText: 'DomainAccountMonitoring',
            range: range,
        }
        ,
        {
            label: 'Local Account Monitoring',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing local user accounts to detect unauthorized activity.",
            insertText: 'LocalAccountMonitoring',
            range: range,
        }
        ,
        {
            label: 'Platform Hardening',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Hardening components of a Platform with the intention of making them more difficult to exploit.\n\nPlatforms includes components such as:\n* BIOS UEFI Subsystems\n* Hardware security devices such as Trusted Platform Modules\n* Boot process logic or code\n* Kernel software components",
            insertText: 'PlatformHardening',
            range: range,
        }
        ,
        {
            label: 'RF Shielding',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Adding physical barriers to a platform to prevent undesired radio interference.",
            insertText: 'RFShielding',
            range: range,
        }
        ,
        {
            label: 'Bootloader Authentication',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Cryptographically authenticating the bootloader software before system boot.",
            insertText: 'BootloaderAuthentication',
            range: range,
        }
        ,
        {
            label: 'TPM Boot Integrity',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Assuring the integrity of a platform by demonstrating that the boot process starts from a trusted combination of hardware and software and continues until the operating system has fully booted and applications are running.  Sometimes called Static Root of Trust Measurement (STRM).",
            insertText: 'TPMBootIntegrity',
            range: range,
        }
        ,
        {
            label: 'Disk Encryption',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Encrypting a hard disk partition to prevent cleartext access to a file system.",
            insertText: 'DiskEncryption',
            range: range,
        }
        ,
        {
            label: 'File Encryption',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Encrypting a file using a cryptographic key.",
            insertText: 'FileEncryption',
            range: range,
        }
        ,
        {
            label: 'Driver Load Integrity Checking',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Ensuring the integrity of drivers loaded during initialization of the operating system.",
            insertText: 'DriverLoadIntegrityChecking',
            range: range,
        }
        ,
        {
            label: 'Local File Permissions',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restricting access to a local file by configuring operating system functionality.",
            insertText: 'LocalFilePermissions',
            range: range,
        }
        ,
        {
            label: 'Software Update',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Replacing old software on a computer system component.",
            insertText: 'SoftwareUpdate',
            range: range,
        }
        ,
        {
            label: 'System Configuration Permissions',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restricting system configuration modifications to a specific user or group of users.",
            insertText: 'SystemConfigurationPermissions',
            range: range,
        }
        ,
        {
            label: 'Network Traffic Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing intercepted or summarized computer network traffic to detect unauthorized activity.",
            insertText: 'NetworkTrafficAnalysis',
            range: range,
        }
        ,
        {
            label: 'Client-server Payload Profiling',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Comparing client-server request and response payloads to a baseline profile to identify outliers.",
            insertText: 'Client-serverPayloadProfiling',
            range: range,
        }
        ,
        {
            label: 'Connection Attempt Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing failed connections in a network to detect unauthorized activity.",
            insertText: 'ConnectionAttemptAnalysis',
            range: range,
        }
        ,
        {
            label: 'File Carving',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Identifying and extracting files from network application protocols through the use of network stream reassembly software.",
            insertText: 'FileCarving',
            range: range,
        }
        ,
        {
            label: 'Network Traffic Community Deviation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Establishing baseline communities of network hosts and identifying statistically divergent inter-community communication.",
            insertText: 'NetworkTrafficCommunityDeviation',
            range: range,
        }
        ,
        {
            label: 'Per Host Download-Upload Ratio Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Detecting anomalies that indicate malicious activity by comparing the amount of data downloaded versus data uploaded by a host.",
            insertText: 'PerHostDownload-UploadRatioAnalysis',
            range: range,
        }
        ,
        {
            label: 'Relay Pattern Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "The detection of an internal host relaying traffic between the internal network and the external network.",
            insertText: 'RelayPatternAnalysis',
            range: range,
        }
        ,
        {
            label: 'Byte Sequence Emulation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing sequences of bytes and determining if they likely represent malicious shellcode.",
            insertText: 'ByteSequenceEmulation',
            range: range,
        }
        ,
        {
            label: 'Administrative Network Activity Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Detection of unauthorized use of administrative network protocols by analyzing network activity against a baseline.",
            insertText: 'AdministrativeNetworkActivityAnalysis',
            range: range,
        }
        ,
        {
            label: 'Protocol Metadata Anomaly Detection',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Collecting network communication protocol metadata and identifying statistical outliers.",
            insertText: 'ProtocolMetadataAnomalyDetection',
            range: range,
        }
        ,
        {
            label: 'Certificate Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing Public Key Infrastructure certificates to detect if they have been misconfigured or spoofed using both network traffic, certificate fields and third-party logs.",
            insertText: 'CertificateAnalysis',
            range: range,
        }
        ,
        {
            label: 'Active Certificate Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Actively collecting PKI certificates by connecting to the server and downloading its server certificates for analysis.",
            insertText: 'ActiveCertificateAnalysis',
            range: range,
        }
        ,
        {
            label: 'Passive Certificate Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Collecting host certificates from network traffic or other passive sources like a certificate transparency log and analyzing them for unauthorized activity.",
            insertText: 'PassiveCertificateAnalysis',
            range: range,
        }
        ,
        {
            label: 'Passive Certificate Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Passively collecting certificates and analyzing them.",
            insertText: 'PassiveCertificateAnalysis',
            range: range,
        }
        ,
        {
            label: 'Inbound Session Volume Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing inbound network session or connection attempt volume.",
            insertText: 'InboundSessionVolumeAnalysis',
            range: range,
        }
        ,
        {
            label: 'DNS Traffic Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analysis of domain name metadata, including name and DNS records, to determine whether the domain is likely to resolve to an undesirable host.",
            insertText: 'DNSTrafficAnalysis',
            range: range,
        }
        ,
        {
            label: 'IPC Traffic Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing standard inter process communication (IPC) protocols to detect deviations from normal protocol activity.",
            insertText: 'IPCTrafficAnalysis',
            range: range,
        }
        ,
        {
            label: 'RPC Traffic Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Monitoring the activity of remote procedure calls in communication traffic to establish standard protocol operations and potential attacker activities.",
            insertText: 'RPCTrafficAnalysis',
            range: range,
        }
        ,
        {
            label: 'Remote Terminal Session Detection',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Detection of an unauthorized remote live terminal console session by examining network traffic to a network host.",
            insertText: 'RemoteTerminalSessionDetection',
            range: range,
        }
        ,
        {
            label: 'Ingress Tool Transfer',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Session is initiated by the client, and may be a custom protocol which is why it is related to generic network traffic instead of file transfer network traffic.",
            insertText: 'T1105',
            range: range,
        }
        ,
        {
            label: 'Traffic Signaling',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "used all over so its not just internet traffic",
            insertText: 'T1205',
            range: range,
        }
        ,
        {
            label: 'Kerberoasting',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Service Provider Name (SPN) scanning is one way to gather hashes, which results in RPC calls conforming to the NSPI protocol.",
            insertText: 'T1558.003',
            range: range,
        }
        ,
        {
            label: 'System Services',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "This technique has been deprecated.",
            insertText: 'T1569',
            range: range,
        }
        ,
        {
            label: 'Scheduled Task/Job Execution',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "The sub-techniques of this are specific software implementations of scheduling capabilities",
            insertText: 'T1053',
            range: range,
        }
        ,
        {
            label: 'Schtasks Execution',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Renamed from ATT&CK to be consistent with at, launchd, cron siblings; name as is looks like parent.  Not sure why parent is not just Scheduled Task [Execution[.",
            insertText: 'T1053.005',
            range: range,
        }
        ,
        {
            label: 'Network Logon Script',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Group Policy Object / Active Directory Users and Computers are both Active Directory-based",
            insertText: 'T1037.003',
            range: range,
        }
        ,
        {
            label: 'Digital Artifact',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An information-bearing artifact (object) that is, or is encoded to be used with, a digital computer system. This concept is broad to include the literal instances of an artifact, or an implicit summarization of changes to or properties of other artifacts.",
            insertText: 'DigitalArtifact',
            range: range,
        }
        ,
        {
            label: 'Blob',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A binary large object (BLOB) is a collection of binary data stored as a single entity. Blobs are typically images, audio or other multimedia objects, though sometimes binary executable code is stored as a blob. They can exist as persistent values inside some databases, or exist at runtime as program variables in some languages. The term is used in NoSQL databases, especially in key-value store databases such as Redis. The term is also used by languages that allow runtime manipulation of Blobs, like JavaScript. (en)",
            insertText: 'Blob',
            range: range,
        }
        ,
        {
            label: 'Enclave',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Network enclaves consist of standalone assets that do not interact with other information systems or networks. A major difference between a DMZ or demilitarized zone and a network enclave is a DMZ allows inbound and outbound traffic access, where firewall boundaries are traversed. In an enclave, firewall boundaries are not traversed. Enclave protection tools can be used to provide protection within specific security domains. These mechanisms are installed as part of an Intranet to connect networks that have similar security requirements.",
            insertText: 'Enclave',
            range: range,
        }
        ,
        {
            label: 'Platform',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Platform includes the hardware and OS. The term computing platform can refer to different abstraction levels, including a certain hardware architecture, an operating system (OS), and runtime libraries. In total it can be said to be the stage on which computer programs can run.",
            insertText: 'Platform',
            range: range,
        }
        ,
        {
            label: 'Shadow Stack',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A shadow stack is a mechanism for protecting a procedure's stored return address, such as from a stack buffer overflow. The shadow stack itself is a second, separate stack that \"shadows\" the program call stack. In the function prologue, a function stores its return address to both the call stack and the shadow stack. In the function epilogue, a function loads the return address from both the call stack and the shadow stack, and then compares them. If the two records of the return address differ, then an attack is detected.",
            insertText: 'ShadowStack',
            range: range,
        }
        ,
        {
            label: 'User Behavior',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A user behavior is a pattern of user actions, or set of such patterns. Modeling and analyzing these patterns and monitoring a users actions for meaningful anomalies is known as user behavior analytics (UBA).",
            insertText: 'UserBehavior',
            range: range,
        }
        ,
        {
            label: 'Address Space',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An address space defines a range of discrete addresses, each of which may correspond to a network host, peripheral device, disk sector, a memory cell or other logical or physical entity. For software programs to save and retrieve stored data, each unit of data must have an address where it can be located. The number of address spaces available depends on the underlying address structure, which is usually limited by the computer architecture being used.",
            insertText: 'AddressSpace',
            range: range,
        }
        ,
        {
            label: 'Memory Address Space',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A memory address space is a space containing memory addresses.",
            insertText: 'MemoryAddressSpace',
            range: range,
        }
        ,
        {
            label: 'Virtual Memory Space',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Virtual memory is a memory management technique where secondary memory can be used as if it were a part of the main memory. Virtual memory uses hardware and software to enable a computer to compensate for physical memory shortages",
            insertText: 'VirtualMemorySpace',
            range: range,
        }
        ,
        {
            label: 'Binary Large Object',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A binary large object (BLOB) is a collection of binary data stored as a single entity. Blobs are typically images, audio or other multimedia objects, though sometimes binary executable code is stored as a blob.",
            insertText: 'BinaryLargeObject',
            range: range,
        }
        ,
        {
            label: 'JavaScript Blob',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A JavaScript Blob is a Blob that was created by a JavaScript Blob() constructor call or equivalent function.",
            insertText: 'JavaScriptBlob',
            range: range,
        }
        ,
        {
            label: 'Domain Registration',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A domain registration, or domain name registration data, is the relevant registration data from Internet resources such as domain names, IP addresses, and autonomous system numbers. Registration data is typically retrieved by means of either the Registration Data Access Protocol (RDAP) or its predecessor, the WHOIS protocol.",
            insertText: 'DomainRegistration',
            range: range,
        }
        ,
        {
            label: 'Intrusion Detection System',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An intrusion detection system (IDS) is a device or software application that monitors a network or systems for malicious activity or policy violations. Any intrusion activity or violation is typically reported either to an administrator or collected centrally using a security information and event management (SIEM) system. A SIEM system combines outputs from multiple sources and uses alarm filtering techniques to distinguish malicious activity from false alarms.",
            insertText: 'IntrusionDetectionSystem',
            range: range,
        }
        ,
        {
            label: 'Intrusion Prevention System',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Intrusion prevention systems (IPS), also known as intrusion detection and prevention systems (IDPS), are network security appliances that monitor network or system activities for malicious activity. The main functions of intrusion prevention systems are to identify malicious activity, log information about this activity, report it and attempt to block or stop it.\n\nIntrusion prevention systems are considered extensions of intrusion detection systems because they both monitor network traffic and/or system activities for malicious activity. The main differences are, unlike intrusion detection systems, intrusion prevention systems are placed in-line and are able to actively prevent or block intrusions that are detected. IPS can take such actions as sending an alarm, dropping detected malicious packets, resetting a connection or blocking traffic from the offending IP address. An IPS also can correct cyclic redundancy check (CRC) errors, defragment packet streams, mitigate TCP sequencing issues, and clean up unwanted transport and network layer options.",
            insertText: 'IntrusionPreventionSystem',
            range: range,
        }
        ,
        {
            label: 'Metadata',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Metadata is \"data [information] that provides information about other data\". Three distinct types of metadata exist: structural metadata, descriptive metadata, and administrative metadata. Structural metadata is data about the containers of data. For instance a \"book\" contains data, and data about the book is metadata about that container of data. Descriptive metadata uses individual instances of application data or the data content.",
            insertText: 'Metadata',
            range: range,
        }
        ,
        {
            label: 'File System Metadata',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Metadata about the files and directories in a file system.  For example file name, file length, time modified, group and user ids, and other file attributes.",
            insertText: 'FileSystemMetadata',
            range: range,
        }
        ,
        {
            label: 'Session',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computer science, in particular networking, a session is a semi-permanent interactive information interchange, also known as a dialogue, a conversation or a meeting, between two or more communicating devices, or between a computer and user (see Login session). A session is set up or established at a certain point in time, and then torn down at some later point. An established communication session may involve more than one message in each direction. A session is typically, but not always, stateful, meaning that at least one of the communicating parts needs to save information about the session history in order to be able to communicate, as opposed to stateless communication, where the communication consists of independent requests with responses.",
            insertText: 'Session',
            range: range,
        }
        ,
        {
            label: 'Login Session',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a login session is the period of activity between a user logging in and logging out of a (multi-user) system. On Unix and Unix-like operating systems, a login session takes one of two main forms: (a) When a textual user interface is used, a login session is represented as a kernel session -- a collection of process groups with the logout action managed by a session leader, and (b) Where an X display manager is employed, a login session is considered to be the lifetime of a designated user process that the display manager invokes.",
            insertText: 'LoginSession',
            range: range,
        }
        ,
        {
            label: 'Remote Session',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A remote login session is a login session where a client has logged in from their local host machine to a server via a network.",
            insertText: 'RemoteSession',
            range: range,
        }
        ,
        {
            label: 'RDP Session',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A Remote Desktop Protocol (RDP) session is a session established using the RDP protocol to access Remove Desktop Services (RDS).",
            insertText: 'RDPSession',
            range: range,
        }
        ,
        {
            label: 'SSH Session',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A Secure Shell Protocol (SSH) session is a session over a secure channel established using SSH to connect a client to a server and establish the remote session.",
            insertText: 'SSHSession',
            range: range,
        }
        ,
        {
            label: 'Trust Store',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Stores public information necessary to determine if another party can be trusted.",
            insertText: 'TrustStore',
            range: range,
        }
        ,
        {
            label: 'Certificate Trust Store',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A certificate truststore is used to store public certificates used to authenticate clients by the server for an SSL connection.",
            insertText: 'CertificateTrustStore',
            range: range,
        }
        ,
        {
            label: 'Binary Segment',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A binary segment is a partition of binary information within a larger binary object, which arranges a set of binary objects for its purpose.   For example, code, data, heap, and stack segments are segments of the binary information used by a process.  Code and data segments are also found in object files.",
            insertText: 'BinarySegment',
            range: range,
        }
        ,
        {
            label: 'Image Segment',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Image segments are distinct partitions of an object file.  Both data and code segments are examples of image segments.",
            insertText: 'ImageSegment',
            range: range,
        }
        ,
        {
            label: 'Image Data Segment',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An image data segment (often denoted .data) is a portion of an object file that contains initialized static variables, that is, global variables and static local variables. The size of this segment is determined by the size of the values in the program's source code, and does not change at run time. This segmenting of the memory space into discrete blocks with specific tasks carried over into the programming languages of the day and the concept is still widely in use within modern programming languages.",
            insertText: 'ImageDataSegment',
            range: range,
        }
        ,
        {
            label: 'Image Code Segment',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An image code segment, also known as a text segment or simply as text, is a portion of an object file that contains executable instructions. The term \"segment\" comes from the memory segment, which is a historical approach to memory management that has been succeeded by paging. When a program is stored in an object file, the code segment is a part of this file; when the loader places a program into memory so that it may be executed, various memory regions are allocated (in particular, as pages), corresponding to both the segments in the object files and to segments only needed at run time. For example, the code segment of an object file is loaded into a corresponding code segment in memory.",
            insertText: 'ImageCodeSegment',
            range: range,
        }
        ,
        {
            label: 'Process Segment',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Process segments are distinct partitions of the memory space of a running process.  Heap, data, code, and stack segments are examples of process segments.",
            insertText: 'ProcessSegment',
            range: range,
        }
        ,
        {
            label: 'Heap Segment',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The heap segment (or free store) is a large pool of memory from which dynamic memory requests of a process are allocated and satisfied.",
            insertText: 'HeapSegment',
            range: range,
        }
        ,
        {
            label: 'Process Data Segment',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A process data segment, is a portion of the program's virtual address space that contains executable instructions and corresponds to the loaded image data segment.",
            insertText: 'ProcessDataSegment',
            range: range,
        }
        ,
        {
            label: 'Stack Segment',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The stack segment contains the program stack, a last-in-first-out structure, typically allocated in the higher parts of memory for the process.",
            insertText: 'StackSegment',
            range: range,
        }
        ,
        {
            label: 'Process Code Segment',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A process code segment, also known as a text segment or simply as text, is a portion of the program's virtual address space that contains executable instructions and corresponds to the loaded image code segment. Includes additional sections such as an import table.",
            insertText: 'ProcessCodeSegment',
            range: range,
        }
        ,
        {
            label: 'Block Device',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A block device (or block special file) provides buffered access to hardware devices, and provides some abstraction from their specifics.\n\nIEEE Std 1003.1-2017: A file that refers to a device. A block special file is normally distinguished from a character special file by providing access to the device in a manner such that the hardware characteristics of the device are not visible.",
            insertText: 'BlockDevice',
            range: range,
        }
        ,
        {
            label: 'Call Stack',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computer science, a call stack is a stack data structure that stores information about the active subroutines of a computer program. This kind of stack is also known as an execution stack, program stack, control stack, run-time stack, or machine stack, and is often shortened to just \"the stack\". Although maintenance of the call stack is important for the proper functioning of most software, the details are normally hidden and automatic in high-level programming languages. Many computer instruction sets provide special instructions for manipulating stacks.",
            insertText: 'CallStack',
            range: range,
        }
        ,
        {
            label: 'Clipboard',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The clipboard is a buffer that some operating systems provide for short-term storage and transfer within and between application programs. The clipboard is usually temporary and unnamed, and its contents reside in the computer's RAM. The clipboard is sometimes called the paste buffer. Windows, Linux and macOS support a single clipboard transaction. Each cut or copy overwrites the previous contents. Normally, paste operations copy the contents, leaving the contents available in the clipboard for further pasting.",
            insertText: 'Clipboard',
            range: range,
        }
        ,
        {
            label: 'Cryptographic Key',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In cryptography, a key is a piece of information (a parameter) that determines the functional output of a cryptographic algorithm. For encryption algorithms, a key specifies the transformation of plaintext into ciphertext, and vice versa for decryption algorithms. Keys also specify transformations in other cryptographic algorithms, such as digital signature schemes and message authentication codes.",
            insertText: 'CryptographicKey',
            range: range,
        }
        ,
        {
            label: 'Symmetric Key',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A symmetric key is a single key used for both encryption and decryption and used with a symmetric-key algorithm. Symmetric-key algorithms are algorithms for cryptography that use the same cryptographic keys for both encryption of plaintext and decryption of ciphertext. The keys may be identical or there may be a simple transformation to go between the two keys. The keys, in practice, represent a shared secret between two or more parties that can be used to maintain a private information link. This requirement that both parties have access to the secret key is one of the main drawbacks of symmetric key encryption, in comparison to public-key encrytption (also known as asymmetric key encryption).",
            insertText: 'SymmetricKey',
            range: range,
        }
        ,
        {
            label: 'Asymmetric Key',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Asymmetric keys are public and private keys, paired such that asymmetric (public-key) cryptography algorithms can be implemented using them. Public-key cryptography, or asymmetric cryptography, is any cryptographic system that uses pairs of keys: public keys that may be disseminated widely paired with private keys which are known only to the owner. There are two functions that can be achieved: using a public key to authenticate that a message originated with a holder of the paired private key; or encrypting a message with a public key to ensure that only the holder of the paired private key can decrypt it.",
            insertText: 'AsymmetricKey',
            range: range,
        }
        ,
        {
            label: 'Private Key',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A private key can be used to decrypt messages encrypted using the corresponding public key, or used to sign a message that can be authenticated with the corresponding public key.",
            insertText: 'PrivateKey',
            range: range,
        }
        ,
        {
            label: 'Public Key',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A public key can be disseminated widely as part of an asymmetric cryptography framework and be used to encrypt messages to send to the public key's owner or to authenticate signed messages from that sender.",
            insertText: 'PublicKey',
            range: range,
        }
        ,
        {
            label: 'Display Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A display server or window server is a program whose primary task is to coordinate the input and output of its clients to and from the rest of the operating system, the hardware, and each other. The display server communicates with its clients over the display server protocol, a communications protocol, which can be network-transparent or simply network-capable. The display server is a key component in any graphical user interface, specifically the windowing system.",
            insertText: 'DisplayServer',
            range: range,
        }
        ,
        {
            label: 'File System',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a file system or filesystem is used to control how data is stored and retrieved. Without a file system, information placed in a storage medium would be one large body of data with no way to tell where one piece of information stops and the next begins. By separating the data into pieces and giving each piece a name, the information is easily isolated and identified. Taking its name from the way paper-based information systems are named, each group of data is called a \"file\". The structure and logic rules used to manage the groups of information and their names is called a \"file system\".",
            insertText: 'FileSystem',
            range: range,
        }
        ,
        {
            label: 'Physical Link',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A physical link is a dedicated connection for communication that uses some physical media (electrical, electromagnetic, optical, to include clear spaces or vacuums.)  A physical link represents only a single hop (link) in any larger communcations path, circuit, or network.\n\nNOTE: not synonymous with data link as a data link can be over a telecommunications circuit, which may be a virtual circuit composed of multiple phyical links.",
            insertText: 'PhysicalLink',
            range: range,
        }
        ,
        {
            label: 'Data Link Link',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A communication link between two network devices connected directly at the physical layer and on the same network segment; i.e., an OSI Layer 2 link.",
            insertText: 'DataLinkLink',
            range: range,
        }
        ,
        {
            label: 'Network Link',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A network link is a link within the network layer, which is responsible for packet forwarding including routing through intermediate routers.",
            insertText: 'NetworkLink',
            range: range,
        }
        ,
        {
            label: 'Network Flow',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A summarization of network transactions between a client and server. It often summarizes bytes sent, bytes received, and protocol flags.",
            insertText: 'NetworkFlow',
            range: range,
        }
        ,
        {
            label: 'Page Table',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A page table  is the data structure used by the MMU in a virtual memory computer system  to store the mapping between virtual addresses (virtual pages) and physical addresses (page frames).",
            insertText: 'PageTable',
            range: range,
        }
        ,
        {
            label: 'Process Tree',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A process tree is a tree structure representation of parent-child relationships established via process spawn operations.",
            insertText: 'ProcessTree',
            range: range,
        }
        ,
        {
            label: 'User Interface',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The user interface (UI), in the industrial design field of human-machine interaction, is the space where interactions between humans and machines occur. The goal of this interaction is to allow effective operation and control of the machine from the human end, whilst the machine simultaneously feeds back information that aids the operators' decision-making process. Examples of this broad concept of user interfaces include the interactive aspects of computer operating systems, hand tools, heavy machinery operator controls, and process controls. The design considerations applicable when creating user interfaces are related to or involve such disciplines as ergonomics and psychology.",
            insertText: 'UserInterface',
            range: range,
        }
        ,
        {
            label: 'Command Line Interface',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A command-line interface or command language interpreter (CLI), also known as command-line user interface, console user interface, and character user interface (CUI), is a means of interacting with a computer program where the user (or client) issues commands to the program in the form of successive lines of text (command lines). Command-line interfaces to computer operating systems are less widely used by casual computer users, who favor graphical user interfaces. Programs with command-line interfaces are generally easier to automate via scripting.",
            insertText: 'CommandLineInterface',
            range: range,
        }
        ,
        {
            label: 'Graphical User Interface',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A graphical user interface (GUI)  is a type of user interface that allows users to interact with electronic devices through graphical icons and visual indicators such as secondary notation, instead of text-based user interfaces, typed command labels or text navigation. GUIs were introduced in reaction to the perceived steep learning curve of command-line interfaces (CLIs), which require commands to be typed on a computer keyboard.",
            insertText: 'GraphicalUserInterface',
            range: range,
        }
        ,
        {
            label: 'Digital System',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A digital system is a group of interacting or interrelated digital artifacts that act according to a set of rules to form a unified whole. A digital system, surrounded and influenced by its environment, is described by its boundaries, structure and purpose and expressed in its functioning. Systems are the subjects of study of systems theory.",
            insertText: 'DigitalSystem',
            range: range,
        }
        ,
        {
            label: 'Legacy System',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a legacy system is an old method, technology, computer system, or application program, \"of, relating to, or being a previous or outdated computer system,\" yet still in use. Often referencing a system as \"legacy\" means that it paved the way for the standards that would follow it. This can also imply that the system is out of date or in need of replacement.",
            insertText: 'LegacySystem',
            range: range,
        }
        ,
        {
            label: 'Interprocess Communication',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computer science, inter-process communication or inter-process communication (IPC) refers specifically to the mechanisms an operating system provides to allow processes it manages to share data. Typically, applications can use IPC categorized as clients and servers, where the client requests data and the server responds to client requests. Many applications are both clients and servers, as commonly seen in distributed computing. Methods for achieving IPC are divided into categories which vary based on software requirements, such as performance and modularity requirements, and system circumstances, such as network bandwidth and latency.",
            insertText: 'InterprocessCommunication',
            range: range,
        }
        ,
        {
            label: 'Pipe',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In Unix-like computer operating systems, a pipeline is a mechanism for inter-process communication using message passing.  In the strictest sense, a pipe is a single segment of a pipeline, allowing one process to pass information forward to another.  Network pipes allow processes on different hosts to interact.",
            insertText: 'Pipe',
            range: range,
        }
        ,
        {
            label: 'Memory Pool',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Memory pools, also called fixed-size blocks allocation, is the use of pools for memory management\u2026 preallocating a number of memory blocks with the same size called the memory pool. The application can allocate, access, and free blocks represented by handles at run time.",
            insertText: 'MemoryPool',
            range: range,
        }
        ,
        {
            label: 'Memory Word',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A memory word is the natural unit of data used by a particular computer processor design; a fixed-size piece of data handled as a unit by the instruction set or the hardware of the processor.",
            insertText: 'MemoryWord',
            range: range,
        }
        ,
        {
            label: 'Memory Block',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing (specifically data transmission and data storage), a block, sometimes called a physical record, is a sequence of bytes or bits, usually containing some whole number of records, having a maximum length; a block size. Data thus structured are said to be blocked. The process of putting data into blocks is called blocking, while deblocking is the process of extracting data from blocks. Blocked data is normally stored in a data buffer and read or written a whole block at a time.",
            insertText: 'MemoryBlock',
            range: range,
        }
        ,
        {
            label: 'Page',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A\u00a0page,\u00a0memory page, logical page, or\u00a0virtual page\u00a0is a fixed-length contiguous block of\u00a0virtual memory, described by a single entry in the\u00a0page table. It is the smallest unit of data for memory management in a virtual memory\u00a0operating system.",
            insertText: 'Page',
            range: range,
        }
        ,
        {
            label: 'Tertiary Storage',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Tertiary storage or tertiary memory is memory primarily used for archiving rarely accessed information. It is primarily useful for extraordinarily large data stores. Typical examples include tape libraries and optical jukeboxes.",
            insertText: 'TertiaryStorage',
            range: range,
        }
        ,
        {
            label: 'Page Frame',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A page frame is the smallest fixed-length contiguous block of physical memory into which memory pages are mapped by the operating system.",
            insertText: 'PageFrame',
            range: range,
        }
        ,
        {
            label: 'Cloud Service Sensor',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Senses data from cloud service platforms. Including data from cloud service  authentications, authorizations, and other activities.",
            insertText: 'CloudServiceSensor',
            range: range,
        }
        ,
        {
            label: 'Network Flow Sensor',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Monitors network traffic and produces summaries of data flows traversing the network.",
            insertText: 'NetworkFlowSensor',
            range: range,
        }
        ,
        {
            label: 'Network Protocol Analyzer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Monitors and parses network protocols to extract values from various network protocol layers.",
            insertText: 'NetworkProtocolAnalyzer',
            range: range,
        }
        ,
        {
            label: 'Endpoint Sensor',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A sensor application installed on a endpoint (platform) to collect information on platform components.",
            insertText: 'EndpointSensor',
            range: range,
        }
        ,
        {
            label: 'Application Inventory Sensor',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Collects information on applications on an endpoint.",
            insertText: 'ApplicationInventorySensor',
            range: range,
        }
        ,
        {
            label: 'File System Sensor',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Collects files and file metadata on an endpoint.",
            insertText: 'FileSystemSensor',
            range: range,
        }
        ,
        {
            label: 'Firmware Sensor',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Collects information on firmware installed on an Endpoint.",
            insertText: 'FirmwareSensor',
            range: range,
        }
        ,
        {
            label: 'Host Configuration Sensor',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Collects the configuration data on an endpoint.",
            insertText: 'HostConfigurationSensor',
            range: range,
        }
        ,
        {
            label: 'Kernel API Sensor',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Monitors system calls (operating system api functions).",
            insertText: 'KernelAPISensor',
            range: range,
        }
        ,
        {
            label: 'Java Archive',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A JAR (Java ARchive) is a package file format typically used to aggregate many Java class files and associated metadata and resources (text, images, etc.) into one file for distribution.",
            insertText: 'JavaArchive',
            range: range,
        }
        ,
        {
            label: 'Python Package',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A Python package is an aggregation of many Python files - either in source code or in bytecode - and associated metadata and resources (text, images, etc.). Python packages can be distributed in different file formats.",
            insertText: 'PythonPackage',
            range: range,
        }
        ,
        {
            label: 'Container Image',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A container is a standard unit of software that packages up code and all its dependencies so the application runs quickly and reliably from one computing environment to another. A Docker container image is a lightweight, standalone, executable package of software that includes everything needed to run an application: code, runtime, system tools, system libraries and settings.\n\nContainer images become containers at runtime and in the case of Docker containers - images become containers when they run on Docker Engine. Available for both Linux and Windows-based applications, containerized software will always run the same, regardless of the infrastructure. Containers isolate software from its environment and ensure that it works uniformly despite differences for instance between development and staging.",
            insertText: 'ContainerImage',
            range: range,
        }
        ,
        {
            label: 'Stack Component',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A stack component is any component of a call stack used for stack-based memory allocation in a running process.  Examples include saved instruction pointers, stack frames, and stack frame canaries.",
            insertText: 'StackComponent',
            range: range,
        }
        ,
        {
            label: 'Saved Instruction Pointer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A saved instruction pointer points to the instruction that generated an exception (trap or fault).",
            insertText: 'SavedInstructionPointer',
            range: range,
        }
        ,
        {
            label: 'Stack Frame Canary',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Stack canaries, named for their analogy to a canary in a coal mine, are used to detect a stack buffer overflow before execution of malicious code can occur. This method works by placing a small integer, the value of which is randomly chosen at program start, in memory just before the stack return pointer. Most buffer overflows overwrite memory from lower to higher memory addresses, so in order to overwrite the return pointer (and thus take control of the process) the canary value must also be overwritten. This value is checked to make sure it has not changed before a routine uses the return pointer on the stack. This technique can greatly increase the difficulty of exploiting a stack buffer overflow because it forces the attacker to gain control of the instruction pointer by some non-traditional means such as corrupting other important variables on the stack.",
            insertText: 'StackFrameCanary',
            range: range,
        }
        ,
        {
            label: 'Stack Frame',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A machine-dependent and application-binary-dependent (ABI-dependent) data structure containing subroutine state information including the arguments passed into the routine, the return address back to the routine's caller, and space for local variables of the routine.",
            insertText: 'StackFrame',
            range: range,
        }
        ,
        {
            label: 'Certificate',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In cryptography, a public key certificate, also known as a digital certificate or identity certificate, is an electronic document used to prove the ownership of a public key. The certificate includes information about the key, information about the identity of its owner (called the subject), and the digital signature of an entity that has verified the certificate's contents (called the issuer). If the signature is valid, and the software examining the certificate trusts the issuer, then it can use that key to communicate securely with the certificate's subject. In email encryption, code signing, and e-signature systems, a certificate's subject is typically a person or organization. However, in Transport Layer Security (TLS) a certificate's subject is typically a computer or other device.",
            insertText: 'Certificate',
            range: range,
        }
        ,
        {
            label: 'Decoy Artifact',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A decoy is an imitation digital artifact in any sense of a digital artifact, object, or phenomenon that is intended to deceive a cyber attacker's surveillance devices or mislead their evaluation.  Examples include fake files, accounts, hosts (honeypots), and network segments (honeynets).",
            insertText: 'DecoyArtifact',
            range: range,
        }
        ,
        {
            label: 'File Section',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A file section is one of the portions of a file in which the file is regarded as divided and where together the file sections constitute the whole file.",
            insertText: 'FileSection',
            range: range,
        }
        ,
        {
            label: 'Resource Fork',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The resource fork is a fork or section of a file on Apple's classic Mac OS operating system, which was also carried over to the modern macOS for compatibility, used to store structured data along with the unstructured data stored within the data fork.",
            insertText: 'ResourceFork',
            range: range,
        }
        ,
        {
            label: 'Kernel Process Table',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A data structure in the kernel which is a table containing all of the information that must be saved when the CPU switches from running one process to another in a multitasking system. It allows the operating system to track all the process's execution status, and contains the For every process managed by the kernel, there is a process control block (PCB) in the process table.",
            insertText: 'KernelProcessTable',
            range: range,
        }
        ,
        {
            label: 'Memory Address',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a memory address is a reference to a specific memory location used at various levels by software and hardware.",
            insertText: 'MemoryAddress',
            range: range,
        }
        ,
        {
            label: 'Physical Address',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In a computer supporting virtual memory, the term\u00a0physical address\u00a0is used mostly to differentiate from a\u00a0virtual address. In particular, in computers utilizing a\u00a0memory management unit(MMU) to translate memory addresses, the virtual and physical addresses refer to an address before and after translation performed by the MMU, respectively.",
            insertText: 'PhysicalAddress',
            range: range,
        }
        ,
        {
            label: 'Virtual Address',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A virtual address in memory is a pointer or marker for a memory space that an operating system allows a process to use. The virtual address points to a location in primary storage that a process can use independently of other processes.",
            insertText: 'VirtualAddress',
            range: range,
        }
        ,
        {
            label: 'Process Image',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A process image is a copy of a given process's state at a given point in time. It is often used to create persistence within an otherwise volatile system.",
            insertText: 'ProcessImage',
            range: range,
        }
        ,
        {
            label: 'User to User Message',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Personal message, private message (PM), direct message (DM), or personal chat (PC) is a private form of messaging between different members on a given platform. It is only seen and accessible by the users participating in the message.",
            insertText: 'UserToUserMessage',
            range: range,
        }
        ,
        {
            label: 'Hardware Driver',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a device driver (commonly referred to simply as a driver) is a computer program that operates or controls a particular type of device that is attached to a computer. A driver provides a software interface to hardware devices, enabling operating systems and other computer programs to access hardware functions without needing to know precise details of the hardware being used. A driver communicates with the device through the computer bus or communications subsystem to which the hardware connects. When a calling program invokes a routine in the driver, the driver issues commands to the device. Once the device sends data back to the driver, the driver may invoke routines in the original calling program. Drivers are hardware dependent and operating-system-specific. They usually provide the interrupt handling required for any necessary asynchronous time-dependent hardware interface.",
            insertText: 'HardwareDriver',
            range: range,
        }
        ,
        {
            label: 'Display Device Driver',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A device driver for a display adapter.",
            insertText: 'DisplayDeviceDriver',
            range: range,
        }
        ,
        {
            label: 'Physical Location',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The terms location  [here, a physical location] and place in geography are used to identify a point or an area on the Earth's surface or elsewhere. The term location generally implies a higher degree of certainty than place, which often indicates an entity with an ambiguous boundary, relying more on human or social attributes of place identity and sense of place than on geometry. The distinction between space and place is considered a central concern of geography, and has been addressed by scholars such as Yi-Fu Tuan and John Agnew.",
            insertText: 'PhysicalLocation',
            range: range,
        }
        ,
        {
            label: 'User Action',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An action performed by a user. Executing commands, granting permissions, and accessing resources are examples of user actions.",
            insertText: 'UserAction',
            range: range,
        }
        ,
        {
            label: 'Resource Access',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Ephemeral digital artifact comprising a request of a resource and any response from that resource.",
            insertText: 'ResourceAccess',
            range: range,
        }
        ,
        {
            label: 'Local Resource Access',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Ephemeral digital artifact comprising a request of a local resource and any response from that resource.",
            insertText: 'LocalResourceAccess',
            range: range,
        }
        ,
        {
            label: 'Network Resource Access',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Ephemeral digital artifact comprising a request of a network resource and any response from that network resource.",
            insertText: 'NetworkResourceAccess',
            range: range,
        }
        ,
        {
            label: 'Web Resource Access',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Ephemeral digital artifact comprising a request of a network resource and any response from that network resource using a standard web protocol.",
            insertText: 'WebResourceAccess',
            range: range,
        }
        ,
        {
            label: 'Authorization',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Authorization is the function of specifying access rights to resources related to information security and computer security in general and to access control in particular. More formally, \"to authorize\" is to define an access policy. For example, human resources staff is normally authorized to access employee records and this policy is usually formalized as access control rules in a computer system. During operation, the system uses the access control rules to decide whether access requests from (authenticated) consumers shall be approved (granted) or disapproved (rejected). Resources include individual files or an item's data, computer programs, computer devices and functionality provided by computer applications. Examples of consumers are computer users, computer program",
            insertText: 'Authorization',
            range: range,
        }
        ,
        {
            label: 'Cloud Service Authorization',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Cloud authorization is the function of specifying access rights to cloud resources.",
            insertText: 'CloudServiceAuthorization',
            range: range,
        }
        ,
        {
            label: 'Authentication',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A request-response comprising a user credential presentation to a system and a verification response.",
            insertText: 'Authentication',
            range: range,
        }
        ,
        {
            label: 'Web Authentication',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A request-response comprising a user credential presentation to a system and a verification response where the verifying party is a web server.",
            insertText: 'WebAuthentication',
            range: range,
        }
        ,
        {
            label: 'Cloud Service Authentication',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A request-response comprising a user credential presentation to a system and a verification response where the verifying party is a cloud service.",
            insertText: 'CloudServiceAuthentication',
            range: range,
        }
        ,
        {
            label: 'Boot Loader',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A bootloader is software that is responsible for booting a computer. When a computer is turned off, its software\u200d-\u200cincluding operating systems, application code, and data\u200d-\u200cremains stored on non-volatile memory. When the computer is powered on, it typically does not have an operating system or its loader in random-access memory (RAM). The computer first executes a relatively small program stored in read-only memory (ROM, and later EEPROM, NOR flash) along with some needed data, to initialize RAM (especially on x86 systems) to access the nonvolatile device (usually block device, eg NAND flash) or devices from which the operating system programs and data can be loaded into RAM.",
            insertText: 'BootLoader',
            range: range,
        }
        ,
        {
            label: 'First-stage Boot Loader',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The very first routine run in order to load the operating system.",
            insertText: 'First-stageBootLoader',
            range: range,
        }
        ,
        {
            label: 'Second-stage Boot Loader',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An optional, often feature rich,  second stage set of routines run in order to load the operating system.",
            insertText: 'Second-stageBootLoader',
            range: range,
        }
        ,
        {
            label: 'Command',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a command is a directive to a computer program acting as an interpreter of some kind, in order to perform a specific task. Most commonly a command is either a directive to some kind of command-line interface, such as a shell, or an event in a graphical user interface triggered by the user selecting an option in a menu.",
            insertText: 'Command',
            range: range,
        }
        ,
        {
            label: 'Remote Command',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A remote command is a command sent from one computer to another to be executed on the remote computer.  One example of this, is through a command-line interface (CLI) like using Invoke-Command from PowerShell or a command sent through an ssh session. This class generalizes to all means of sending a command through an established protocol to control capabilities on a remote computer.",
            insertText: 'RemoteCommand',
            range: range,
        }
        ,
        {
            label: 'Remote Database Query',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A remote query session enabling a user to make an SQL, SPARQL, or similar query over the network from one host to another.",
            insertText: 'RemoteDatabaseQuery',
            range: range,
        }
        ,
        {
            label: 'Remote Procedure Call',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In distributed computing a remote procedure call (RPC) is when a computer program causes a procedure (subroutine) to execute in another address space (commonly on another computer on a shared network), which is coded as if it were a normal (local) procedure call, without the programmer explicitly coding the details for the remote interaction. That is, the programmer writes essentially the same code whether the subroutine is local to the executing program, or remote. This is a form of client-server interaction (caller is client, executor is server), typically implemented via a request-response message-passing system. The object-oriented programming analog is remote method invocation (RMI). The RPC model implies a level of location transparency.",
            insertText: 'RemoteProcedureCall',
            range: range,
        }
        ,
        {
            label: 'Database Query',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A specific query expressed in SQL, SPARQL, or similar language against a database.",
            insertText: 'DatabaseQuery',
            range: range,
        }
        ,
        {
            label: 'File System Link',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A file system link associates a name with a file on a file system.  Most generally, this may be a direct reference (a hard link) or an indirect one (a soft link).",
            insertText: 'FileSystemLink',
            range: range,
        }
        ,
        {
            label: 'Hard Link',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a hard link is a directory entry that associates a name with a file on a file system. All directory-based file systems must have at least one hard link giving the original name for each file. The term \"hard link\" is usually only used in file systems that allow more than one hard link for the same file. Multiple hard links -- that is, multiple directory entries to the same file -- are supported by POSIX-compliant and partially POSIX-compliant operating systems, such as Linux, Android, macOS, and also Windows NT4 and later Windows NT operating systems.",
            insertText: 'HardLink',
            range: range,
        }
        ,
        {
            label: 'NTFS Hard Link',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An NTFS hard link points to another file, and files share the same MFT entry (inode), in the same filesystem.",
            insertText: 'NTFSHardLink',
            range: range,
        }
        ,
        {
            label: 'Unix Hard Link',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A Unix hard link is a hard link on a Unix file system.",
            insertText: 'UnixHardLink',
            range: range,
        }
        ,
        {
            label: 'NTFS Link',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The NTFS filesystem defines various ways to link files, i.e. to make a file point to another file or its contents. The object being pointed to is called the target. There are three classes of NTFS links: (a) Hard links, which have files share the same MFT entry (inode), in the same filesystem; (b) Symbolic links, which record the path of another file that the links contents should show and can accept relative paths; and (c) Junction points, which are similar to symlinks but defined only for directories and only accepts local absolute paths",
            insertText: 'NTFSLink',
            range: range,
        }
        ,
        {
            label: 'NTFS Junction Point',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "NTFS junction points are are similar to NTFS symlinks but are defined only for directories. Only accepts local absolute paths.",
            insertText: 'NTFSJunctionPoint',
            range: range,
        }
        ,
        {
            label: 'NTFS Symbolic Link',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An NTFS symbolic link records the path of another file that the links contents should show. Can accept relative paths. SMB networking (UNC path) and directory support added in NTFS 3.1.",
            insertText: 'NTFSSymbolicLink',
            range: range,
        }
        ,
        {
            label: 'Unix Link',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A Unix link is a file link in a Unix file system.",
            insertText: 'UnixLink',
            range: range,
        }
        ,
        {
            label: 'Fast Symbolic Link',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Fast symbolic links, allow storage of the target path within the data structures used for storing file information on disk (e.g., within the inodes). This space normally stores a list of disk block addresses allocated to a file. Thus, symlinks with short target paths are accessed quickly. Systems with fast symlinks often fall back to using the original method if the target path exceeds the available inode space.",
            insertText: 'FastSymbolicLink',
            range: range,
        }
        ,
        {
            label: 'POSIX Symbolic Link',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A POSIX-compliant symbolic link.  These are often fast symbolic links, but need not be.",
            insertText: 'POSIXSymbolicLink',
            range: range,
        }
        ,
        {
            label: 'Slow Symbolic Link',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A slow symbolic link is any symbolic link on a Unix filesystem that is not a fast symbolic link; slow symlink is thus retroactively termed from fast symlink.  Slow symbolic links stored the symbolic link information as data in regular files.",
            insertText: 'SlowSymbolicLink',
            range: range,
        }
        ,
        {
            label: 'Alias',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In macOS, an alias is a small file that represents another object in a local, remote, or removable[1] file system and provides a dynamic link to it; the target object may be moved or renamed, and the alias will still link to it (unless the original file is recreated; such an alias is ambiguous and how it is resolved depends on the version of macOS).",
            insertText: 'Alias',
            range: range,
        }
        ,
        {
            label: 'Symbolic Link',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A symbolic link (also symlink or soft link) is a term for any file that contains a reference to another file or directory in the form of an absolute or relative path and that affects pathname resolution.",
            insertText: 'SymbolicLink',
            range: range,
        }
        ,
        {
            label: 'Partition',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A partition is a region on secondary storage device created so that the region can be managed by itself; separate from any other regions (partitions) on that secondary storage device. Creating partitions is typically the first step of preparing a newly installed storage device, before any file system is created. The device stores the information about the partitions' locations and sizes in an area known as the partition table that the operating system reads before any other part of the disk. Each partition then appears to the operating system as a distinct \"logical\" storage device that uses part of the actual device. System administrators use a program called a partition editor to create, resize, delete, and manipulate the partitions. Partitioning allows the use of different filesystems to be installed for different kinds of files. Separating user data from system data can prevent the system partition from becoming full and rendering the system unusable. Partitioning can also make backing up easier. [Definition adapted as generalization from definition of disk partitioning and distinct from in-memory partitions.]",
            insertText: 'Partition',
            range: range,
        }
        ,
        {
            label: 'Partition Table',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A partition is a fixed-size subset of a storage device which is treated as a unit by the operating system. A partition table is a table maintained on the storage device by the operating system describing the partitions on that device. The terms partition table and partition map are most commonly associated with the MBR partition table of a Master Boot Record (MBR) in IBM PC compatibles, but it may be used generically to refer to other \"formats\" that divide a disk drive into partitions, such as: GUID Partition Table (GPT), Apple partition map (APM), or BSD disklabel.",
            insertText: 'PartitionTable',
            range: range,
        }
        ,
        {
            label: 'Record',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computer science, a record (also called struct or compound data) is a basic data structure. A record is a collection of fields, possibly of different data types, typically in fixed number and sequence . The fields of a record may also be called members, particularly in object-oriented programming. Fields may also be called elements, though these risk confusion with the elements of a collection. A tuple may or may not be considered a record, and vice versa, depending on conventions and the specific programming language.",
            insertText: 'Record',
            range: range,
        }
        ,
        {
            label: 'DNS Record',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A Domain Name System (DNS) record is a record of information returned to clients seeking to find computers, services, and other resources connected to the Internet or a private network.  Record information is stored on a domain name server so it can respond to DNS queries from clients.There are a variety of record types, depending on the client's information needs. Common types include Start of Authority, IP addresses, SMTP mail exchangers, name servers, reverse DNS lookup pointers, etc.",
            insertText: 'DNSRecord',
            range: range,
        }
        ,
        {
            label: 'System Utilization Record',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A system utilization record is a record for the tracking of resource utilization e.g. CPU, Disk, Network, Memory Bandwidth, GPU, or other resources for a given time period.",
            insertText: 'SystemUtilizationRecord',
            range: range,
        }
        ,
        {
            label: 'Boot Record',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A d3f:Record which is an essential component of the early boot (system initialization) process.",
            insertText: 'BootRecord',
            range: range,
        }
        ,
        {
            label: 'Volume Boot Record',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A volume boot record (VBR) (also known as a volume boot sector, a partition boot record or a partition boot sector) is a type of boot sector introduced by the IBM Personal Computer. It may be found on a partitioned data storage device, such as a hard disk, or an unpartitioned device, such as a floppy disk, and contains machine code for bootstrapping programs (usually, but not necessarily, operating systems) stored in other parts of the device. On non-partitioned storage devices, it is the first sector of the device. On partitioned devices, it is the first sector of an individual partition on the device, with the first sector of the entire device being a Master Boot Record (MBR) containing the partition table.",
            insertText: 'VolumeBootRecord',
            range: range,
        }
        ,
        {
            label: 'Boot Sector',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A boot record [boot sector] is the sector of a persistent data storage device (e.g., hard disk, floppy disk, optical disc, etc.) which contains machine code to be loaded into random-access memory (RAM) and then executed by a computer system's built-in firmware (e.g., the BIOS, Das U-Boot, etc.).",
            insertText: 'BootSector',
            range: range,
        }
        ,
        {
            label: 'Application Configuration Database Record',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A database record holding information used to configure the parameters and initial settings for an application.",
            insertText: 'ApplicationConfigurationDatabaseRecord',
            range: range,
        }
        ,
        {
            label: 'System Configuration Database Record',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A database record holding information used to configure the services, parameters, and initial settings for an operating system.",
            insertText: 'SystemConfigurationDatabaseRecord',
            range: range,
        }
        ,
        {
            label: 'Windows Registry Value',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A Windows Registry Value is a data structure consisting of a name, type, data (as a pointer), and the length. Windows Registry Values are always associated with a Windows Registry Key. They store the actual configuration data for the operating system and the programs that run on the system.",
            insertText: 'WindowsRegistryValue',
            range: range,
        }
        ,
        {
            label: 'System Configuration Init Database Record',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A database record holding information used to configure the services, parameters, and initial settings for an operating system at startup.",
            insertText: 'SystemConfigurationInitDatabaseRecord',
            range: range,
        }
        ,
        {
            label: 'Windows Registry Key',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Windows Registry Keys are container objects similar to folders that contain subkeys and/or data entries called values. A key can be a 'Registry Hive' when it is root key of a logical group of keys, subkeys, and values that has a set of supporting files loaded into memory when the operating system is started or a user logs in.",
            insertText: 'WindowsRegistryKey',
            range: range,
        }
        ,
        {
            label: 'User',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A user is a person [or agent] who uses a computer or network service. Users generally use a system or a software product without the technical expertise required to fully understand it. Power users use advanced features of programs, though they are not necessarily capable of computer programming and system administration. A user often has a user account and is identified to the system by a username (or user name). Other terms for username include login name, screenname (or screen name), nickname (or nick) and handle, which is derived from the identical Citizen's Band radio term. Some software products provide services to other systems and have no direct end users.",
            insertText: 'User',
            range: range,
        }
        ,
        {
            label: 'Volume',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In the context of computer operating systems, a volume or logical drive is a single accessible storage area with a single file system, typically (though not necessarily) resident on a single partition of a hard disk. Although a volume might be different from a physical disk drive, it can still be accessed with an operating system's logical interface. However, a volume differs from a partition.",
            insertText: 'Volume',
            range: range,
        }
        ,
        {
            label: 'DNS Lookup',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A Domain Name System (DNS) lookup is a record returned from a DNS resolver after querying a DNS name server.  Typically considered an A or AAAA record, where a domain name is resolved to an IPv4 or IPv6 address, respectively.",
            insertText: 'DNSLookup',
            range: range,
        }
        ,
        {
            label: 'Internet DNS Lookup',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An internet Domain Name System (DNS) lookup is a DNS lookup made from a host on a network that is resolved after querying a DNS name server hosted on a different network.",
            insertText: 'InternetDNSLookup',
            range: range,
        }
        ,
        {
            label: 'Intranet DNS Lookup',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An Intranet Domain Name System (DNS) lookup is a DNS lookup made from a host on a network that is resolved after querying a DNS name server hosted on a that same network.",
            insertText: 'IntranetDNSLookup',
            range: range,
        }
        ,
        {
            label: 'Dependency',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A dependency is the relationship of relying on or being controlled by someone or something else.  This class reifies dependencies that correspond to the object property depends-on.",
            insertText: 'Dependency',
            range: range,
        }
        ,
        {
            label: 'Activity Dependency',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An activity dependency is a dependency that indicates an activity has an activity or agent which relies on it in order to be functional.",
            insertText: 'ActivityDependency',
            range: range,
        }
        ,
        {
            label: 'Service Dependency',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A service dependency indicates a service has an activity, agent, or another service which relies on it in order to be functional.",
            insertText: 'ServiceDependency',
            range: range,
        }
        ,
        {
            label: 'System Dependency',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A system dependency indicates a system has an activity, agent, or another system which relies on it in order to be functional.",
            insertText: 'SystemDependency',
            range: range,
        }
        ,
        {
            label: 'Log',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A record of events in the order of their occurrence.",
            insertText: 'Log',
            range: range,
        }
        ,
        {
            label: 'Authorization Log',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A log of authorization events.",
            insertText: 'AuthorizationLog',
            range: range,
        }
        ,
        {
            label: 'Packet Log',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A log of all the network packet data captured from a network by a network sensor (i.e., packet analyzer),",
            insertText: 'PacketLog',
            range: range,
        }
        ,
        {
            label: 'Authentication Log',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A log of authentication events.",
            insertText: 'AuthenticationLog',
            range: range,
        }
        ,
        {
            label: 'Event Log',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Event logs record events taking place in the execution of a system in order to provide an audit trail that can be used to understand the activity of the system and to diagnose problems. They are essential to understand the activities of complex systems, particularly in the case of applications with little user interaction (such as server applications).",
            insertText: 'EventLog',
            range: range,
        }
        ,
        {
            label: 'Command History Log',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A log of commands run in an operating system shell.",
            insertText: 'CommandHistoryLog',
            range: range,
        }
        ,
        {
            label: 'Network',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A network is a group of computers that use a set of common communication protocols over digital interconnections for the purpose of sharing resources located on or provided by the network nodes. The interconnections between nodes are formed from a broad spectrum of telecommunication network technologies, based on physically wired, optical, and wireless radio-frequency methods that may be arranged in a variety of network topologies.",
            insertText: 'Network',
            range: range,
        }
        ,
        {
            label: 'Internet Network',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A network of multiple, connected networks. Internetworking is the practice of connecting a computer network with other networks through the use of gateways that provide a common method of routing information packets between the networks. The resulting system of interconnected networks are called an internetwork, or simply an internet. Internetworking is a combination of the words inter (\"between\") and networking; not internet-working or international-network.",
            insertText: 'InternetNetwork',
            range: range,
        }
        ,
        {
            label: 'Wide Area Network',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "By contrast to a local area network (LAN), a wide area network (WAN), not only covers a larger geographic distance, but also generally involves leased telecommunication circuits or Internet links.",
            insertText: 'WideAreaNetwork',
            range: range,
        }
        ,
        {
            label: 'Local Area Network',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A local area network (LAN) is a computer network that interconnects computers within a limited area such as a residence, school, laboratory, university campus or office building and has its network equipment and interconnects locally managed. Ethernet and Wi-Fi are the two most common transmission technologies in use for local area networks. Historical technologies include ARCNET, Token ring, and AppleTalk.",
            insertText: 'LocalAreaNetwork',
            range: range,
        }
        ,
        {
            label: 'Intranet Network',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An intranet is a private network accessible only to an organization's staff or delegates. Generally a wide range of information and services from the organization's internal IT systems are available that would not be available to the public from the Internet. A company-wide intranet can constitute an important focal point of internal communication and collaboration, and provide a single starting point to access internal and external resources. In its simplest form an intranet is established with the technologies for local area networks (LANs) and wide area networks (WANs).",
            insertText: 'IntranetNetwork',
            range: range,
        }
        ,
        {
            label: 'Operating System',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An operating system (OS) is system software that manages computer hardware and software resources and provides common services for computer programs. All computer programs, excluding firmware, require an operating system to function. Time-sharing operating systems schedule tasks for efficient use of the system and may also include accounting software for cost allocation of processor time, mass storage, printing, and other resources.",
            insertText: 'OperatingSystem',
            range: range,
        }
        ,
        {
            label: 'Storage',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Computer data storage, often called storage or memory, is a technology consisting of computer components and recording media used to retain digital data. It is a core function and fundamental component of computers. In the Von Neumann architecture, the CPU consists of two main parts: The control unit and the arithmetic / logic unit (ALU). The former controls the flow of data between the CPU and memory, while the latter performs arithmetic and logical operations on data.",
            insertText: 'Storage',
            range: range,
        }
        ,
        {
            label: 'Secondary Storage',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Secondary memory (storage, hard disk) is the computer component holding information that does not need to be accessed quickly and that needs to be retained long-term.",
            insertText: 'SecondaryStorage',
            range: range,
        }
        ,
        {
            label: 'Flash Memory',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Flash memory is an electronic non-volatile computer memory storage medium that can be electrically erased and reprogrammed.",
            insertText: 'FlashMemory',
            range: range,
        }
        ,
        {
            label: 'Cloud Storage',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Cloud storage is storage held within a computing cloud.",
            insertText: 'CloudStorage',
            range: range,
        }
        ,
        {
            label: 'Primary Storage',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Primary memory of a computer is memory that is wired directly to the processor, consisting of RAM and possibly ROM.  These terms are used in contrast to mass storage devices and cache memory (although we may note that when a program accesses main memory, it is often actually interacting with a cache).",
            insertText: 'PrimaryStorage',
            range: range,
        }
        ,
        {
            label: 'RAM',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Random-access memory (RAM) is a form of computer memory that can be read and changed in any order, typically used to store working data and machine code.",
            insertText: 'RAM',
            range: range,
        }
        ,
        {
            label: 'ROM',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Read-only memory (ROM) is a type of non-volatile memory used in computers and other electronic devices. Data stored in ROM cannot be electronically modified after the manufacture of the memory device. Read-only memory is useful for storing software that is rarely changed during the life of the system, also known as firmware.",
            insertText: 'ROM',
            range: range,
        }
        ,
        {
            label: 'Processor Register',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A processor register is a quickly accessible location available to a computer's processor. Registers usually consist of a small amount of fast storage, although some registers have specific hardware functions, and may be read-only or write-only.",
            insertText: 'ProcessorRegister',
            range: range,
        }
        ,
        {
            label: 'Processor Cache Memory',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Cache memory is temporary storage that is more readily available to the processor than the computer's main memory source, located between the main memory and the processor.  It is typically either integrated directly into the CPU chip (level 1 cache) or placed on a separate chip with a bus interconnect with the CPU (level 2 cache).",
            insertText: 'CacheMemory',
            range: range,
        }
        ,
        {
            label: 'Database',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A database is an organized collection of data, generally stored and accessed electronically from a computer system. Where databases are more complex they are often developed using formal design and modeling techniques.",
            insertText: 'Database',
            range: range,
        }
        ,
        {
            label: 'Code Repository',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A code repository is a form of database where code, typically source code, is stored and managed.  In revision control systems, a repository is a data structure that stores metadata for a set of files or directory structure. Depending on whether the version control system in use is distributed like (Git or Mercurial) or centralized like (Subversion, CVS, or Perforce), the whole set of information in the repository may be duplicated on every user's system or may be maintained on a single server.",
            insertText: 'CodeRepository',
            range: range,
        }
        ,
        {
            label: 'Password Database',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A password database is a database that holds passwords for user accounts and is usually encrypted (i.e.., the passwords are hashed). Password databases are found supporting system services (such as SAM) or part of user applications such as password managers.",
            insertText: 'PasswordDatabase',
            range: range,
        }
        ,
        {
            label: 'Password Store',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A user repository of account passwords, often accessed via a password manager.",
            insertText: 'PasswordStore',
            range: range,
        }
        ,
        {
            label: 'MacOS Keychain',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Keychain is the password management system in macOS, developed by Apple. It was introduced with Mac OS 8.6, and has been included in all subsequent versions of the operating system, now known as macOS. A Keychain can contain various types of data: passwords (for websites, FTP servers, SSH accounts, network shares, wireless networks, groupware applications, encrypted disk images), private keys, certificates, and secure notes.",
            insertText: 'MacOSKeychain',
            range: range,
        }
        ,
        {
            label: 'In-memory Password Store',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A password store held in memory.",
            insertText: 'In-memoryPasswordStore',
            range: range,
        }
        ,
        {
            label: 'System Password Database',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A password database used by a system service or process to authenticate users (e.g., Security Account Manager)",
            insertText: 'SystemPasswordDatabase',
            range: range,
        }
        ,
        {
            label: 'Password File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Simple form of password database held in a single file (e.g., /etc/password)",
            insertText: 'PasswordFile',
            range: range,
        }
        ,
        {
            label: 'System Configuration Database',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A database used to hold system configuration data.",
            insertText: 'SystemConfigurationDatabase',
            range: range,
        }
        ,
        {
            label: 'Windows Registry',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The Windows Registry is a hierarchical database that stores low-level settings for the Microsoft Windows operating system and for applications that opt to use the registry. The kernel, device drivers, services, Security Accounts Manager, and user interface can all use the registry. The registry also allows access to counters for profiling system performance.",
            insertText: 'WindowsRegistry',
            range: range,
        }
        ,
        {
            label: 'Pointer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computer science, a pointer is a programming language object, whose value refers to (or \"points to\") another value stored elsewhere in the computer memory using its memory address. A pointer references a location in memory, and obtaining the value stored at that location is known as dereferencing the pointer. As an analogy, a page number in a book's index could be considered a pointer to the corresponding page; dereferencing such a pointer would be done by flipping to the page with the given page number.",
            insertText: 'Pointer',
            range: range,
        }
        ,
        {
            label: 'Job Schedule',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A job schedule contains specification of tasks to be executed at particular times or time intervals.  The schedule is a plan that enacted by a task scheduling process. In Windows, the schedule can be accessed at 'C:\\Windows\\System32\\Tasks' or in the registry. In Linux, the schedule is located at '/etc/crontab'",
            insertText: 'JobSchedule',
            range: range,
        }
        ,
        {
            label: 'Identifier',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An identifier is a name that identifies (that is, labels the identity of) either a unique object or a unique class of objects, where the \"object\" or class may be an idea, physical [countable] object (or class thereof), or physical [noncountable] substance (or class thereof). The abbreviation ID often refers to identity, identification (the process of identifying), or an identifier (that is, an instance of identification). An identifier may be a word, number, letter, symbol, or any combination of those.",
            insertText: 'Identifier',
            range: range,
        }
        ,
        {
            label: 'Hostname',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computer networking, a hostname (archaically nodename) is a label that is assigned to a device connected to a computer network and that is used to identify the device in various forms of electronic communication, such as the World Wide Web. Hostnames may be simple names consisting of a single word or phrase, or they may be structured.",
            insertText: 'Hostname',
            range: range,
        }
        ,
        {
            label: 'Digital Fingerprint',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A digital signature uniquely identifies data and has the property that changing a single bit in the data will cause a completely different message digest to be generated.",
            insertText: 'DigitalFingerprint',
            range: range,
        }
        ,
        {
            label: 'IP Address',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An Internet Protocol address (IP address) is a numerical label assigned to each device connected to a computer network that uses the Internet Protocol for communication.An IP address serves two main functions: host or network interface identification and location addressing. Internet Protocol version 4 (IPv4) defines an IP address as a 32-bit number. However, because of the growth of the Internet and the depletion of available IPv4 addresses, a new version of IP (IPv6), using 128 bits for the IP address, was standardized in 1998. IPv6 deployment has been ongoing since the mid-2000s.",
            insertText: 'IPAddress',
            range: range,
        }
        ,
        {
            label: 'Domain Name',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A domain name is an identification string that defines a realm of administrative autonomy, authority or control within the Internet. Domain names are formed by the rules and procedures of the Domain Name System (DNS). Any name registered in the DNS is a domain name.Domain names are used in various networking contexts and application-specific naming and addressing purposes. In general, a domain name represents an Internet Protocol (IP) resource, such as a personal computer used to access the Internet, a server computer hosting a web site, or the web site itself or any other service communicated via the Internet. In 2015, 294 million domain names had been registered.",
            insertText: 'DomainName',
            range: range,
        }
        ,
        {
            label: 'URL',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A Uniform Resource Locator (URL), commonly informally termed a web address (a term which is not defined identically) is a reference to a web resource that specifies its location on a computer network and a mechanism for retrieving it.A URL is a specific type of Uniform Resource Identifier (URI), although many people use the two terms interchangeably. A URL implies the means to access an indicated resource, which is not true of every URI. URLs occur most commonly to reference web pages (http), but are also used for file transfer (ftp), email (mailto), database access (JDBC), and many other applications.",
            insertText: 'URL',
            range: range,
        }
        ,
        {
            label: 'Directory',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a directory is a file system cataloging structure which contains references to other computer files, and possibly other directories. On many computers, directories are known as folders, or drawers to provide some relevancy to a workbench or the traditional office file cabinet.",
            insertText: 'Directory',
            range: range,
        }
        ,
        {
            label: 'Startup Directory',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A startup directory is a directory containing executable files or links to executable files which are run when a user logs in or when a system component or service is started.",
            insertText: 'StartupDirectory',
            range: range,
        }
        ,
        {
            label: 'System Startup Directory',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A system startup directory is a directory containing executable files or links to executable files which are run when the system starts.",
            insertText: 'SystemStartupDirectory',
            range: range,
        }
        ,
        {
            label: 'Network Node',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In telecommunications networks, a node (Latin nodus, 'knot') is either a redistribution point or a communication endpoint. The definition of a node depends on the network and protocol layer referred to. A physical network node is an electronic device that is attached to a network, and is capable of creating, receiving, or transmitting information over a communications channel. A passive distribution point such as a distribution frame or patch panel is consequently not a node.",
            insertText: 'NetworkNode',
            range: range,
        }
        ,
        {
            label: 'Switch',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A network switch (also called switching hub, bridging hub, and by the IEEE MAC bridge) is networking hardware that connects devices on a computer network by using packet switching to receive and forward data to the destination device. A network switch is a multiport network bridge that uses MAC addresses to forward data at the data link layer (layer 2) of the OSI model. Some switches can also forward data at the network layer (layer 3) by additionally incorporating routing functionality. Such switches are commonly known as layer-3 switches or multilayer switches.",
            insertText: 'Switch',
            range: range,
        }
        ,
        {
            label: 'Firewall',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a firewall is a network security system that monitors and controls incoming and outgoing network traffic based on predetermined security rules. A firewall typically establishes a barrier between a trusted internal network and untrusted external network, such as the Internet. Firewalls are often categorized as either network firewalls or host-based firewalls. Network firewalls filter traffic between two or more networks and run on network hardware. Host-based firewalls run on host computers and control network traffic in and out of those machines. This definition refers to network firewalls.",
            insertText: 'Firewall',
            range: range,
        }
        ,
        {
            label: 'Application Layer Firewall',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An application firewall is a form of firewall that controls input, output, and/or access from, to, or by an application or service. It operates by monitoring and potentially blocking the input, output, or system service calls that do not meet the configured policy of the firewall. The application firewall is typically built to control all network traffic on any OSI layer up to the application layer. It is able to control applications or services specifically, unlike a stateful network firewall, which is - without additional software - unable to control network traffic regarding a specific application. There are two primary categories of application firewalls, network-based application firewalls and host-based application firewalls.",
            insertText: 'ApplicationLayerFirewall',
            range: range,
        }
        ,
        {
            label: 'Web Application Firewall',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A web application firewall (or WAF) filters, monitors, and blocks HTTP traffic to and from a web application. A WAF is differentiated from a regular firewall in that a WAF is able to filter the content of specific web applications while regular firewalls serve as a safety gate between servers. By inspecting HTTP traffic, it can prevent attacks stemming from web application security flaws, such as SQL injection, cross-site scripting (XSS), file inclusion, and security misconfigurations.",
            insertText: 'WebApplicationFirewall',
            range: range,
        }
        ,
        {
            label: 'Router',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A router is a networking device that forwards data packets between computer networks. Routers perform the traffic directing functions on the Internet. Data sent through the internet, such as a web page or email, is in the form of data packets. A packet is typically forwarded from one router to another router through the networks that constitute an internetwork (e.g. the Internet) until it reaches its destination node.",
            insertText: 'Router',
            range: range,
        }
        ,
        {
            label: 'Wireless Router',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A wireless router is a device that performs the functions of a router and also includes the functions of a wireless access point. It is used to provide access to the Internet or a private computer network. Depending on the manufacturer and model, it can function in a wired local area network, in a wireless-only LAN, or in a mixed wired and wireless network.",
            insertText: 'WirelessRouter',
            range: range,
        }
        ,
        {
            label: 'Wireless Access Point',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computer networking, a wireless access point (WAP), or more generally just access point (AP), is a networking hardware device that allows other Wi-Fi devices to connect to a wired network. The AP usually connects to a router (via a wired network) as a standalone device, but it can also be an integral component of the router itself. An AP is differentiated from a hotspot which is a physical location where Wi-Fi access is available.",
            insertText: 'WirelessAccessPoint',
            range: range,
        }
        ,
        {
            label: 'Proxy Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computer networking, a proxy server is a server application or appliance that acts as an intermediary for requests from clients seeking resources from servers that provide those resources. A proxy server thus functions on behalf of the client when requesting service, potentially masking the true origin of the request to the resource server.",
            insertText: 'ProxyServer',
            range: range,
        }
        ,
        {
            label: 'Forward Proxy Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An forward (or open) proxy is a proxy server that is accessible by any Internet user. Generally, a proxy server only allows users within a network group (i.e. a closed proxy) to store and forward Internet services such as DNS or web pages to reduce and control the bandwidth used by the group. With an open proxy, however, any user on the Internet is able to use this forwarding service.",
            insertText: 'ForwardProxyServer',
            range: range,
        }
        ,
        {
            label: 'Reverse Proxy Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computer networks, a reverse proxy is a type of proxy server that retrieves resources on behalf of a client from one or more servers. These resources are then returned to the client, appearing as if they originated from the proxy server itself. Unlike a forward proxy, which is an intermediary for its associated clients to contact any server, a reverse proxy is an intermediary for its associated servers to be contacted by any client. In other words, a proxy acts on behalf of the client(s), while a reverse proxy acts on behalf of the server(s); a reverse proxy is usually an internal-facing proxy used as a 'front-end' to control and protect access to a server on a private network.",
            insertText: 'ReverseProxyServer',
            range: range,
        }
        ,
        {
            label: 'Modem',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A modem -- a portmanteau of \"modulator-demodulator\" -- is a hardware device that converts data into a format suitable for a transmission medium so that it can be transmitted from one computer to another (historically along telephone wires). A modem modulates one or more carrier wave signals to encode digital information for transmission and demodulates signals to decode the transmitted information. The goal is to produce a signal that can be transmitted easily and decoded reliably to reproduce the original digital data. Modems can be used with almost any means of transmitting analog signals from light-emitting diodes to radio. A common type of modem is one that turns the digital data of a computer into modulated electrical signal for transmission over telephone lines and demodulated by another modem at the receiver side to recover the digital data.",
            insertText: 'Modem',
            range: range,
        }
        ,
        {
            label: 'Dial Up Modem',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A dial-up modem transmits computer data over an ordinary switched telephone line that has not been designed for data use. This contrasts with leased line modems, which also operate over lines provided by a telephone company, but ones which are intended for data use and do not impose the same signaling constraints. The modulated data must fit the frequency constraints of a normal voice audio signal, and the modem must be able to perform the actions needed to connect a call through a telephone exchange, namely: picking up the line, dialing, understanding signals sent back by phone company equipment (dial tone, ringing, busy signal,) and on the far end of the call, the second modem in the connection must be able to recognize the incoming ring signal and answer the line.",
            insertText: 'DialUpModem',
            range: range,
        }
        ,
        {
            label: 'Optical Modem',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A modem that connects to a fiber optic network is known as an optical network terminal (ONT) or optical network unit (ONU). These are commonly used in fiber to the home installations, installed inside or outside a house to convert the optical medium to a copper Ethernet interface, after which a router or gateway is often installed to perform authentication, routing, NAT, and other typical consumer internet functions, in addition to \"triple play\" features such as telephony and television service.",
            insertText: 'OpticalModem',
            range: range,
        }
        ,
        {
            label: 'Radio Modem',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A radio modem provides the means to send digital data wirelessly.  Radio modems are used to communicate by direct broadcast satellite, WiFi, WiMax, mobile phones, GPS, Bluetooth and NFC. Modern telecommunications and data networks also make extensive use of radio modems where long distance data links are required. Such systems are an important part of the PSTN, and are also in common use for high-speed computer network links to outlying areas where fiber optic is not economical.",
            insertText: 'RadioModem',
            range: range,
        }
        ,
        {
            label: 'Host',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A host is a computer or other device, typically connected to a computer network. A network host may offer information resources, services, and applications to users or other nodes on the network. A network host is a network node that is assigned a network layer host address. Network hosts that participate in applications that use the client-server model of computing, are classified as server or client systems. Network hosts may also function as nodes in peer-to-peer applications, in which all nodes share and consume resources in an equipotent manner.",
            insertText: 'Host',
            range: range,
        }
        ,
        {
            label: 'Client Computer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A client computer is a host that accesses a service made available by a server. The server is often (but not always) on another computer system, in which case the client accesses the service by way of a network.",
            insertText: 'ClientComputer',
            range: range,
        }
        ,
        {
            label: 'Embedded Computer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An embedded computer is a computer system -- a combination of a computer processor, computer memory, and input/output peripheral devices-that has a dedicated function within a larger mechanical or electrical system. It is embedded as part of a complete device often including electrical or electronic hardware and mechanical parts. Because an embedded system typically controls physical operations of the machine that it is embedded within, it often has real-time computing constraints. Embedded systems control many devices in common use today. Ninety-eight percent of all microprocessors manufactured are used in embedded systems.",
            insertText: 'EmbeddedComputer',
            range: range,
        }
        ,
        {
            label: 'Shared Computer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A computer whose resources are intended to be shared widely.",
            insertText: 'SharedComputer',
            range: range,
        }
        ,
        {
            label: 'Kiosk Computer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An interactive kiosk is a computer terminal featuring specialized hardware and software that provides access to information and applications for communication, commerce, entertainment, or education. Early interactive kiosks sometimes resembled telephone booths, but have been embraced by retail, food service and hospitality to improve customer service and streamline operations. Interactive kiosks are typically placed in high foot traffic settings such as shops, hotel lobbies or airports.",
            insertText: 'KioskComputer',
            range: range,
        }
        ,
        {
            label: 'Network Printer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a network printer is a device that can be accessed over a network which makes a persistent representation of graphics or text, usually on paper. While most output is human-readable, bar code printers are an example of an expanded use for printers. The different types of printers include 3D printer, inkjet printer, laser printer, thermal printer, etc.  Note that not all printers are networked and the digital information to be printed must be passed either by removable media or as directly connecting the printer to a computer (e.g., by USB.)",
            insertText: 'NetworkPrinter',
            range: range,
        }
        ,
        {
            label: 'Operations Center Computer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Mainframe computers or mainframes (colloquially referred to as \"big iron\") are computers used primarily by large organizations for critical applications; bulk data processing, such as census, industry and consumer statistics, and enterprise resource planning; and transaction processing. They are larger and have more processing power than some other classes of computers: minicomputers, servers, workstations, and personal computers.",
            insertText: 'OperationsCenterComputer',
            range: range,
        }
        ,
        {
            label: 'Thin Client Computer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A thin client is a lightweight computer that has been optimized for establishing a remote connection with a server-based computing environment. The server does most of the work, which can include launching software programs, performing calculations, and storing data. This contrasts with a fat client or a conventional personal computer; the former is also intended for working in a client-server model but has significant local processing power, while the latter aims to perform its function mostly locally. Thin clients are shared computers as the thin client's computing resources are provided by a remote server.",
            insertText: 'ThinClientComputer',
            range: range,
        }
        ,
        {
            label: 'Zero Client Computer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Zero client is also referred as ultra thin client, contains no moving parts but centralizes all processing and storage to just what is running on the server. As a result, it requires no local driver to install, no patch management, and no local operating system licensing fees or updates. The device consumes very little power and is tamper-resistant and completely incapable of storing any data locally, providing a more secure endpoint.",
            insertText: 'ZeroClientComputer',
            range: range,
        }
        ,
        {
            label: 'Personal Computer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A personal computer (PC) is a multi-purpose computer whose size, capabilities, and price make it feasible for individual use. Personal computers are intended to be operated directly by an end user, rather than by a computer expert or technician. Unlike large, costly minicomputers and mainframes, time-sharing by many people at the same time is not used with personal computers. PCs have in practice become powerful enough that they may be shared by multiple users at any given time, though this is not common practice nor the primary purpose of a PC.",
            insertText: 'PersonalComputer',
            range: range,
        }
        ,
        {
            label: 'Desktop Computer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A desktop computer is a personal computer designed for regular use at a single location on or near a desk or table due to its size and power requirements. The most common configuration has a case that houses the power supply, motherboard (a printed circuit board with a microprocessor as the central processing unit (CPU), memory, bus, and other electronic components, disk storage (usually one or more hard disk drives, solid state drives, optical disc drives, and in early models a floppy disk drive); a keyboard and mouse for input; and a computer monitor, speakers, and, often, a printer for output. The case may be oriented horizontally or vertically and placed either underneath, beside, or on top of a desk.",
            insertText: 'DesktopComputer',
            range: range,
        }
        ,
        {
            label: 'IP Phone',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A VoIP phone or IP phone uses voice over IP technologies for placing and transmitting telephone calls over an IP network, such as the Internet, instead of the traditional public switched telephone network (PSTN). Digital IP-based telephone service uses control protocols such as the Session Initiation Protocol (SIP), Skinny Client Control Protocol (SCCP) or various other proprietary protocols.",
            insertText: 'IPPhone',
            range: range,
        }
        ,
        {
            label: 'Laptop Computer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A laptop computer (also laptop), is a small, portable personal computer (PC) with a \"clamshell\" form factor, typically having a thin LCD or LED computer screen mounted on the inside of the upper lid of the clamshell and an alphanumeric keyboard on the inside of the lower lid. The clamshell is opened up to use the computer. Laptops are folded shut for transportation, and thus are suitable for mobile use. Its name comes from lap, as it was deemed to be placed on a person's lap when being used. Although originally there was a distinction between laptops and notebooks (the former being bigger and heavier than the latter), as of 2014, there is often no longer any difference. Today, laptops are commonly used in a variety of settings, such as at work, in education, for playing games, web browsing",
            insertText: 'LaptopComputer',
            range: range,
        }
        ,
        {
            label: 'Mobile Phone',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A mobile phone, cellular phone, cell phone, cellphone or hand phone, sometimes shortened to simply mobile, cell or just phone, is a portable telephone that can make and receive calls over a radio frequency link while the user is moving within a telephone service area. The radio frequency link establishes a connection to the switching systems of a mobile phone operator, which provides access to the public switched telephone network (PSTN). Modern mobile telephone services use a cellular network architecture and, therefore, mobile telephones are called cellular telephones or cell phones in North America. In addition to telephony, digital mobile phones (2G) support a variety of other services, such as text messaging, MMS, email, Internet access, short-range wireless communications (infrared,",
            insertText: 'MobilePhone',
            range: range,
        }
        ,
        {
            label: 'Tablet Computer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A tablet computer, commonly shortened to tablet, is a mobile device, typically with a mobile operating system and touchscreen display processing circuitry, and a rechargeable battery in a single, thin and flat package. Tablets, being computers, do what other personal computers do, but lack some input/output (I/O) abilities that others have. Modern tablets largely resemble modern smartphones, the only differences being that tablets are relatively larger than smartphones, with screens 7 inches (18 cm) or larger, measured diagonally, and may not support access to a cellular network.",
            insertText: 'TabletComputer',
            range: range,
        }
        ,
        {
            label: 'Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a server is a piece of computer hardware or software (computer program) that provides functionality for other programs or devices, called \"clients\". This architecture is called the client-server model. Servers can provide various functionalities, often called \"services\", such as sharing data or resources among multiple clients, or performing computation for a client. A single server can serve multiple clients, and a single client can use multiple servers. A client process may run on the same device or may connect over a network to a server on a different device. Typical servers are database servers, file servers, mail servers, print servers, web servers, game servers, and application servers.",
            insertText: 'Server',
            range: range,
        }
        ,
        {
            label: 'Authentication Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An authentication server provides a network service that applications use to authenticate the credentials, usually account names and passwords, of their users. When a client submits a valid set of credentials, it receives a cryptographic ticket that it can subsequently use to access various services. Major authentication algorithms include passwords, Kerberos, and public key encryption.",
            insertText: 'AuthenticationServer',
            range: range,
        }
        ,
        {
            label: 'Computing Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A compute server is a system specifically designed to undertake large amounts of computation, usually but not necessarily in a client/server environment.",
            insertText: 'ComputingServer',
            range: range,
        }
        ,
        {
            label: 'DHCP Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A Dynamic Host Configuration Protocol (DHCP) server is a type of server that assigns IP addresses to computers.  DHCP servers are used to assign IP addresses to computers and other devices automatically.  The DHCP server is responsible for assigning the unique IP address to each device.",
            insertText: 'DHCPServer',
            range: range,
        }
        ,
        {
            label: 'DNS Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A Domain Name System (DNS) name server is a kind of name server.  Domain names are one of the two principal namespaces of the Internet. The most important function of DNS servers is the translation (resolution) of human-memorable domain names and hostnames into the corresponding numeric Internet Protocol (IP) addresses, the second principal name space of the Internet which is used to identify and locate computer systems and resources on the Internet. (en).\n\nMore generally, a name server is a computer application that implements a network service for providing responses to queries against a directory service. It translates an often humanly meaningful, text-based identifier to a system-internal, often numeric identification or addressing component. This service is performed by the server in response to a service protocol request.",
            insertText: 'DNSServer',
            range: range,
        }
        ,
        {
            label: 'Database Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A database server is a server which uses a database application that provides database services to other computer programs or to computers, as defined by the client-server model. Database management systems (DBMSs) frequently provide database-server functionality, and some database management systems (such as MySQL) rely exclusively on the client-server model for database access (while others e.g. SQLite are meant for using as an embedded database). For clarification, a database server is simply a server that maintains services related to clients via database applications.",
            insertText: 'DatabaseServer',
            range: range,
        }
        ,
        {
            label: 'Media Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A media server is a computer appliance or an application software that stores digital media (video, audio or images) and makes it available over a network. Media servers range from servers that provide video on demand to smaller personal computers or NAS (Network Attached Storage) for the home.",
            insertText: 'MediaServer',
            range: range,
        }
        ,
        {
            label: 'Network Time Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A network time server is a server computer that reads the actual time from a reference clock and distributes this information to its clients using a computer network. The time server may be a local network time server or an internet time server. The time server may also be a stand-alone hardware device. It can use NTP (RFC5905) or other protocols.",
            insertText: 'NetworkTimeServer',
            range: range,
        }
        ,
        {
            label: 'Print Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A print server, or printer server, is a device that connects printers to client computers over a network. It accepts print jobs from the computers and sends the jobs to the appropriate printers, queuing the jobs locally to accommodate the fact that work may arrive more quickly than the printer can actually handle.",
            insertText: 'PrintServer',
            range: range,
        }
        ,
        {
            label: 'TFTP Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Trivial File Transfer Protocol (TFTP) is a simple file transfer protocol, typically used to automatically transfer configuration or boot files between machines.  It is used where user authentication and directory visibility are not required.",
            insertText: 'TFTPServer',
            range: range,
        }
        ,
        {
            label: 'VPN Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A VPN server is a type of server that enables hosting and delivery of VPN services.\n\nIt is a combination of VPN hardware and software technologies that provides VPN clients with connectivity to a secure and/or private network, or rather, the VPN.",
            insertText: 'VPNServer',
            range: range,
        }
        ,
        {
            label: 'File Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The term server highlights the role of the machine in the traditional client-server scheme, where the clients are the workstations using the storage. A file server does not normally perform computational tasks or run programs on behalf of its client workstations. File servers are commonly found in schools and offices, where users use a local area network to connect their client computers.",
            insertText: 'FileServer',
            range: range,
        }
        ,
        {
            label: 'Orchestration Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A d3f:Server which is involved with the orchestration of workloads or the execution of orchestrated workloads.",
            insertText: 'OrchestrationServer',
            range: range,
        }
        ,
        {
            label: 'Orchestration Controller',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An orchestration server provides orchestration services that automate the configuration, coordination, and management of computer systems and software.",
            insertText: 'OrchestrationController',
            range: range,
        }
        ,
        {
            label: 'Orchestration Worker',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A d3f:Server which receives commands from a d3f:OrchestrationController to execute workloads.",
            insertText: 'OrchestrationWorker',
            range: range,
        }
        ,
        {
            label: 'Web Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A web server is server software, or hardware dedicated to running this software, that can satisfy client requests on the World Wide Web. A web server can, in general, contain one or more websites. A web server processes incoming network requests over HTTP and several other related protocols. While the major function is to serve content, a full implementation of HTTP also includes ways of receiving content from clients. This feature is used for submitting web forms, including uploading of files.",
            insertText: 'WebServer',
            range: range,
        }
        ,
        {
            label: 'Web Application Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A web application server is a web server that hosts applications. Application server frameworks are software frameworks for building application servers. An application server framework provides both facilities to create web applications and a server environment to run them. In the case of Java application servers, the server behaves like an extended virtual machine for running applications, transparently handling connections to the database on one side, and, often, connections to the Web client on the other.",
            insertText: 'WebApplicationServer',
            range: range,
        }
        ,
        {
            label: 'Artifact Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A digital artifact server provides access services to digital artifacts in a repository.  It provides an associated set of data management, search and access methods allowing application-independent access to the content.",
            insertText: 'ArtifactServer',
            range: range,
        }
        ,
        {
            label: 'Data Artifact Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A data artifact server provides access services to content in a content repository.  The content repository or content store is a database of digital content with an associated set of data management, search and access methods allowing application-independent access to the content, rather like a digital library, but with the ability to store and modify content in addition to searching and retrieving. The content repository acts as the storage engine for a larger application such as a content management system or a document management system, which adds a user interface on top of the repository's application programming interface.",
            insertText: 'DataArtifactServer',
            range: range,
        }
        ,
        {
            label: 'Software Artifact Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A software artifact server provides access to the software artifacts in a software repository. A software repository, or \"repo\" for short, is a storage location for software packages. Often a table of contents is stored, as well as metadata. Repositories group packages. Sometimes the grouping is for a programming language, such as CPAN for the Perl programming language, sometimes for an entire operating system, sometimes the license of the contents is the criteria. At client side, a package manager helps installing from and updating the repositories.",
            insertText: 'SoftwareArtifactServer',
            range: range,
        }
        ,
        {
            label: 'Mail Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Within the Internet email system, a message transfer agent or mail transfer agent (MTA) or mail relay is software that transfers electronic mail messages from one computer to another using SMTP. The terms mail server, mail exchanger, and MX host are also used in some contexts. Messages exchanged across networks are passed between mail servers, including any attached data files (such as images, multimedia or documents). These servers also often keep mailboxes for email. Access to this email by end users is typically either via webmail or an email client.",
            insertText: 'MailServer',
            range: range,
        }
        ,
        {
            label: 'Hardware Device',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Hardware devices are the physical artifacts that constitute a network or computer system. Hardware devices are the physical parts or components of a computer, such as the monitor, keyboard, computer data storage, hard disk drive (HDD), graphic cards, sound cards, memory (RAM), motherboard, and so on, all of which are tangible physical objects. By contrast, software is instructions that can be stored and run by hardware. Hardware is directed by the software to execute any command or instruction. A combination of hardware and software forms a usable computing system.",
            insertText: 'HardwareDevice',
            range: range,
        }
        ,
        {
            label: 'Translation Lookaside Buffer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A translation lookaside buffer (TLB) is a memory cache that is used to reduce the time taken to access a user memory location. It is a part of the chip's memory-management unit (MMU).",
            insertText: 'TranslationLookasideBuffer',
            range: range,
        }
        ,
        {
            label: 'Output Device',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An output device is any piece of computer hardware equipment which converts information into human-readable form. It can be text, graphics, tactile, audio, and video. Some of the output devices are Visual Display Units (VDU) i.e. a Monitor, Printer, Graphic Output devices, Plotters, Speakers etc. A new type of Output device is been developed these days, known as Speech synthesizer, a mechanism attached to the computer which produces verbal output sounding almost like human speeches.",
            insertText: 'OutputDevice',
            range: range,
        }
        ,
        {
            label: 'Display Adapter',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A graphics card (also called a display card, video card, display adapter, or graphics adapter) is an expansion card which generates a feed of output images to a display device (such as a computer monitor). Frequently, these are advertised as discrete or dedicated graphics cards, emphasizing the distinction between these and integrated graphics. At the core of both is the graphics processing unit (GPU), which is the main part that does the actual computations, but should not be confused with the video card as a whole, although \"GPU\" is often used to refer to video cards.",
            insertText: 'DisplayAdapter',
            range: range,
        }
        ,
        {
            label: 'Central Processing Unit',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A central processing unit (CPU), also called a central processor, main processor or just processor, is the electronic circuitry that executes instructions comprising a computer program. The CPU performs basic arithmetic, logic, controlling, and input/output (I/O) operations specified by the instructions in the program. This contrasts with external components such as main memory and I/O circuitry, and specialized processors such as graphics",
            insertText: 'CentralProcessingUnit',
            range: range,
        }
        ,
        {
            label: 'Memory Management Unit',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A computer\u2019s memory management unit (MMU) is the physical hardware that handles its virtual memory and caching operations. The MMU is usually located within the computer\u2019s central processing unit (CPU), but sometimes operates in a separate integrated chip (IC).",
            insertText: 'MemoryManagementUnit',
            range: range,
        }
        ,
        {
            label: 'Security Token',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Security tokens are peripheral devices used to prove one's identity electronically (as in the case of a customer trying to access their bank account). The token is used in addition to or in place of a password to prove that the customer is who they claim to be. The token acts like an electronic key to access something.",
            insertText: 'SecurityToken',
            range: range,
        }
        ,
        {
            label: 'Input Device',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, an input device is a piece of equipment used to provide data and control signals to an information processing system such as a computer or information appliance. Examples of input devices include keyboards, mouse, scanners, digital cameras, joysticks, and microphones. Input devices can be categorized based on:",
            insertText: 'InputDevice',
            range: range,
        }
        ,
        {
            label: 'Mouse Input Device',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A computer mouse (plural mice or mouses) is a hand-held pointing device that detects two-dimensional motion relative to a surface. This motion is typically translated into the motion of a pointer on a display, which allows a smooth control of the graphical user interface of a computer. In addition to moving a cursor, computer mice have one or more buttons to allow operations such as selection of a menu item on a display. Mice often also feature other elements, such as touch surfaces and scroll wheels, which enable additional control and dimensional input.",
            insertText: 'MouseInputDevice',
            range: range,
        }
        ,
        {
            label: 'Audio Input Device',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Audio input devices allow a user to send audio info to a computer for processing, recording, or carrying out commands. Devices such as microphones allow users to speak to the computer in order to record a voice message or navigate software. Aside from recording, audio input devices are also used with speech recognition software.",
            insertText: 'AudioInputDevice',
            range: range,
        }
        ,
        {
            label: 'Keyboard Input Device',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A computer keyboard is a typewriter-style device which uses an arrangement of buttons or keys to act as mechanical levers or electronic switches. Following the decline of punch cards and paper tape, interaction via teleprinter-style keyboards became the main input method for computers. A keyboard is also used to give commands to the operating system of a computer, such as Windows' Control-Alt-Delete combination. Although on Pre-Windows 95 Microsoft operating systems this forced a re-boot, now it brings up a system security options screen.",
            insertText: 'KeyboardInputDevice',
            range: range,
        }
        ,
        {
            label: 'Video Input Device',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Video input devices are used to digitize images or video from the outside world into the computer. The information can be stored in a multitude of formats depending on the user's requirement.",
            insertText: 'VideoInputDevice',
            range: range,
        }
        ,
        {
            label: 'Image Scanner Input Device',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An image scanner -- often abbreviated to just scanner, is a device that optically scans images, printed text, handwriting or an object and converts it to a digital image. Commonly used in offices are variations of the desktop flatbed scanner where the document is placed on a glass window for scanning. Hand-held scanners, where the device is moved by hand, have evolved from text scanning \"wands\" to 3D scanners used for industrial design, reverse engineering, test and measurement, orthotics, gaming and other applications. Mechanically driven scanners that move the document are typically used for large-format documents, where a flatbed design would be impractical.",
            insertText: 'ImageScannerInputDevice',
            range: range,
        }
        ,
        {
            label: 'Barcode Scanner Input Device',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A barcode reader (or barcode scanner) is an optical scanner that can read printed barcodes, decode the data contained in the barcode and send the data to a computer. Like a flatbed scanner, it consists of a light source, a lens and a light sensor translating for optical impulses into electrical signals. Additionally, nearly all barcode readers contain decoder circuitry that can analyze the barcode's image data provided by the sensor and sending the barcode's content to the scanner's output port.",
            insertText: 'BarcodeScannerInputDevice',
            range: range,
        }
        ,
        {
            label: 'Finger Print Scanner Input Device',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A fingerprint sensor is an electronic device used to capture a digital image of the fingerprint pattern. The captured image is called a live scan. This live scan is digitally processed to create a biometric template (a collection of extracted features) which is stored and used for matching. Many technologies have been used including optical, capacitive, RF, thermal, piezoresistive, ultrasonic, piezoelectric, and MEMS.",
            insertText: 'FingerPrintScannerInputDevice',
            range: range,
        }
        ,
        {
            label: 'Removable Media Device',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A removable media device is a hardware device used for computer storage and that is designed to be inserted and removed from the system.  It is distinct from other removable media in that all the hardware required to read the data are built into the device.  So USB flash drives and external hard drives are removable media devices, whereas tapes and disks are not, as they require additional hardware to perform read/write operations.",
            insertText: 'RemovableMediaDevice',
            range: range,
        }
        ,
        {
            label: 'Resource',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a system resource, or simply resource, is any physical or virtual component of limited availability within a computer system. Every device connected to a computer system is a resource. Every internal system component is a resource. Virtual system resources include files (concretely file handles), network connections (concretely network sockets), and memory areas. Managing resources is referred to as resource management, and includes both preventing resource leaks (releasing a resource when a process has finished using it) and dealing with resource contention (when multiple processes wish to access a limited resource).",
            insertText: 'Resource',
            range: range,
        }
        ,
        {
            label: 'Remote Resource',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a remote  resource is a computer resource made available from one host to other hosts on a computer network. It is a device or piece of information on a computer that can be remotely accessed from another computer, typically via a local area network or an enterprise intranet.",
            insertText: 'RemoteResource',
            range: range,
        }
        ,
        {
            label: 'Network Resource',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a shared resource, or network share, is a computer resource made available from one host to other hosts on a computer network. It is a device or piece of information on a computer that can be remotely accessed from another computer, typically via a local area network or an enterprise intranet, transparently as if it were a resource in the local machine.Network sharing is made possible by inter-process communication over the network.",
            insertText: 'NetworkResource',
            range: range,
        }
        ,
        {
            label: 'Web Resource',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A web resource is a resource identified by a Uniform Resource Identifier (URI) and made available from one host to another host via a web protocol and across a network or networks.",
            insertText: 'WebResource',
            range: range,
        }
        ,
        {
            label: 'Web API Resource',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A web API resource is an API resource identified by a Uniform Resource Identifier (URI) and made available from one host to another host via a web protocol and across a network or networks.",
            insertText: 'WebAPIResource',
            range: range,
        }
        ,
        {
            label: 'Web File Resource',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A web file resource is a file resource identified by a Uniform Resource Identifier (URI) and made available from one host to another host via a web protocol and across a network or networks.",
            insertText: 'WebFileResource',
            range: range,
        }
        ,
        {
            label: 'Network File Share Resource',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A shared file resource, or network file share, is a computer file made available from one host to other hosts on a computer network. Network sharing is made possible by inter-process communication over the network. It includes both files and directories.",
            insertText: 'NetworkFileShareResource',
            range: range,
        }
        ,
        {
            label: 'Network Directory Resource',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A directory resource made available from one host to other hosts on a computer network.",
            insertText: 'NetworkDirectoryResource',
            range: range,
        }
        ,
        {
            label: 'Network File Resource',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A computer file resource made available from one host to other hosts on a computer network.",
            insertText: 'NetworkFileResource',
            range: range,
        }
        ,
        {
            label: 'Network Init Script File Resource',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A computer file resource made available from one host to other hosts on a computer network that is also an initialization script.",
            insertText: 'NetworkInitScriptFileResource',
            range: range,
        }
        ,
        {
            label: 'Local Resource',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a system resource, or simply resource, is any physical or virtual component of limited availability within a computer system. Every device connected to a computer system is a resource. Every internal system component is a resource. Virtual system resources include files (concretely file handles), network connections (concretely network sockets), and memory areas. Managing resources is referred to as resource management, and includes both preventing resource leaks (releasing a resource when a process has finished using it) and dealing with resource contention (when multiple processes wish to access a limited resource).",
            insertText: 'LocalResource',
            range: range,
        }
        ,
        {
            label: 'System Configuration Init Resource',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A system configuration initialization resource has information for initializing (booting) a system.",
            insertText: 'SystemConfigurationInitResource',
            range: range,
        }
        ,
        {
            label: 'System Init Script',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A script used to initialize and configure elements of the system's environment, applications, services, or its operating system.",
            insertText: 'SystemInitScript',
            range: range,
        }
        ,
        {
            label: 'User Logon Init Resource',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A user logon initialization resource contains information used to configure a user's environment when a user logs into a system.",
            insertText: 'UserLogonInitResource',
            range: range,
        }
        ,
        {
            label: 'User Startup Directory',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A user startup directory holds information necessary to start the users session with the system.",
            insertText: 'UserStartupDirectory',
            range: range,
        }
        ,
        {
            label: 'User Init Configuration File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A user initialization configuration file is a file containing the information necessary to configure that part of a user's environment which is common to all applications and actions. User configurations may be overridden by more specific configuration information (such as that found in a application configuration file.)",
            insertText: 'UserInitConfigurationFile',
            range: range,
        }
        ,
        {
            label: 'User Startup Script File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A user startup script file is a shortcut file that is executed when a user logs in and starts a session on the host.  These indicate applications the user wants started at login.  For Windows, these are typically found in the user's startup directory.",
            insertText: 'UserStartupScriptFile',
            range: range,
        }
        ,
        {
            label: 'User Init Script',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A script used to initialize and configure elements of the user's applications and user environment.",
            insertText: 'UserInitScript',
            range: range,
        }
        ,
        {
            label: 'PowerShell Profile Script',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A PowerShell profile script is a script that runs when PowerShell starts and can be used as a logon script to customize user environments.",
            insertText: 'PowerShellProfileScript',
            range: range,
        }
        ,
        {
            label: 'Configuration Resource',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A resource used to configure a system including software and hardware.",
            insertText: 'ConfigurationResource',
            range: range,
        }
        ,
        {
            label: 'Configuration Management Database',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A database used to store configuration records throughout their lifecycle. The Configuration Management System (CMS) maintains one or more CMDBs, and each CMDB stores attributes of configuration items (CIs), and relationships with other CIs.",
            insertText: 'ConfigurationManagementDatabase',
            range: range,
        }
        ,
        {
            label: 'Application Configuration Database',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A database used to hold application configuration data.",
            insertText: 'ApplicationConfigurationDatabase',
            range: range,
        }
        ,
        {
            label: 'Shim Database',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A application configuration database that contains or points to software shims (e.g., for backward compatibility, patches, etc.)",
            insertText: 'ShimDatabase',
            range: range,
        }
        ,
        {
            label: 'Operating System Configuration',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Information used to configure the services, parameters, and initial settings for an operating system.",
            insertText: 'OperatingSystemConfiguration',
            range: range,
        }
        ,
        {
            label: 'Operating System Configuration Component',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An component of the overall information necessary for the configuration of an operating system.",
            insertText: 'OperatingSystemConfigurationComponent',
            range: range,
        }
        ,
        {
            label: 'System Firewall Configuration',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The configuration for a individual host operating system's firewall.",
            insertText: 'SystemFirewallConfiguration',
            range: range,
        }
        ,
        {
            label: 'System Init Configuration',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "System initialization configuration information is configuration information used to configure the services, parameters, and initial settings for an operating system at startup.",
            insertText: 'SystemInitConfiguration',
            range: range,
        }
        ,
        {
            label: 'Cloud Configuration',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Information used to configure the services, parameters, and initial settings for a virtual server instance running in a cloud service..",
            insertText: 'CloudConfiguration',
            range: range,
        }
        ,
        {
            label: 'Cloud Instance Metadata',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Cloud instance metadata is configuration information on the instance and users of the instance.  This includes such information as security groups, public ip addresses, and private addresses, public keys configured, and event rotating security keys. User data can contain initialization scripts, variables, passwords, and more.",
            insertText: 'CloudInstanceMetadata',
            range: range,
        }
        ,
        {
            label: 'Access Control Configuration',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Information about what access permissions are granted to particular users for particular objects",
            insertText: 'AccessControlConfiguration',
            range: range,
        }
        ,
        {
            label: 'Access Control Group',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A collection of objects that can have access controls placed on them.",
            insertText: 'AccessControlGroup',
            range: range,
        }
        ,
        {
            label: 'Host Group',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A collection of Hosts used to allow operations such as access control to be applied to the entire group.",
            insertText: 'HostGroup',
            range: range,
        }
        ,
        {
            label: 'User Group',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "User groups are a way to collect user accounts and/or computer accounts into manageable units. Administrators can assign permissions, roles, or access to resources, as well as modify group membership, depending on the operating system.",
            insertText: 'UserGroup',
            range: range,
        }
        ,
        {
            label: 'Access Control List',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A list of permissions attached to an object.",
            insertText: 'AccessControlList',
            range: range,
        }
        ,
        {
            label: 'Group Policy',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Group Policy is a feature of the Microsoft Windows NT family of operating systems that controls the working environment of user accounts and computer accounts. Group Policy provides the centralized management and configuration of operating systems, applications, and users' settings in an Active Directory environment. A version of Group Policy called Local Group Policy (\"LGPO\" or \"LocalGPO\") also allows Group Policy Object management on standalone and non-domain computers.",
            insertText: 'GroupPolicy',
            range: range,
        }
        ,
        {
            label: 'Application Configuration',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Information used to configure the parameters and initial settings for an application.",
            insertText: 'ApplicationConfiguration',
            range: range,
        }
        ,
        {
            label: 'Application Process Configuration',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The current configuration of an application process, stored in memory. It may have been sourced from other types of application configurations, e.g. Application Configuration Files or Application Configuration Database Records.",
            insertText: 'ApplicationProcessConfiguration',
            range: range,
        }
        ,
        {
            label: 'Application Rule',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A configuration of an application which is used to apply logical or data processing functions to data processed by the application.",
            insertText: 'ApplicationRule',
            range: range,
        }
        ,
        {
            label: 'Email Rule',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A configuration of an email application which is used to apply logical or data processing functions to data processed by the email  application.",
            insertText: 'EmailRule',
            range: range,
        }
        ,
        {
            label: 'Process Environment Variable',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An environment variable is a dynamic-named value that can affect the way running processes will behave on a computer. They are part of the environment in which a process runs.",
            insertText: 'ProcessEnvironmentVariable',
            range: range,
        }
        ,
        {
            label: 'File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A file maintained in computer-readable form.",
            insertText: 'File',
            range: range,
        }
        ,
        {
            label: 'Shortcut File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A shortcut file, or shortcut, is a handle that allows the user to find a file or resource located in a different directory or folder from the place where the shortcut is located.\n\nShortcuts, which are supported by the graphical file browsers of some operating systems, may resemble symbolic links but differ in a number of important ways. One difference is what type of software is able to follow them:\n\n - Symbolic links are automatically resolved by the file system. Any software program, upon accessing a symbolic link, will see the target instead, whether the program is aware of symbolic links or not.\n\n - Shortcuts are treated like ordinary files by the file system and by software programs that are not aware of them. Only software programs that understand shortcuts (such as the Windows shell and file browsers) treat them as references to other files.\n\nAnother difference are the capabilities of the mechanism:\n\n - Microsoft Windows shortcuts normally refer to a destination by an absolute path (starting from the root directory), whereas POSIX symbolic links can refer to destinations via either an absolute or a relative path. The latter is useful if both the location and destination of the symbolic link share a common path prefix[clarification needed], but that prefix is not yet known when the symbolic link is created (e.g., in an archive file that can be unpacked anywhere).\n\n- Microsoft Windows application shortcuts contain additional metadata that can be associated with the destination, whereas POSIX symbolic links are just strings that will be interpreted as absolute or relative pathnames.\n\n- Unlike symbolic links, Windows shortcuts maintain their references to their targets even when the target is moved or renamed. Windows domain clients may subscribe to a Windows service called Distributed Link Tracking to track the changes in files and folders to which they are interested. The service maintains the integrity of shortcuts, even when files and folders are moved across the network.[14] Additionally, in Windows 9x and later, Windows shell tries to find the target of a broken shortcut before proposing to delete it.",
            insertText: 'ShortcutFile',
            range: range,
        }
        ,
        {
            label: 'Windows Shortcut File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A Microsoft Windows shortcut file.",
            insertText: 'WindowsShortcutFile',
            range: range,
        }
        ,
        {
            label: 'Log File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A log file is a file that records either events that occur in an operating system or other software runs, or messages between different users of a communication software. Logging is the act of keeping a log. In the simplest case, messages are written to a single log file.\n\nA transaction log is a file (i.e., log) of the communications between a system and the users of that system, or a data collection method that automatically captures the type, content, or time of transactions made by a person from a terminal with that system. For Web searching, a transaction log is an electronic record of interactions that have occurred during a searching episode between a Web search engine and users searching for information on that Web search engine.\n\nMany operating systems, software frameworks and programs include a logging system. A widely used logging standard is syslog, defined in Internet Engineering Task Force (IETF) RFC 5424). The syslog standard enables a dedicated, standardized subsystem to generate, filter, record, and analyze log messages. This relieves software developers of having to design and code their own ad hoc logging systems.",
            insertText: 'LogFile',
            range: range,
        }
        ,
        {
            label: 'Command History Log File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A command history log file is a file containing a command history, which the history of commands run in an operating system shell.",
            insertText: 'CommandHistoryLogFile',
            range: range,
        }
        ,
        {
            label: 'Operating System Log File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An operating system log file records events that occur in an operating system",
            insertText: 'OperatingSystemLogFile',
            range: range,
        }
        ,
        {
            label: 'Software Library File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A software library is a collection of software components that are used to build a software product.",
            insertText: 'SoftwareLibraryFile',
            range: range,
        }
        ,
        {
            label: 'Configuration File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A file containing Information used to configure the parameters and initial settings for some computer programs. They are used for user applications, server processes and operating system settings.",
            insertText: 'ConfigurationFile',
            range: range,
        }
        ,
        {
            label: 'Application Configuration File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A file containing Information used to configure the parameters and initial settings for an application.. A plist file is an example of this type of file for macOS.  Usually text-based.",
            insertText: 'ApplicationConfigurationFile',
            range: range,
        }
        ,
        {
            label: 'Compiler Configuration File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A file containing Information used to configure the parameters and initial settings for a compiler.",
            insertText: 'CompilerConfigurationFile',
            range: range,
        }
        ,
        {
            label: 'Operating System Configuration File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An operating system configuration file is a file used to configure the operating system.",
            insertText: 'OperatingSystemConfigurationFile',
            range: range,
        }
        ,
        {
            label: 'Property List File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In the OS X, iOS, NeXTSTEP, and GNUstep programming frameworks, property list files are files that store serialized objects. Property list files use the filename extension .plist, and thus are often referred to as p-list files. Property list files are often used to store a user's settings. They are also used to store information about bundles and applications, a task served by the resource fork in the old Mac OS.",
            insertText: 'PropertyListFile',
            range: range,
        }
        ,
        {
            label: 'Object File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An object file is a file that contains relocatable machine code.",
            insertText: 'ObjectFile',
            range: range,
        }
        ,
        {
            label: 'Kernel Module',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A loadable kernel module (LKM) is an object file that contains code to extend the running kernel, or so-called base kernel, of an operating system. LKMs are typically used to add support for new hardware (as device drivers) and/or filesystems, or for adding system calls. When the functionality provided by a LKM is no longer required, it can be unloaded in order to free memory and other resources.\n\nMost current Unix-like systems and Microsoft Windows support loadable kernel modules, although they might use a different name for them, such as kernel loadable module (kld) in FreeBSD, kernel extension (kext) in macOS,[1] kernel extension module in AIX, kernel-mode driver in Windows NT[2] and downloadable kernel module (DKM) in VxWorks. They are also known as kernel loadable modules (or KLM), and simply as kernel modules (KMOD).",
            insertText: 'KernelModule',
            range: range,
        }
        ,
        {
            label: 'Shared Library File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A shared library file is a file that is intended to be shared by executable files and further shared library (object) files. Modules used by a program are loaded from individual shared objects into memory at load time or runtime, rather than being copied by a linker when it creates a single monolithic executable file for the program",
            insertText: 'SharedLibraryFile',
            range: range,
        }
        ,
        {
            label: 'Operating System Shared Library File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An operating system shared library file is a shared library file that is part of the operating system and that incorporates common operating system code for use by any application or to provide operating system services.",
            insertText: 'OperatingSystemSharedLibraryFile',
            range: range,
        }
        ,
        {
            label: 'Archive File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An archive file is a file that is composed of one or more computer files along with metadata. Archive files are used to collect multiple data files together into a single file for easier portability and storage, or simply to compress files to use less storage space. Archive files often store directory structures, error detection and correction information, arbitrary comments, and sometimes use built-in encryption.",
            insertText: 'ArchiveFile',
            range: range,
        }
        ,
        {
            label: 'Custom Archive File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A custom archive file is an archive file conforming to a custom format; that is, an archive file that does not conform to a common standard.",
            insertText: 'CustomArchiveFile',
            range: range,
        }
        ,
        {
            label: 'Certificate File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A file containing a digital certificate. In cryptography, a public key certificate (also known as a digital certificate or identity certificate) is an electronic document used to prove the ownership of a public key. The certificate includes information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate with its owner.",
            insertText: 'CertificateFile',
            range: range,
        }
        ,
        {
            label: 'CA Certificate File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A file containing a digital certificate issued by a certificate authority (CA).  Certificate authorities store, issue, and sign digital certificates used as part of the public key infrastructure.",
            insertText: 'CACertificateFile',
            range: range,
        }
        ,
        {
            label: 'Operating System File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An operating system file is a file that is part of, or used to store information about, the operating system itself.",
            insertText: 'OperatingSystemFile',
            range: range,
        }
        ,
        {
            label: 'Operating System Executable File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An operating system executable is a critical executable that is part of the operating system, and without which, the operating system may not operate correctly.",
            insertText: 'OperatingSystemExecutableFile',
            range: range,
        }
        ,
        {
            label: 'Document File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A document is a written, drawn, presented or recorded representation of thoughts. An electronic document file is usually used to describe a primarily textual file, along with its structure and design, such as fonts, colors and additional images.",
            insertText: 'DocumentFile',
            range: range,
        }
        ,
        {
            label: 'Email Attachment',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An email attachment is a computer file sent along with an email message. One or more files can be attached to any email message, and be sent along with it to the recipient. This is typically used as a simple method to share documents and images.",
            insertText: 'EmailAttachment',
            range: range,
        }
        ,
        {
            label: 'Multimedia Document File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Digital video files which often contain audio.",
            insertText: 'MultimediaDocumentFile',
            range: range,
        }
        ,
        {
            label: 'HTML File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A document file encoded in HTML.The HyperText Markup Language, or HTML is the standard markup language for documents designed to be displayed in a web browser. It can be assisted by technologies such as Cascading Style Sheets (CSS) and scripting languages such as JavaScript. Web browsers receive HTML documents from a web server or from local storage and render the documents into multimedia web pages. HTML describes the structure of a web page semantically and originally included cues for the appearance of the document.",
            insertText: 'HTMLFile',
            range: range,
        }
        ,
        {
            label: 'Office Application File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A document file in a format associated with an d3f:OfficeApplication.",
            insertText: 'OfficeApplicationFile',
            range: range,
        }
        ,
        {
            label: 'Email',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An email, or email message, is a document that is sent between computer users across computer networks.",
            insertText: 'Email',
            range: range,
        }
        ,
        {
            label: 'Executable File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, executable code or an executable file or executable program, sometimes simply an executable, causes a computer \"to perform indicated tasks according to encoded instructions,\" as opposed to a data file that must be parsed by a program to be meaningful. These instructions are traditionally machine code instructions for a physical CPU. However, in a more general sense, a file containing instructions (such as bytecode) for a software interpreter may also be considered executable; even a scripting language source file may therefore be considered executable in this sense. The exact interpretation depends upon the use; while the term often refers only to machine code files, in the context of protection against computer viruses all files which cause potentially hazardous instruction",
            insertText: 'ExecutableFile',
            range: range,
        }
        ,
        {
            label: 'Executable Binary',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An executable binary contains machine code instructions for a physical CPU. D3FEND also considers byte code for a virtual machine to be binary code.  This is in contrast to executable scripts written in a scripting language.",
            insertText: 'ExecutableBinary',
            range: range,
        }
        ,
        {
            label: 'Executable Script',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An executable script is written in a scripting language and interpreted at run time. This is in contrast with an executable binary, which contains machine code instructions for a physical CPU or byte code for a virtual machine.",
            insertText: 'ExecutableScript',
            range: range,
        }
        ,
        {
            label: 'Init Script',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An init script (or initialization script) is an executable script that initializes the an application, a process, or a service's state.  Examples include scripts run at boot by Unix or Windows, or those run to initialize a shell.",
            insertText: 'InitScript',
            range: range,
        }
        ,
        {
            label: 'Web Script File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A file containing a script in a web-scripting programming language. Web scripts may be present and run on the client or on the server side.",
            insertText: 'WebScriptFile',
            range: range,
        }
        ,
        {
            label: 'Credential',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A credential is a physical/tangible object, a piece of knowledge, or a facet of a person's physical being that enables an individual access to a given physical facility or computer-based information system. Typically, credentials can be something a person knows (such as a number or PIN), something they have (such as an access badge), something they are (such as a biometric feature), something they do (measurable behavioral patterns) or some combination of these items. This is known as multi-factor authentication. The typical credential is an access card or key-fob, and newer software can also turn users' smartphones into access devices.",
            insertText: 'Credential',
            range: range,
        }
        ,
        {
            label: 'Session Cookie',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A session cookie, also known as an in-memory cookie, transient cookie or non-persistent cookie, exists only in temporary memory while the user navigates the website. Web browsers normally delete session cookies when the user closes the browser. Unlike other cookies, session cookies do not have an expiration date assigned to them, which is how the browser knows to treat them as session cookies.",
            insertText: 'SessionCookie',
            range: range,
        }
        ,
        {
            label: 'Encrypted Credential',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A credential that is encrypted.",
            insertText: 'EncryptedCredential',
            range: range,
        }
        ,
        {
            label: 'Password',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A password, sometimes called a passcode, is a memorized secret, typically a string of characters, usually used to confirm the identity of a user. Using the terminology of the NIST Digital Identity Guidelines, the secret is memorized by a party called the claimant while the party verifying the identity of the claimant is called the verifier. When the claimant successfully demonstrates knowledge of the password to the verifier through an established authentication protocol, the verifier is able to infer the claimant's identity.",
            insertText: 'Password',
            range: range,
        }
        ,
        {
            label: 'Access Token',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computer systems, an access token contains the security credentials for a login session and identifies the user, the user's groups, the user's privileges, and, in some cases, a particular application. Typically one may be asked to enter the access token (e.g. 40 random characters) rather than the usual password (it therefore should be kept secret just like a password).",
            insertText: 'AccessToken',
            range: range,
        }
        ,
        {
            label: 'Ticket Granting Ticket',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In some computer security systems, a Ticket Granting Ticket or Ticket to Get Tickets (TGT) is a small, encrypted identification file with a limited validity period. After authentication, this file is granted to a user for data traffic protection by the key distribution center (KDC) subsystem of authentication services such as Kerberos. The TGT file contains the session key, its expiration date, and the user's IP address, which protects the user from man-in-the-middle attacks. The TGT is used to obtain a service ticket from Ticket Granting Service (TGS). User is granted access to network services only after this service ticket is provided.",
            insertText: 'TicketGrantingTicket',
            range: range,
        }
        ,
        {
            label: 'Kerberos Ticket Granting Ticket',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A ticket granting ticket issued by a Kerberos system; that is, a ticket that grants a user domain admin access.",
            insertText: 'KerberosTicketGrantingTicket',
            range: range,
        }
        ,
        {
            label: 'Kerberos Ticket',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An access ticket/token issued by a Kerberos system.",
            insertText: 'KerberosTicket',
            range: range,
        }
        ,
        {
            label: 'Kerberos Ticket Granting Service Ticket',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A Kerberos ticket-granting service (TGS) ticket is given in response to requesting a Kerberos TGS request.",
            insertText: 'KerberosTicketGrantingServiceTicket',
            range: range,
        }
        ,
        {
            label: 'Software',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Computer software, or simply software, is that part of a computer system that consists of encoded information or computer instructions, in contrast to the physical hardware from which the system is built.",
            insertText: 'Software',
            range: range,
        }
        ,
        {
            label: 'Software Library',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A software library is a collection of software components that are used to build a software product.",
            insertText: 'SoftwareLibrary',
            range: range,
        }
        ,
        {
            label: 'Software Patch',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A patch is a piece of software designed to update a computer program or its supporting data, to fix or improve it. This includes fixing security vulnerabilities and other bugs, with such patches usually called bugfixes or bug fixes, and improving the usability or performance. Although meant to fix problems, poorly designed patches can sometimes introduce new problems (see software regressions). In some special cases updates may knowingly break the functionality, for instance, by removing components for which the update provider is no longer licensed or disabling a device.",
            insertText: 'SoftwarePatch',
            range: range,
        }
        ,
        {
            label: 'Utility Software',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Utility applications are software applications designed to help to analyze, configure, optimize or maintain a computer. It is used to support the computer infrastructure - in contrast to application software, which is aimed at directly performing tasks that benefit ordinary users. However, utilities often form part of the application systems. For example, a batch job may run user-written code to update a database and may then include a step that runs a utility to back up the database, or a job may run a utility to compress a disk before copying files.",
            insertText: 'UtilitySoftware',
            range: range,
        }
        ,
        {
            label: 'System Time Application',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A system time utility is utility software that can get the system time, such as the Unix date command or Windows' Net utility.",
            insertText: 'SystemTimeApplication',
            range: range,
        }
        ,
        {
            label: 'System Software',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Computer software which enables operating system or platform functionality.",
            insertText: 'SystemSoftware',
            range: range,
        }
        ,
        {
            label: 'Host-based Firewall',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A software firewall which controls network inbound and outbound network traffic to the host computer.",
            insertText: 'Host-basedFirewall',
            range: range,
        }
        ,
        {
            label: 'Kernel',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The kernel is a computer program that constitutes the central core of a computer's operating system. It has complete control over everything that occurs in the system. As such, it is the first program loaded on startup, and then manages the remainder of the startup, as well as input/output requests from software, translating them into data processing instructions for the central processing unit. It is also responsible for managing memory, and for managing and communicating with computing peripherals, like printers, speakers, etc. The kernel is a fundamental part of a modern computer's operating system.",
            insertText: 'Kernel',
            range: range,
        }
        ,
        {
            label: 'Shim',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computer programming, a shim is a small library that transparently intercepts API calls and changes the arguments passed, handles the operation itself, or redirects the operation elsewhere. Shims can be used to support an old API in a newer environment, or a new API in an older environment. Shims can also be used for running programs on different software platforms than those for which they were developed.",
            insertText: 'Shim',
            range: range,
        }
        ,
        {
            label: 'Application Shim',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An application shim adapts an application program to run on a version of a platform for which they were not originally created. Most commonly \"Application Shimming\" refers to use of The Windows Application Compatibility Toolkit (ACT) provides backward compatibility by simulating the behavior of older version of Windows.",
            insertText: 'ApplicationShim',
            range: range,
        }
        ,
        {
            label: 'Network Agent',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A network agent is software installed on a network node or device that transmits information back to a collector agent or management system.  Kinds of network agents include SNMP Agent, IPMI agents, WBEM agents, and many proprietary agents capturing network monitoring and management information.",
            insertText: 'CollectorAgent',
            range: range,
        }
        ,
        {
            label: 'System Service Software',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Software services provided as part of the operating system, typically accessed through system calls.",
            insertText: 'SystemServiceSoftware',
            range: range,
        }
        ,
        {
            label: 'Local Authentication Service',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A local authentication service running on a host can authenticate a user logged into just that local host computer.",
            insertText: 'LocalAuthenticationService',
            range: range,
        }
        ,
        {
            label: 'Local Authorization Service',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A local authorization service running on a host can authorize a user logged into just that local host computer.",
            insertText: 'LocalAuthorizationService',
            range: range,
        }
        ,
        {
            label: 'Job Scheduler Software',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A job scheduler software is operating system software that when run executes scheduled tasks (time-scheduling in the sense of wall clock time; not operating system scheduling of processes for multitasking). Processes running such software are task scheduler processes. In Windows, Scheduled Tasks are created and managed by the Task Scheduler. In Unix-like OSes, the `cron` utitility serves a similar role.",
            insertText: 'JobSchedulerSoftware',
            range: range,
        }
        ,
        {
            label: 'Application',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A program that gives a computer instructions that provide the user with tools to accomplish a task; \"he has tried several different word processing applications\".  Distinct from system software that is intrinsically part of the operating system.  An application can be made up of executable files, configuration files, shared libraries, etc.",
            insertText: 'Application',
            range: range,
        }
        ,
        {
            label: 'Password Manager',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A password manager is a software application or hardware that helps a user store and organize passwords. Password managers usually store passwords encrypted, requiring the user to create a master password: a single, ideally very strong password which grants the user access to their entire password database. Some password managers store passwords on the user's computer (called offline password managers), whereas others store data in the provider's cloud (often called online password managers). However offline password managers also offer data storage in the user's own cloud accounts rather than the provider's cloud. While the core functionality of a password manager is to securely store large collections of passwords, many provide additional features such as form filling and password generation.",
            insertText: 'PasswordManager',
            range: range,
        }
        ,
        {
            label: 'Client Application',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A client application is software that accesses a service made available by a server. The server is often (but not always) on another computer system, in which case the client accesses the service by way of a network. The term applies to the role that programs or devices play in the client-server model",
            insertText: 'ClientApplication',
            range: range,
        }
        ,
        {
            label: 'User Application',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A user application is executed for that an individual user on a user's personal computer or remotely by means of virtualization.  This is in contrast to service applications or enterprise software.",
            insertText: 'UserApplication',
            range: range,
        }
        ,
        {
            label: 'Browser',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A web browser (commonly referred to as a browser) is a software application for retrieving, presenting, and traversing information resources on the World Wide Web. An information resource is identified by a Uniform Resource Identifier (URI/URL) and may be a web page, image, video or other piece of content. Hyperlinks present in resources enable users easily to navigate their browsers to related resources. Although browsers are primarily intended to use the World Wide Web, they can also be used to access information provided by web servers in private networks or files in file systems.",
            insertText: 'Browser',
            range: range,
        }
        ,
        {
            label: 'Office Application',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An office application is one that is part of an application suite (e.g., Microsoft Office, Open Office).",
            insertText: 'OfficeApplication',
            range: range,
        }
        ,
        {
            label: 'Collaborative Software',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Collaborative software or groupware is application software designed to help people working on a common task to attain their goals. One of the earliest definitions of groupware is \"intentional group processes plus software to support them\". Collaborative software is a broad concept that overlaps considerably with computer-supported cooperative work (CSCW). According to Carstensen and Schmidt (1999) groupware is part of CSCW. The authors claim that CSCW, and thereby groupware, addresses \"how collaborative activities and their coordination can be supported by means of computer systems.\"",
            insertText: 'CollaborativeSoftware',
            range: range,
        }
        ,
        {
            label: 'Business Communication Platform Client',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Client software to enable the process of sharing information between employees within and outside a company.  Business communication encompasses topics such as marketing, brand management, customer relations, consumer behavior, advertising, public relations, corporate communication, community engagement, reputation management, interpersonal communication, employee engagement, and event management. It is closely related to the fields of professional communication and technical communication.",
            insertText: 'BusinessCommunicationPlatformClient',
            range: range,
        }
        ,
        {
            label: 'Chatroom Client',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Client software used to describe conduct any form of synchronous conferencing, occasionally even asynchronous conferencing. The term can thus mean any technology ranging from real-time online chat and online interaction with strangers (e.g., online forums) to fully immersive graphical social environments.",
            insertText: 'ChatroomClient',
            range: range,
        }
        ,
        {
            label: 'Instant Messaging Client',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Client software used to engage in Instant Messaging, a type of online chat that offers real-time text transmission over the Internet. A LAN messenger operates in a similar way over a local area network. Short messages are typically transmitted between two parties, when each user chooses to complete a thought and select \"send\". Some IM applications can use push technology to provide real-time text, which transmits messages character by character, as they are composed. More advanced instant messaging can add file transfer, clickable hyperlinks, Voice over IP, or video chat.",
            insertText: 'InstantMessagingClient',
            range: range,
        }
        ,
        {
            label: 'Browser Extension',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A browser extension is a plug-in that extends the functionality of a web browser in some way. Some extensions are authored using web technologies such as HTML, JavaScript, and CSS. Browser extensions can change the user interface of the web browser without directly affecting viewable content of a web page; for example, by adding a \"toolbar.\"",
            insertText: 'BrowserExtension',
            range: range,
        }
        ,
        {
            label: 'Developer Application',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An application used to develop computer software including applications used for software construction, analysis, testing, packaging, or management.",
            insertText: 'DeveloperApplication',
            range: range,
        }
        ,
        {
            label: 'Network Traffic Analysis Software',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A packet analyzer, also known as packet sniffer, protocol analyzer, or network analyzer, is a computer program or computer hardware such as a packet capture appliance, that can intercept and log traffic that passes over a computer network or part of a network.",
            insertText: 'NetworkTrafficAnalysisSoftware',
            range: range,
        }
        ,
        {
            label: 'Version Control Tool',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Version control tools are tools that used to conduct version control. A  component of software configuration management, version control, also known as revision control, source control, or source code management systems are systems responsible for the management of changes to documents, computer programs, large web sites, and other collections of information. Changes are usually identified by a number or letter code, termed the \"revision number\", \"revision level\", or simply \"revision\". For example, an initial set of files is \"revision 1\". When the first change is made, the resulting set is \"revision 2\", and so on. Each revision is associated with a timestamp and the person making the change. Revisions can be compared, restored, and with some types of files, merged.",
            insertText: 'VersionControlTool',
            range: range,
        }
        ,
        {
            label: 'Build Tool',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A tool that automates the process of creating a software build and the associated processes including: compiling computer source code into binary code, packaging binary code, and running automated tests.",
            insertText: 'BuildTool',
            range: range,
        }
        ,
        {
            label: 'Compiler',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a compiler is a computer program that translates computer code written in one programming language (the source language) into another language (the target language). The name \"compiler\" is primarily used for programs that translate source code from a high-level programming language to a lower level language (e.g., assembly language, object code, or machine code) to create an executable program.",
            insertText: 'Compiler',
            range: range,
        }
        ,
        {
            label: 'Software Packaging Tool',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A tool that automates the process of packaging either or both binary code  and source code for use on one or more target platforms.",
            insertText: 'SoftwarePackagingTool',
            range: range,
        }
        ,
        {
            label: 'Container Build Tool',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A software build tool that creates a container (e.g., Docker container) for deployment.",
            insertText: 'ContainerBuildTool',
            range: range,
        }
        ,
        {
            label: 'Operating System Packaging Tool',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A software packaging tool oriented on building a software package for a particular operating system (e.g. rpmbuild.)",
            insertText: 'OperatingSystemPackagingTool',
            range: range,
        }
        ,
        {
            label: 'Code Analyzer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Code analyzers automatically analyze the composition or behavior of computer programs regarding a property such as correctness, robustness, security, and safety. Program analysis can be performed without executing the program (static program analysis), during runtime (dynamic program analysis) or in a combination of both.",
            insertText: 'CodeAnalyzer',
            range: range,
        }
        ,
        {
            label: 'Dynamic Analysis Tool',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Dynamic program analysis is the analysis of computer software that is performed by executing programs on a real or virtual processor.",
            insertText: 'DynamicAnalysisTool',
            range: range,
        }
        ,
        {
            label: 'Static Analysis Tool',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A static [program] analysis tool performs an automated analysis of computer software without actually executing programs, in contrast with dynamic analysis, which is analysis performed on programs while they are executing. In most cases the analysis is performed on some version of the source code, and in the other cases, some form of the object code.",
            insertText: 'StaticAnalysisTool',
            range: range,
        }
        ,
        {
            label: 'Source Code Analyzer Tool',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A source code analyzer tool is a static analysis tool that operates specifically on source code, but not object code.",
            insertText: 'SourceCodeAnalyzerTool',
            range: range,
        }
        ,
        {
            label: 'Test Execution Tool',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A test execution tool is a type of software used to test software, hardware or complete systems.  Synonyms of test execution tool include test execution engine, test executive, test manager, test sequencer.  Two common forms in which a test execution engine may appear are as a: (a) module of a test software suite (test bench) or an integrated development environment, or (b) stand-alone application software.",
            insertText: 'TestExecutionTool',
            range: range,
        }
        ,
        {
            label: 'Integration Test Execution Tool',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An integration test execution tool automatically performs integration testing.  Integration testing (sometimes called integration and testing, abbreviated I&T) is the phase in software testing in which individual software modules are combined and tested as a group.",
            insertText: 'IntegrationTestExecutionTool',
            range: range,
        }
        ,
        {
            label: 'Unit Test Execution Tool',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An unit test execution tool automatically performs unit testing.  Unit testing is a software testing method by which individual units of source code are tested to determine whether they are fit for use.  Unit test execution tools work with sets of one or more computer program modules together with associated control data, usage procedures, and operating procedures. This contrasts with integration testing, which tests inter-unit dependencies and the modules as a group.",
            insertText: 'UnitTestExecutionTool',
            range: range,
        }
        ,
        {
            label: 'Service Application',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An application that provides a set of software functionalities so that multiple clients who can reuse the functionality, provided they are authorized for use of the service.",
            insertText: 'ServiceApplication',
            range: range,
        }
        ,
        {
            label: 'Container Runtime',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A software layer between d3f:ContainerProcess and d3f:Kernel which often mediates the invocation of d3f:SystemCall",
            insertText: 'ContainerRuntime',
            range: range,
        }
        ,
        {
            label: 'Container Orchestration Software',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A d3f:Software which manages and coordinates running one or more d3f:ContainerProcess.",
            insertText: 'ContainerOrchestrationSoftware',
            range: range,
        }
        ,
        {
            label: 'Credential Management System',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Credential Management, also referred to as a Credential Management System (CMS), is an established form of software that is used for issuing and managing credentials as part of public key infrastructure (PKI).",
            insertText: 'CredentialManagementSystem',
            range: range,
        }
        ,
        {
            label: 'Software Deployment Tool',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Software that coordinates the deployment process of software to systems, typically remotely.",
            insertText: 'SoftwareDeploymentTool',
            range: range,
        }
        ,
        {
            label: 'Web Server Application',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A web server application (or web app) is an application software that runs on a web server, unlike computer-based software programs that are stored locally on the Operating System (OS) of the device. Web applications are accessed by the user through a web browser with an active internet connection. These applications are programmed using a client-server modeled structure-the user (\"client\") is provided services through an off-site server that is hosted by a third-party. Examples of commonly-used, web applications, include: web-mail, online retail sales, online banking, and online auctions.",
            insertText: 'WebServerApplication',
            range: range,
        }
        ,
        {
            label: 'Virtualization Software',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Virtualization software allows a single host computer to create and run one or more virtual environments. Virtualization software is most often used to emulate a complete computer system in order to allow a guest operating system to be run, for example allowing Linux to run as a guest on top of a PC that is natively running a Microsoft Windows operating system (or the inverse, running Windows as a guest on Linux).",
            insertText: 'VirtualizationSoftware',
            range: range,
        }
        ,
        {
            label: 'Firmware',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In electronic systems and computing, firmware is a type of software that provides control, monitoring and data manipulation of engineered products and systems. Typical examples of devices containing firmware are embedded systems (such as traffic lights, consumer appliances, remote controls and digital watches), computers, computer peripherals, mobile phones, and digital cameras. The firmware contained in these devices provides the low-level control program for the device.",
            insertText: 'Firmware',
            range: range,
        }
        ,
        {
            label: 'Microcode',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Microcode is a computer hardware technique that interposes a layer of organization between the CPU hardware and the programmer-visible instruction set architecture of the computer. As such, the microcode is a layer of hardware-level instructions that implement higher-level machine code instructions or internal state machine sequencing in many digital processing elements.",
            insertText: 'Microcode',
            range: range,
        }
        ,
        {
            label: 'System Firmware',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Firmware that is installed on a computer's main board which manages the initial boot process. It can also continue to run or function after the operating system boots.",
            insertText: 'SystemFirmware',
            range: range,
        }
        ,
        {
            label: 'Peripheral Firmware',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Firmware that is installed on computer peripheral devices.",
            insertText: 'PeripheralFirmware',
            range: range,
        }
        ,
        {
            label: 'Graphics Card Firmware',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Firmware that is installed on computer graphics card.",
            insertText: 'GraphicsCardFirmware',
            range: range,
        }
        ,
        {
            label: 'Hard Disk Firmware',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Firmware that is installed on a hard disk device.",
            insertText: 'HardDiskFirmware',
            range: range,
        }
        ,
        {
            label: 'Human Input Device Firmware',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Firmware that is installed on an HCI device such as a mouse or keyboard.",
            insertText: 'HumanInputDeviceFirmware',
            range: range,
        }
        ,
        {
            label: 'Network Card Firmware',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Firmware that is installed on a network card (network interface controller).",
            insertText: 'NetworkCardFirmware',
            range: range,
        }
        ,
        {
            label: 'Peripheral Hub Firmware',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Firmware that is installed on peripheral hub device such as a USB or Firewire hub.",
            insertText: 'PeripheralHubFirmware',
            range: range,
        }
        ,
        {
            label: 'Linux Connect',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Initiate a connection on a socket.",
            insertText: 'LinuxConnect',
            range: range,
        }
        ,
        {
            label: 'Linux Socket',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Create an endpoint for communication.",
            insertText: 'LinuxSocket',
            range: range,
        }
        ,
        {
            label: 'Linux Execve',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Executes a program by replacing the calling process with a new program, with newly initialized stack, heap, and (initialized and uninitialized) data segments. The PID stays the same.",
            insertText: 'LinuxExecve',
            range: range,
        }
        ,
        {
            label: 'Linux Execveat',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Execute program relative to a directory file descriptor. Behavior is similar to Linux Execve.",
            insertText: 'LinuxExecveat',
            range: range,
        }
        ,
        {
            label: 'Linux Munmap',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Unmap files or devices from memory.",
            insertText: 'LinuxMunmap',
            range: range,
        }
        ,
        {
            label: 'Linux Time',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Get time in seconds.",
            insertText: 'LinuxTime',
            range: range,
        }
        ,
        {
            label: 'Windows NtQuerySystemTime',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Returns current time in Coordinated Universal Time (UTC) 8-bytes format.",
            insertText: 'WindowsNtQuerySystemTime',
            range: range,
        }
        ,
        {
            label: 'Linux Pause Thread',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Causes the calling thread to sleep until a signal is delivered that either terminates the thread or causes the invocation of a signal-catching function.",
            insertText: 'LinuxPauseThread',
            range: range,
        }
        ,
        {
            label: 'Linux Ptrace Argument PTRACE_TRACEME',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Indicates that the process is to be traced by its parent.",
            insertText: 'LinuxPtraceArgumentPTRACE_TRACEME',
            range: range,
        }
        ,
        {
            label: 'Windows NtOpenProcess',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Opens a handle to process obj and sets the access rights to this object.",
            insertText: 'WindowsNtOpenProcess',
            range: range,
        }
        ,
        {
            label: 'Linux Rename',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Change the name or location of a file",
            insertText: 'LinuxRename',
            range: range,
        }
        ,
        {
            label: 'Linux Renameat',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Change the name or location of a file. Different parameter handling than Linux Rename.",
            insertText: 'LinuxRenameat',
            range: range,
        }
        ,
        {
            label: 'Linux Renameat2',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Change the name or location of a file. Additional flags argument.",
            insertText: 'LinuxRenameat2',
            range: range,
        }
        ,
        {
            label: 'Linux Pause Process',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Causes the calling process to sleep until a signal is delivered that either terminates the process or causes the invocation of a signal-catching function.",
            insertText: 'LinuxPauseProcess',
            range: range,
        }
        ,
        {
            label: 'Linux Ptrace Argument PTRACE_INTERRUPT',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Stops a tracee.",
            insertText: 'LinuxPtraceArgumentPTRACEINTERRUPT',
            range: range,
        }
        ,
        {
            label: 'Linux Kill Argument SIGKILL',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Send SIGKILL signal to a process.",
            insertText: 'LinuxKillArgumentSIGKILL',
            range: range,
        }
        ,
        {
            label: 'Linux _Exit',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Terminate the calling process.",
            insertText: 'Linux_Exit',
            range: range,
        }
        ,
        {
            label: 'Linux Mmap',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Map files or devices into memory.",
            insertText: 'LinuxMmap',
            range: range,
        }
        ,
        {
            label: 'Linux Mmap2',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Map files or devices into memory.",
            insertText: 'LinuxMmap2',
            range: range,
        }
        ,
        {
            label: 'Linux Clone3 Argument CLONE_THREAD',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A flag parameter to the Clone3 syscall. If set, the child is placed in the same thread group as the calling process.",
            insertText: 'LinuxClone3ArgumentCLONE_THREAD',
            range: range,
        }
        ,
        {
            label: 'Linux Clone Argument CLONE_THREAD',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A flag parameter to the Clone syscall. If set, the child is placed in the same thread group as the calling process.",
            insertText: 'LinuxCloneArgumentCLONE_THREAD',
            range: range,
        }
        ,
        {
            label: 'Linux Unlink',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Delete a name and possibly the file it refers to.",
            insertText: 'LinuxUnlink',
            range: range,
        }
        ,
        {
            label: 'Linux Unlinkat',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Delete a name and possibly the file it refers to. Different parameter handling than Linux Unlink",
            insertText: 'LinuxUnlinkat',
            range: range,
        }
        ,
        {
            label: 'Windows NtDeleteFile',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Deletes the specified file.",
            insertText: 'WindowsNtDeleteFile',
            range: range,
        }
        ,
        {
            label: 'Windows NtSetInformationFile Argument FileDispositionInformation',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Request to delete the file when it is closed or cancel a previously requested deletion.",
            insertText: 'WindowsNtSetInformationFileArgumentFileDispositionInformation',
            range: range,
        }
        ,
        {
            label: 'Linux Open Argument O_RDONLY, O_WRONLY, O_RDWR',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Opens a file specified by pathname.",
            insertText: 'LinuxOpenArgumentO_RDONLY-O_WRONLY-O_RDWR',
            range: range,
        }
        ,
        {
            label: 'Linux OpenAt2 Argument O_RDONLY, O_WRONLY, O_RDWR',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Extension of Linux Openat.",
            insertText: 'LinuxOpenAt2ArgumentO_RDONLY-O_WRONLY-O_RDWR',
            range: range,
        }
        ,
        {
            label: 'Linux OpenAt Argument O_RDONLY, O_WRONLY, O_RDWR',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Same functionality as Linux Open but slight differences in parameter.",
            insertText: 'LinuxOpenAtArgumentO_RDONLY-O_WRONLY-O_RDWR',
            range: range,
        }
        ,
        {
            label: 'Linux Read',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Read from a file descriptor.",
            insertText: 'LinuxRead',
            range: range,
        }
        ,
        {
            label: 'Linux Readv',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Read data into multiple buffers.",
            insertText: 'LinuxReadv',
            range: range,
        }
        ,
        {
            label: 'Windows NtReadFileScatter',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Reads specified block from file into multiple buffers. Each buffer must have one page length.",
            insertText: 'WindowsNtReadFileScatter',
            range: range,
        }
        ,
        {
            label: 'Linux Write',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Write to a file descriptor.",
            insertText: 'LinuxWrite',
            range: range,
        }
        ,
        {
            label: 'Linux Writev',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Write data into multiple buffers.",
            insertText: 'LinuxWritev',
            range: range,
        }
        ,
        {
            label: 'Windows NtWriteFileGather',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Writes specified block of file with data from memory pages.",
            insertText: 'WindowsNtWriteFileGather',
            range: range,
        }
        ,
        {
            label: 'Linux Clone',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Creates a child process and provides more precise control over the data shared between the parent and child processes",
            insertText: 'LinuxClone',
            range: range,
        }
        ,
        {
            label: 'Linux Clone3',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Creates a child process and provides more precise control over the data shared between the parent and child processes.\n\nNewer system call.",
            insertText: 'LinuxClone3',
            range: range,
        }
        ,
        {
            label: 'Linux Fork',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Creates a child process with unique PID but retains parent PID as Parent Process Identifier (PPID)",
            insertText: 'LinuxFork',
            range: range,
        }
        ,
        {
            label: 'Linux Vfork',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Create child process that temp suspends parent process until it terminates",
            insertText: 'LinuxVfork',
            range: range,
        }
        ,
        {
            label: 'Linux Creat',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Equivalent to calling Linux Open with flags equal to O_CREAT|O_WRONLY|O_TRUNC.",
            insertText: 'LinuxCreat',
            range: range,
        }
        ,
        {
            label: 'Linux Open Argument O_CREAT',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Create a regular file.",
            insertText: 'LinuxOpenArgumentO_CREAT',
            range: range,
        }
        ,
        {
            label: 'Linux OpenAt2 Argument O_CREAT',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Create a regular file. Extension of Linux Openat.",
            insertText: 'LinuxOpenAt2ArgumentO_CREAT',
            range: range,
        }
        ,
        {
            label: 'Linux OpenAt Argument O_CREAT',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Create a regular file. Same functionality as Linux Open but slight differences in parameter.",
            insertText: 'LinuxOpenAtArgumentO_CREAT',
            range: range,
        }
        ,
        {
            label: 'Windows NtCreateMailslotFile',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Creates a special File Object called Mailslot.",
            insertText: 'WindowsNtCreateMailslotFile',
            range: range,
        }
        ,
        {
            label: 'Windows NtCreateNamedPipeFile',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Creates Named Pipe File Object.",
            insertText: 'WindowsNtCreateNamedPipeFile',
            range: range,
        }
        ,
        {
            label: 'Windows NtCreatePagingFile',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Typically used by Control Panel's \"System\" applet for creating new paged files.",
            insertText: 'WindowsNtCreatePagingFile',
            range: range,
        }
        ,
        {
            label: 'Subroutine',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In different programming languages, a subroutine may be called a procedure, a function, a routine, a method, or a subprogram. The generic term callable unit is sometimes used.",
            insertText: 'Subroutine',
            range: range,
        }
        ,
        {
            label: 'Console Output Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Outputs characters to a computer console.",
            insertText: 'ConsoleOutputFunction',
            range: range,
        }
        ,
        {
            label: 'Copy Memory Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Copies a memory block from one location to another.",
            insertText: 'CopyMemoryFunction',
            range: range,
        }
        ,
        {
            label: 'Exception Handler',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An exception handler is a code segment that processes an exception.",
            insertText: 'ExceptionHandler',
            range: range,
        }
        ,
        {
            label: 'File Path Open Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Has an input of a file path, and opens a file handle for reading or writing.",
            insertText: 'FilePathOpenFunction',
            range: range,
        }
        ,
        {
            label: 'Import Library Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Loads an external software library to enable the invocations of its methods.",
            insertText: 'ImportLibraryFunction',
            range: range,
        }
        ,
        {
            label: 'Log Message Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Produces an entry in a log.",
            insertText: 'LogMessageFunction',
            range: range,
        }
        ,
        {
            label: 'Memory Allocation Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Reserves memory for a running process to use.",
            insertText: 'MemoryAllocationFunction',
            range: range,
        }
        ,
        {
            label: 'Memory Free Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Releases previously reserved memory associated with a process.",
            insertText: 'MemoryFreeFunction',
            range: range,
        }
        ,
        {
            label: 'Serialization Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A function which has an operation that serializes data.",
            insertText: 'SerializationFunction',
            range: range,
        }
        ,
        {
            label: 'String Format Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A function which creates a new string based on a format specification and correspondingi specified values.",
            insertText: 'StringFormatFunction',
            range: range,
        }
        ,
        {
            label: 'Thread Start Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A function which invokes a create thread system call.",
            insertText: 'ThreadStartFunction',
            range: range,
        }
        ,
        {
            label: 'Input Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Generic function that receives input from an untrusted source.",
            insertText: 'InputFunction',
            range: range,
        }
        ,
        {
            label: 'User Input Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Generic function that receives direct user input from an untrusted source.",
            insertText: 'UserInputFunction',
            range: range,
        }
        ,
        {
            label: 'Deserialization Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Function with an input of serialized data which deserializes that data, usually with data parsing methods.",
            insertText: 'DeserializationFunction',
            range: range,
        }
        ,
        {
            label: 'External Content Inclusion Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "External content, strings or data, are inserted into a local document (e.g. xml document) as if it were a native part of that document.",
            insertText: 'ExternalContentInclusionFunction',
            range: range,
        }
        ,
        {
            label: 'Mathematical Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Computes mathematical expressions.",
            insertText: 'MathematicalFunction',
            range: range,
        }
        ,
        {
            label: 'Pointer Dereferencing Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A function which has an operation which dereferences a pointer.",
            insertText: 'PointerDereferencingFunction',
            range: range,
        }
        ,
        {
            label: 'Process Start Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A function creates a new computer process, usually by invoking a create process system call.",
            insertText: 'ProcessStartFunction',
            range: range,
        }
        ,
        {
            label: 'Shared Resource Access Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A function which access a shared resource.",
            insertText: 'SharedResourceAccessFunction',
            range: range,
        }
        ,
        {
            label: 'Stored Procedure',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A stored procedure (also termed proc, storp, sproc, StoPro, StoredProc, StoreProc, sp, or SP) is a subroutine available to applications that access a relational database management system (RDBMS). Such procedures are stored in the database data dictionary.",
            insertText: 'StoredProcedure',
            range: range,
        }
        ,
        {
            label: 'Authentication Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Authenticates a user account by verifying a presented credential.",
            insertText: 'AuthenticationFunction',
            range: range,
        }
        ,
        {
            label: 'Eval Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Takes inputs of strings and evaluations them as expressions.",
            insertText: 'EvalFunction',
            range: range,
        }
        ,
        {
            label: 'Raw Memory Access Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A function which accesses raw memory, usually using memory addresses.",
            insertText: 'RawMemoryAccessFunction',
            range: range,
        }
        ,
        {
            label: 'Process',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A process is an instance of a computer program that is being executed. It contains the program code and its current activity. Depending on the operating system (OS), a process may be made up of multiple threads of execution that execute instructions concurrently. A computer program is a passive collection of instructions, while a process is the actual execution of those instructions. Several processes may be associated with the same program; for example, opening up several instances of the same program often means more than one process is being executed.",
            insertText: 'Process',
            range: range,
        }
        ,
        {
            label: 'Child Process',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A child process in computing is a process created by another process (the parent process). This technique pertains to multitasking operating systems, and is sometimes called a subprocess or traditionally a subtask. There are two major procedures for creating a child process: the fork system call (preferred in Unix-like systems and the POSIX standard) and the spawn (preferred in the modern (NT) kernel of Microsoft Windows, as well as in some historical operating systems).",
            insertText: 'ChildProcess',
            range: range,
        }
        ,
        {
            label: 'Parent Process',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a parent process is a process that has created one or more child processes.",
            insertText: 'ParentProcess',
            range: range,
        }
        ,
        {
            label: 'User Process',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A user process is a process running to perform functions in the name of on particular user and user account, such as run an application or application service serving any number users.  This is in contrast to a system process, which executes software to fulfill operating system functions.",
            insertText: 'UserProcess',
            range: range,
        }
        ,
        {
            label: 'Application Process',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An application process is an instance of an application computer program that is being executed.",
            insertText: 'ApplicationProcess',
            range: range,
        }
        ,
        {
            label: 'Container Process',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A running instance of a d3f:ContainerImage",
            insertText: 'ContainerProcess',
            range: range,
        }
        ,
        {
            label: 'Script Application Process',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A script application process is an application process interpreting an executable script.",
            insertText: 'ScriptApplicationProcess',
            range: range,
        }
        ,
        {
            label: 'Authorization Service',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An authorization service ensures that the user is authorized to have access to a particular resource. Authorization can be done through role-based access control (RBAC) or list-based access control (LBAC).",
            insertText: 'AuthorizationService',
            range: range,
        }
        ,
        {
            label: 'Remote Authorization Service',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A remote authorization service provides for the authorization of a user across a network (i.e., remotely).",
            insertText: 'RemoteAuthorizationService',
            range: range,
        }
        ,
        {
            label: 'Network Service',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computer networking, a network service is an application running at the network application layer and above, that provides data storage, manipulation, presentation, communication or other capability which is often implemented using a client-server or peer-to-peer architecture based on application layer network protocols. Clients and servers will often have a user interface, and sometimes other hardware associated with it.",
            insertText: 'NetworkService',
            range: range,
        }
        ,
        {
            label: 'File Share Service',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A file sharing service (or file share service) provides the ability to share data across a network.",
            insertText: 'FileShareService',
            range: range,
        }
        ,
        {
            label: 'Remote Authentication Service',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A remote authentication service provides for the authentication of a user across a network (i.e., remotely).",
            insertText: 'RemoteAuthenticationService',
            range: range,
        }
        ,
        {
            label: 'Mail Service',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A mail service provides the ability to send and receive mail across a computer network.  The mail service runs on message transfer agents (i.e., mail servers) and is accessed by users through an email client.",
            insertText: 'MailService',
            range: range,
        }
        ,
        {
            label: 'Message Transfer Agent',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A message transfer agent or mail transfer agent (MTA) or mail relay is software that transfers electronic mail messages from one computer to another using a client-server application architecture. An MTA implements both the client (sending) and server (receiving) portions of the Simple Mail Transfer Protocol.",
            insertText: 'MessageTransferAgent',
            range: range,
        }
        ,
        {
            label: 'Directory Service',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, directory service or name service maps the names of network resources to their respective network addresses. It is a shared information infrastructure for locating, managing, administering and organizing everyday items and network resources, which can include volumes, folders, files, printers, users, groups, devices, telephone numbers and other objects. A directory service is a critical component of a network operating system. A directory server or name server is a server which provides such a service. Each resource on the network is considered an object by the directory server. Information about a particular resource is stored as a collection of attributes associated with that resource or object.",
            insertText: 'DirectoryService',
            range: range,
        }
        ,
        {
            label: 'Authentication Service',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An authentication service is a mechanism, analogous to the use of passwords on time-sharing systems, for the secure authentication of the identity of network clients by servers and vice versa, without presuming the operating system integrity of either (e.g., Kerberos).",
            insertText: 'AuthenticationService',
            range: range,
        }
        ,
        {
            label: 'Operating System Process',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An operating system process, or system process, is a process running to perform operating system functions.",
            insertText: 'OperatingSystemProcess',
            range: range,
        }
        ,
        {
            label: 'System Init Process',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A system initialization process is a process that executes to initialize (boot) an operating system.",
            insertText: 'SystemInitProcess',
            range: range,
        }
        ,
        {
            label: 'Scheduled Job',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A task scheduler process is an operating system process that executes scheduled tasks (time-scheduling in the sense of wall clock time; not operating system scheduling of processes for multitasking).",
            insertText: 'ScheduledJob',
            range: range,
        }
        ,
        {
            label: 'System Call',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A system call is the programmatic way in which a computer program requests a service from the kernel of the operating system it is executed on. This may include hardware-related services (for example, accessing a hard disk drive), creation and execution of new processes, and communication with integral kernel services such as process scheduling. System calls provide an essential interface between a process and the operating system.",
            insertText: 'SystemCall',
            range: range,
        }
        ,
        {
            label: 'Connect Socket',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The connect socket system call connects the socket to a target address.",
            insertText: 'ConnectSocket',
            range: range,
        }
        ,
        {
            label: 'Delete File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Remove a file from a machine.",
            insertText: 'DeleteFile',
            range: range,
        }
        ,
        {
            label: 'Suspend Thread',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Suspending a thread causes the thread to stop executing user-mode code.",
            insertText: 'SuspendThread',
            range: range,
        }
        ,
        {
            label: 'Terminate Process',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "On many computer operating systems, a computer process terminates its execution by making an exit system call. More generally, an exit in a multithreading environment means that a thread of execution has stopped running. For resource management, the operating system reclaims resources (memory, files, etc.) that were used by the process. The process is said to be a dead process after it terminates.",
            insertText: 'TerminateProcess',
            range: range,
        }
        ,
        {
            label: 'Trace Process',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A trace system call provides a means by which one process (the \"tracer\") may observe and control the execution of another process (the \"tracee\"), and examine and change the tracee's memory and registers. It is primarily used to implement breakpoint debugging and system call tracing.",
            insertText: 'TraceProcess',
            range: range,
        }
        ,
        {
            label: 'Write File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The write is one of the most basic routines provided by a Unix-like operating system kernel. It writes data from a buffer declared by the user to a given device, such as a file. This is the primary way to output data from a program by directly using a system call. The destination is identified by a numeric code. The data to be written, for instance a piece of text, is defined by a pointer and a size, given in number of bytes. write thus takes three arguments.",
            insertText: 'WriteFile',
            range: range,
        }
        ,
        {
            label: 'Create Socket',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A create socket system call creates an endpoint for communication and returns a file descriptor that refers to that endpoint.",
            insertText: 'CreateSocket',
            range: range,
        }
        ,
        {
            label: 'Create Thread',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Threads are an execution model that exists independently from a language, as well as a parallel execution model. They enable a program to control multiple different flows of work that overlap in time.",
            insertText: 'CreateThread',
            range: range,
        }
        ,
        {
            label: 'Move File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A system call to rename or move a file.  Linux's rename() is an example of this kind of system call. Another way of handling it is to call a copy file system call followed by a delete file system call.",
            insertText: 'MoveFile',
            range: range,
        }
        ,
        {
            label: 'Open File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "For most file systems, a program initializes access to a file in a file system using the open system call. This allocates resources associated to the file (the file descriptor), and returns a handle that the process will use to refer to that file. In some cases the open is performed by the first access. During the open, the filesystem may allocate memory for buffers, or it may wait until the first operation. Various other errors which may occur during the open include directory update failures, un-permitted multiple connections, media failures, communication link failures and device failures.",
            insertText: 'OpenFile',
            range: range,
        }
        ,
        {
            label: 'Read File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A program that needs to access data from a file stored in a file system uses the read system call. The file is identified by a file descriptor that is normally obtained from a previous call to open. This system call reads in data in bytes, the number of which is specified by the caller, from the file and stores then into a buffer supplied by the calling process.",
            insertText: 'ReadFile',
            range: range,
        }
        ,
        {
            label: 'Get System Time',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A system call that gets the system time.  For POSIX.1 systems, time() invokes a call to get the system time.",
            insertText: 'GetSystemTime',
            range: range,
        }
        ,
        {
            label: 'Create File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "System call to create a new file on a file system. Some operating systems implement this functionality as part of their d3f:OpenFile system call.",
            insertText: 'CreateFile',
            range: range,
        }
        ,
        {
            label: 'Create Process',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A process spawn refers to a function that loads and executes a new child process.The current process may wait for the child to terminate or may continue to execute asynchronously. Creating a new subprocess requires enough memory in which both the child process and the current program can execute. There is a family of spawn functions in DOS, inherited by Microsoft Windows. There is also a different family of spawn functions in an optional extension of the POSIX standards.  Fork-exec is another technique combining two Unix system calls, which can effect a process spawn.",
            insertText: 'CreateProcess',
            range: range,
        }
        ,
        {
            label: 'Create Process',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Creates a process.",
            insertText: 'CreateProcess',
            range: range,
        }
        ,
        {
            label: 'Create Process',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Executes a process.",
            insertText: 'CreateProcess',
            range: range,
        }
        ,
        {
            label: 'Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Network traffic or data traffic is the data, or alternatively the amount of data, moving across a network at a given point of time.  Network data in computer networks is mostly encapsulated in network packets, which provide the load in the network.",
            insertText: 'NetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'IPC Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "IPC network traffic is network traffic related to inter-process communication (IPC) between network nodes..This includes only network traffic conforming to a standard IPC protocol; not custom protocols.",
            insertText: 'IPCNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Intranet IPC Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Intranet IPC network traffic is network traffic that does not cross a given network's boundaries and uses a standard inter-process communication (IPC) networking protocol.",
            insertText: 'IntranetIPCNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Mail Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Mail traffic is network traffic that uses a standard mail transfer protocol.",
            insertText: 'MailNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Inbound Internet Mail Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Inbound internet mail traffic is network traffic that is: (a) coming from a host outside a given network via an incoming connection to a host inside that same network, and (b) using a standard protocol for email.",
            insertText: 'InboundInternetMailTraffic',
            range: range,
        }
        ,
        {
            label: 'DHCP Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "DHCP Network Traffic is network traffic related to the DHCP protocol, used by network nodes to negotiate and configure either IPv4 or IPv6 addresses.",
            insertText: 'DHCPNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Network Packet',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A network packet is a formatted unit of data carried by a packet-switched network. Computer communications links that do not support packets, such as traditional point-to-point telecommunications links, simply transmit data as a bit stream. When data is formatted into packets, packet switching is possible and the bandwidth of the communication medium can be better shared among users than with circuit switching.",
            insertText: 'NetworkPackets',
            range: range,
        }
        ,
        {
            label: 'TFTP Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "TFTP Network Traffic is network traffic typically used to automatically transfer configuration or boot files between machines.",
            insertText: 'TFTPNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'DNS Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "DNS network traffic is network traffic related to queries and responses involving the Domain Name System. DNS traffic can involve clients, servers such as relays or resolvers. This includes only network traffic conforming to standard DNS protocol; not custom protocols.",
            insertText: 'DNSNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Outbound Internet DNS Lookup Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Outbound internet DNS lookup traffic is network traffic using the DNS protocol on an outgoing connection initiated from a host within a network to a host outside the network.",
            insertText: 'OutboundInternetDNSLookupTraffic',
            range: range,
        }
        ,
        {
            label: 'Inbound Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Inbound traffic is network traffic originating from another host (client), to the host of interest (server).",
            insertText: 'InboundNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Inbound Internet Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Inbound internet traffic is network traffic from a host outside a given network initiated on an incoming connection to a host inside that network.",
            insertText: 'InboundInternetNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Inbound Internet DNS Response Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Inbound internet DNS response traffic is DNS response traffic from a host outside a given network initiated on an incoming connection to a host inside that network.",
            insertText: 'InboundInternetDNSResponseTraffic',
            range: range,
        }
        ,
        {
            label: 'File Transfer Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "File transfer network traffic is network traffic related to file transfers between network nodes..This includes only network traffic conforming to standard file transfer protocols, not custom transfer protocols.",
            insertText: 'FileTransferNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Internet File Transfer Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Internet file transfer network traffic is network traffic related to file transfers between network nodes that crosses a boundary between networks. This includes only network traffic conforming to standard file transfer protocols, not custom transfer protocols.",
            insertText: 'InternetFileTransferTraffic',
            range: range,
        }
        ,
        {
            label: 'Intranet File Transfer Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Intranet file transfer traffic is file transfer traffic that does not cross a given network's boundaries and uses a standard file transfer protocol.",
            insertText: 'IntranetFileTransferTraffic',
            range: range,
        }
        ,
        {
            label: 'Outbound Internet File Transfer Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Outbound internet file transfer traffic is file transfer traffic that is: (a) on an outgoing connection initiated from a host within a network to a host outside the network, and (b) using a standard file transfer protocol.",
            insertText: 'OutboundInternetFileTransferTraffic',
            range: range,
        }
        ,
        {
            label: 'Network Session',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A network session is a temporary and interactive information interchange between two or more devices communicating over a network. A session is established at a certain point in time, and then 'torn down' - brought to an end - at some later point. An established communication session may involve more than one message in each direction. A session is typically stateful, meaning that at least one of the communicating parties needs to hold current state information and save information about the session history in order to be able to communicate, as opposed to stateless communication, where the communication consists of independent requests with responses. Network sessions may be established and implemented as part of protocols and services at the application, session, or transport layers of the OSI model.",
            insertText: 'NetworkSession',
            range: range,
        }
        ,
        {
            label: 'Remote Terminal Session',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A remote terminal session is a session that provides a user access from one host to another host via a terminal.",
            insertText: 'RemoteTerminalSession',
            range: range,
        }
        ,
        {
            label: 'Outbound Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Outbound traffic is network traffic originating from a host of interest (client), to another host (server).",
            insertText: 'OutboundNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Outbound Internet RPC Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Outbound internet RPC traffic is RPC traffic that is: (a) on an outgoing connection initiated from a host within a network to a host outside the network, and (b) using a standard RPC protocol.",
            insertText: 'OutboundInternetRPCTraffic',
            range: range,
        }
        ,
        {
            label: 'Outbound Internet Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Outbound internet network traffic is network traffic on an outgoing connection initiated from a host within a network to a host outside the network.",
            insertText: 'OutboundInternetNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Outbound Internet Mail Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Outbound internet DNS lookup traffic is network traffic using a standard email protocol on an outgoing connection initiated from a host within a network to a host outside the network.",
            insertText: 'OutboundInternetMailTraffic',
            range: range,
        }
        ,
        {
            label: 'Outbound Internet Web Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Outbound internet web traffic is network traffic that is: (a) on an outgoing connection initiated from a host within a network to a host outside the network, and (b) using a standard web protocol.",
            insertText: 'OutboundInternetWebTraffic',
            range: range,
        }
        ,
        {
            label: 'Outbound Internet Encrypted Web Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Outbound internet encrypted web traffic is network traffic using a standard web protocol on an outgoing connection initiated from a host within a network to a host outside the network.",
            insertText: 'OutboundInternetEncryptedWebTraffic',
            range: range,
        }
        ,
        {
            label: 'Outbound Internet Encrypted Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Outbound internet encrypted traffic is encrypted network traffic on an outgoing connection initiated from a host within a network to a host outside the network.",
            insertText: 'OutboundInternetEncryptedTraffic',
            range: range,
        }
        ,
        {
            label: 'Outbound Internet Encrypted Remote Terminal Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Outbound internet encrypted remote terminal traffic is encrypted network traffic for a standard remote terminal protocol on an outgoing connection initiated from a host within a network to a host outside the network.",
            insertText: 'OutboundInternetEncryptedRemoteTerminalTraffic',
            range: range,
        }
        ,
        {
            label: 'RPC Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "RPC network traffic is network traffic related to remote procedure calls between network nodes..This includes only network traffic conforming to a standard RPC protocol; not custom protocols.",
            insertText: 'RPCNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Intranet RPC Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Intranet RPC network traffic is network traffic that does not cross a given network's boundaries and uses a standard remote procedure call (e.g., RFC 1050) protocol.",
            insertText: 'IntranetRPCNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Web Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Web network traffic is network traffic that uses a standard web protocol.",
            insertText: 'WebNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Intranet Web Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Intranet web network traffic is network traffic that does not cross a given network's boundaries and uses a standard web protocol.",
            insertText: 'IntranetWebNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Administrative Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Administrative network traffic is network traffic related to the remote administration or control of hosts or devices through a standard remote administrative protocol.  Remote shells, terminals, RDP, and VNC are examples of these protocols, which are typically only used by administrators.",
            insertText: 'AdministrativeNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Intranet Administrative Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Intranet administrative network traffic is administrative network traffic that does not cross a given network's boundaries and uses a standard administrative protocol.",
            insertText: 'IntranetAdministrativeNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Internet Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Internet network traffic is network traffic that crosses a boundary between networks. [This is the general sense of inter-networking; It may or may not cross to or from the Internet]",
            insertText: 'InternetNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Intranet Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Intranet network traffic is network traffic traversing that does not traverse a given network's boundaries.",
            insertText: 'IntranetNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Intranet Multicast Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Intranet IPC network traffic is multicast network traffic that does not cross a given network's boundaries.",
            insertText: 'IntranetMulticastNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'Local Area Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Intranet local area network (LAN) traffic is network traffic that does not cross a given network's boundaries; where that network is defined as a LAN.",
            insertText: 'LocalAreaNetworkTraffic',
            range: range,
        }
        ,
        {
            label: 'User Account',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A user account allows a user to authenticate to a system and potentially to receive authorization to access resources provided by or connected to that system; however, authentication does not imply authorization. To log into an account, a user is typically required to authenticate oneself with a password or other credentials for the purposes of accounting, security, logging, and resource management.",
            insertText: 'UserAccount',
            range: range,
        }
        ,
        {
            label: 'Privileged User Account',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A privileged account is a user account that has more privileges than ordinary users. Privileged accounts might, for example, be able to install or remove software, upgrade the operating system, or modify system or application configurations. They might also have access to files that are not normally accessible to standard users. Typical examples are root and administrator accounts. But there also service accounts, system accounts, etc. Privileged accounts are especially powerful, and should be monitored especially closely.",
            insertText: 'PrivilegedUserAccount',
            range: range,
        }
        ,
        {
            label: 'Default User Account',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems or default factory/provider set accounts on other types of systems, software, or devices.",
            insertText: 'DefaultUserAccount',
            range: range,
        }
        ,
        {
            label: 'Cloud User Account',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A user account on a given host is a local user account for a given cloud and specified resources within that cloud.",
            insertText: 'CloudUserAccount',
            range: range,
        }
        ,
        {
            label: 'Local User Account',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A user account on a given host is a local user account for that specific host.",
            insertText: 'LocalUserAccount',
            range: range,
        }
        ,
        {
            label: 'Domain User Account',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A domain user account in Microsoft Windows (2000) defines that user's access to a logical group of network objects (computers, users, devices) that share the same Active Directory databases; that is, a user's access to a domain.",
            insertText: 'DomainUserAccount',
            range: range,
        }
        ,
        {
            label: 'Global User Account',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A type of user account in Microsoft Windows (NT) that has a domain-wide scope.defines that user's access to a logical group of network objects (computers, users, devices) that share the same Active Directory databases; that is, a user's access to the domain.",
            insertText: 'GlobalUserAccount',
            range: range,
        }
        ,
        {
            label: 'd3fend-kb-object-property',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x d3fend-kb-object-property y: The object y is a d3fend knowledge base object property. These properties allow the linkage of knowledge and information supporting and illustrating the d3fend model.",
            insertText: 'd3fend-kb-object-property',
            range: range,
        }
        ,
        {
            label: 'kb-reference-of',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x kb-is-example-of y: The reference x is an example of technique y.",
            insertText: 'kb-reference-of',
            range: range,
        }
        ,
        {
            label: 'resume',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "The agent or technique x continues a previous action on entity y. Usually occurs after suspension on y.",
            insertText: 'resume',
            range: range,
        }
        ,
        {
            label: 'spoofs',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x spoofs y: The technique x creates a fake instance of a digital artifact y; that is, y is a decoy, fake, or counterfeit.",
            insertText: 'spoofs',
            range: range,
        }
        ,
        {
            label: 'monitors',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x monitors y: The technique or agent x keep tabs on; keeps an eye on; or keep the digital artifact y under surveillance.",
            insertText: 'monitors',
            range: range,
        }
        ,
        {
            label: 'analyzes',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x analyzes y: The subject x break down object y into components or essential features, assessing y by quantitative methods, qualitative methods, or both.  Usually the analysis is done in terms of some model or framework.",
            insertText: 'analyzes',
            range: range,
        }
        ,
        {
            label: 'verifies',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x verifies y: A technique x confirms the truth of a digital artifact y.",
            insertText: 'verifies',
            range: range,
        }
        ,
        {
            label: 'isolates',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x isolates y: The technique or agent x sets digital artifact y apart from other digital artifacts, sequestering y.",
            insertText: 'isolates',
            range: range,
        }
        ,
        {
            label: 'filters',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x filters y: An technique or agent x removes some specified set of of entities from the content of a digital artifact y, by passing an artifact's content through a filter.  A filter is a device that removes something from whatever passes through it.",
            insertText: 'filters',
            range: range,
        }
        ,
        {
            label: 'blocks',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x blocks y: The entity x blocks off the use of digital artifact y by reference to a block or allow list (or both.)",
            insertText: 'blocks',
            range: range,
        }
        ,
        {
            label: 'obfuscates',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x obfuscates y: The technique x makes the digital artifact y unclear or obscure.  Typically obfuscation is a way to hide a digital artifact from discovery, use, or both.",
            insertText: 'obfuscates',
            range: range,
        }
        ,
        {
            label: 'terminates',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x terminates y: The technique x brings to an end or halt to some activity y.",
            insertText: 'terminates',
            range: range,
        }
        ,
        {
            label: 'suspends',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x suspends y: The agent or technique x pauses entity y.",
            insertText: 'suspends',
            range: range,
        }
        ,
        {
            label: 'disables',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x disables y: The technique or agent x makes an entity y unable to perform its actions or capabilities.",
            insertText: 'disables',
            range: range,
        }
        ,
        {
            label: 'deletes',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x deletes y: A technique or agent x wipes out the digitally or magnetically recorded information of digital object y.",
            insertText: 'deletes',
            range: range,
        }
        ,
        {
            label: 'authorizes',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x authorizes y: A subject x grants authorization or clearance for an agent y to use an object.  This relation indicates an authorization event has occurred.",
            insertText: 'authorizes',
            range: range,
        }
        ,
        {
            label: 'neutralizes',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x neutralizes y: The technique x makes the execution of actions of y ineffective by preventing or counterbalancing the effect of y.",
            insertText: 'neutralizes',
            range: range,
        }
        ,
        {
            label: 'regenerates',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x regenerates y: The entity x discards the current digital artifact y and creates a new version that serves the same function.",
            insertText: 'regenerates',
            range: range,
        }
        ,
        {
            label: 'updates',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x updates y: The technique x updates the software for component y.",
            insertText: 'updates',
            range: range,
        }
        ,
        {
            label: 'strengthens',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x strengthens y: The technique x make digital artifact y resistant (to harm or misuse.)",
            insertText: 'strengthens',
            range: range,
        }
        ,
        {
            label: 'validates',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x validates y: The technique x proves the digital artifact y is valid; that is, x shows or confirms the validity of y.",
            insertText: 'validates',
            range: range,
        }
        ,
        {
            label: 'encrypts',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x encrypts y: The entity x converts the ordinary representation of a digital artifact y into a secret code.",
            insertText: 'encrypts',
            range: range,
        }
        ,
        {
            label: 'authenticates',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x authenticates y: The subject x establishes the authenticity of some y. This relation indicates an authentication event has occurred.",
            insertText: 'authenticates',
            range: range,
        }
        ,
        {
            label: 'produces',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x produces y: The subject entity x or process produces a data object y, which may be discrete digital object or a stream (e.g., a stream such as network traffic.)",
            insertText: 'produces',
            range: range,
        }
        ,
        {
            label: 'may-be-associated-with',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x may-be-associated-with y: The subject x and object y may be associated in some way.",
            insertText: 'may-be-associated-with',
            range: range,
        }
        ,
        {
            label: 'may-be-tactically-associated-with',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x may-be-tactically-associated-with y: the defensive technique x may be a tactic that counters offensive technique y.",
            insertText: 'may-be-tactically-associated-with',
            range: range,
        }
        ,
        {
            label: 'may-interpret',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x may-interpret y: They entity x may interpret the thing y; that is, 'x interprets y' may be true.",
            insertText: 'may-interpret',
            range: range,
        }
        ,
        {
            label: 'interprets',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x interprets y: The subject x interprets the executable script y. The sense of interprets is here 'Parse the source code and perform its behavior directly.'",
            insertText: 'interprets',
            range: range,
        }
        ,
        {
            label: 'may-run',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x may-run y: They entity x may run the thing y; that is, 'x runs y' may be true.",
            insertText: 'may-run',
            range: range,
        }
        ,
        {
            label: 'runs',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x runs y: To carry out a process or program y, as on a computer or a machine x; where y may be a large software assembly or a specific module or instruction.  Examples: \"run a new program on the Mac\"; \"the computer runs the application software\".",
            insertText: 'runs',
            range: range,
        }
        ,
        {
            label: 'executes',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x executes y: The subject x takes the action of carrying out (executing) y, which is a single software module, function, or instruction.",
            insertText: 'executes',
            range: range,
        }
        ,
        {
            label: 'injects',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x injects y: The subject x takes the action of exploiting a security flaw by introducing (injecting) y, which is code or data that will change the course of execution or state of a computing process to an alternate course or state. Typically code injection is associated with adversaries intending the alternate course to facilitate a malevolent purpose; however, code injection can be unintentional or the intentions behind it may be good or benign.",
            insertText: 'injects',
            range: range,
        }
        ,
        {
            label: 'invokes',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x invokes y: The subject x invokes a system service y by use of an instruction object y that interrupts the program being executed and passes control to the operating system to perform that operation.",
            insertText: 'invokes',
            range: range,
        }
        ,
        {
            label: 'may-execute',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x may execute y: The subject x might take the action of carrying out (executing) y, which is a single software module, function, or instruction.",
            insertText: 'may-execute',
            range: range,
        }
        ,
        {
            label: 'may-transfer',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x may-transfer y: They entity x might send the thing y; that is, 'x transfers y' may be true.",
            insertText: 'may-transfer',
            range: range,
        }
        ,
        {
            label: 'may-add',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x may-add y: They entity x may add the thing y; that is, 'x adds y' may be true.",
            insertText: 'may-add',
            range: range,
        }
        ,
        {
            label: 'adds',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x adds y: The subject x adds a data object y, such as a file, to some other digital artifact, such as a directory. Examples include an agent or technique adding a record to a database. or a domain entry to a DNS server.",
            insertText: 'adds',
            range: range,
        }
        ,
        {
            label: 'may-produce',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x may-produce y: They entity x may produce the thing y; that is, 'x produces y' may be true.",
            insertText: 'may-produce',
            range: range,
        }
        ,
        {
            label: 'may-create',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x may-create y: They entity x may create the entity y; that is, 'x creates y' may be true.",
            insertText: 'may-create',
            range: range,
        }
        ,
        {
            label: 'creates',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x creates y: The subject x bring into existence an object y.  Some technique or agent x creates a persistent digital artifact y (as opposed to production of a consumable or transient object.); i.e., bring forth or generate",
            insertText: 'creates',
            range: range,
        }
        ,
        {
            label: 'forges',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x forges y: An technique or agent x counterfeits a digital artifact y, such as a fake credential, with the intent to deceive.",
            insertText: 'forges',
            range: range,
        }
        ,
        {
            label: 'copies',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x copies y: An technique or agent x reproduces or makes and exact copy of some digital artifact y.",
            insertText: 'copies',
            range: range,
        }
        ,
        {
            label: 'may-access',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x may-access y: They entity x may access the thing y; that is, 'x accesses y' may be true.",
            insertText: 'may-access',
            range: range,
        }
        ,
        {
            label: 'accesses',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x accesses y: An subject x takes the action of reading from, writing into, or executing the stored information in the object y. Reads, writes, and executes are specific cases of accesses.",
            insertText: 'accesses',
            range: range,
        }
        ,
        {
            label: 'writes',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x writes y: The subject x takes the action of writing to a digital artifact y to store data and placing it into persistent memory for later reference.",
            insertText: 'writes',
            range: range,
        }
        ,
        {
            label: 'reads',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x reads y: The subject x takes the action of reading from a digital source y to acquire data and placing it into volatile memory for processing.",
            insertText: 'reads',
            range: range,
        }
        ,
        {
            label: 'enumerates',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "definition \"x enumerates y: The subject x takes the action of reading from a digital source y to acquire data and create a list of its contents.",
            insertText: 'enumerates',
            range: range,
        }
        ,
        {
            label: 'modifies',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x modifies y: A technique or agent x causes a digital object y to change; become different; or undertake a transformation.  Afterwards, the data or state held by a digital object is changed.",
            insertText: 'modifies',
            range: range,
        }
        ,
        {
            label: 'extends',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x extends y: The entity x extend the scope or range or area of entity y, especially in the sense of widen the range of applications.",
            insertText: 'extends',
            range: range,
        }
        ,
        {
            label: 'may-invoke',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x may-invoke y: They entity x may invoke the thing y; that is, 'x invokes y' may be true.",
            insertText: 'may-invoke',
            range: range,
        }
        ,
        {
            label: 'may-contain',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "to potentially have as contents or constituent parts; comprise; include.",
            insertText: 'may-contain',
            range: range,
        }
        ,
        {
            label: 'contains',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x contains y: A core relation that holds between a whole x and its part y.  Equivalent to relational concept 'has part' and thus transitive.",
            insertText: 'contains',
            range: range,
        }
        ,
        {
            label: 'may-modify',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x may-modify y: They entity x may modify the thing y; that is, 'x modifies y' may be true.",
            insertText: 'may-modify',
            range: range,
        }
        ,
        {
            label: 'modifies-part',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x modifies-part y: The entity x modifies a part of y.  [Note: This is a rolification property for the rule 'if one modifies a part of a whole, they modify the whole.'  Reasoning for this and similar semantics to come are under evaluation and not part of current d3fend inferences.]",
            insertText: 'modifies-part',
            range: range,
        }
        ,
        {
            label: 'associated-with',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x associated-with y: The subject x and object y are associated in some way.  This is the most general definite relationship in d3fend (i.e., most general relationship that is not prefixed by 'may-'.)",
            insertText: 'associated-with',
            range: range,
        }
        ,
        {
            label: 'employed-by',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x employed-by y: An entity x is put into service by a technique or agent y.  Inverse of y employs x.",
            insertText: 'employed-by',
            range: range,
        }
        ,
        {
            label: 'used-by',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x used-by y: is inverse of y uses x.",
            insertText: 'used-by',
            range: range,
        }
        ,
        {
            label: 'addressed-by',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x addressed-by y: Relates a resource x (e.g., network host, peripheral device, disk sector, a memory cell or other logical or physical entity) to a discrete address y in an address space that points to it.",
            insertText: 'addressed-by',
            range: range,
        }
        ,
        {
            label: 'attached-to',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x attached-to y: A subject x is joined in close association to an object y.",
            insertText: 'attached-to',
            range: range,
        }
        ,
        {
            label: 'copy-of',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x copy-of y: The subject x is a duplicate of the object y",
            insertText: 'copy-of',
            range: range,
        }
        ,
        {
            label: 'dependent',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x dependent y: A dependent y is an entity that requires the fulfillment of the requirements specified in dependency x.",
            insertText: 'dependent',
            range: range,
        }
        ,
        {
            label: 'has-location',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x has-location y: The entity x is situated in a particular spot or position y.",
            insertText: 'has-location',
            range: range,
        }
        ,
        {
            label: 'has-recipient',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x has_recipient y: An agent y is the intended recipient and decoder of the information contained in communication x.",
            insertText: 'has-recipient',
            range: range,
        }
        ,
        {
            label: 'has-sender',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x has_sender y: An agent y is the sender and encoder of the information contained in communication x.",
            insertText: 'has-sender',
            range: range,
        }
        ,
        {
            label: 'hides',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x hides y: A technique or operation x conceals the digital artifact y.",
            insertText: 'hides',
            range: range,
        }
        ,
        {
            label: 'installs',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x installs y: An entity x sets up a digital artifact y for subsequent use.  For example, an installation program can install application software.",
            insertText: 'installs',
            range: range,
        }
        ,
        {
            label: 'instructed-by',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "definition \"x instructed-by y: A subject x takes machine instructions from object y.\"",
            insertText: 'instructed-by',
            range: range,
        }
        ,
        {
            label: 'instructs',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "definition \"x instructs y: A subject x delivers machine instructions to object y.\"",
            insertText: 'instructs',
            range: range,
        }
        ,
        {
            label: 'owns',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x owns y: The subject x has ownership or possession of some object y.",
            insertText: 'owns',
            range: range,
        }
        ,
        {
            label: 'has-account',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x has-account y: The subject x has ownership or possession of some account y.",
            insertText: 'has-account',
            range: range,
        }
        ,
        {
            label: 'provider',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x provider y: A provider y is an entity that supplies a service, system, or data resources to a dependent entity x.",
            insertText: 'provider',
            range: range,
        }
        ,
        {
            label: 'summarizes',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x summarizes y: The sensor x summarizes a set y of events concerning digital artifacts over time",
            insertText: 'summarizes',
            range: range,
        }
        ,
        {
            label: 'unmounts',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x unmounts y: An operation x removes the access via computer system's file system the availability of files and directories on a storage artifact y.  Unmounts reverse or undo prior mount operations.",
            insertText: 'unmounts',
            range: range,
        }
        ,
        {
            label: 'connects',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x connects y: The subject x joins system y by means of communication equipment (to some other system, typically the adversary-targeted host).",
            insertText: 'connects',
            range: range,
        }
        ,
        {
            label: 'drives',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x drives y: The device driver x causes a system component y to function by controlling it.",
            insertText: 'drives',
            range: range,
        }
        ,
        {
            label: 'enabled-by',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x enabled-by y: A top level technique y enables a tactic x, that is, the property indicates that a technique y is used to put a particular tactic x into action. In other words, y renders x capable or able for some task.  Inverse of enables.",
            insertText: 'enabled-by',
            range: range,
        }
        ,
        {
            label: 'originates-from',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x originates-from y: The digital event or artifact x began its network transit from a physical location y.",
            insertText: 'originates-from',
            range: range,
        }
        ,
        {
            label: 'process-property',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x process-property y: Process x has the a process-property y.  This is generalization for specific process object properties.",
            insertText: 'process-property',
            range: range,
        }
        ,
        {
            label: 'process-ancestor',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x process-ancestor y: The process y is a process ancestor of process x, indicating one or more process creation events were conducted were started at process y and subsequently created process x.",
            insertText: 'process-ancestor',
            range: range,
        }
        ,
        {
            label: 'process-parent',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x process-parent y: The process y created the process x (directly) with a create process event.",
            insertText: 'process-parent',
            range: range,
        }
        ,
        {
            label: 'process-image-path',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x process-image-path y: The filepath y is the process image path for the process x, indicating the path to the resource from which the process's image was loaded.",
            insertText: 'process-image-path',
            range: range,
        }
        ,
        {
            label: 'process-user',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x process-user y: The process x has been executed by the user y.",
            insertText: 'process-user',
            range: range,
        }
        ,
        {
            label: 'records',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x records y: The digital artifact x makes a record of events y; set down in permanent form.",
            insertText: 'records',
            range: range,
        }
        ,
        {
            label: 'manages',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x manages y: The technique or agent x watches and directs the use of a digital artifact y.",
            insertText: 'manages',
            range: range,
        }
        ,
        {
            label: 'addresses',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x addresses y: Relates a pointer x to a digital artifact y located in the address space to which x points. The address space is part of some digital store, whether it be in memory, an image, or a persistent storage device.",
            insertText: 'addresses',
            range: range,
        }
        ,
        {
            label: 'loads',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x loads y: The technique or process x transfers a software from a storage y to a computer's memory for subsequent execution.",
            insertText: 'loads',
            range: range,
        }
        ,
        {
            label: 'related',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x related y: x has a symmetric associative relation to y.",
            insertText: 'related',
            range: range,
        }
        ,
        {
            label: 'uses',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x uses y: An entity x puts into service a resource or implement y; makes y work or employ for a particular purpose or for its inherent or natural purpose.",
            insertText: 'uses',
            range: range,
        }
        ,
        {
            label: 'abuses',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x abuses y: The entity x applies an artifact y to a wrong thing or person; x applies y badly or incorrectly.",
            insertText: 'abuses',
            range: range,
        }
        ,
        {
            label: 'restricts',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x restricts y: An entity x bounds the use of entity y.",
            insertText: 'restricts',
            range: range,
        }
        ,
        {
            label: 'limits',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x limits y: An entity x specifies a designated limit beyond which some entity y cannot function or must be terminated.",
            insertText: 'limits',
            range: range,
        }
        ,
        {
            label: 'use-limits',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x use-limits y: An entity x specifies a designated number of uses beyond which some entity y cannot function or must be terminated.",
            insertText: 'use-limits',
            range: range,
        }
        ,
        {
            label: 'enables',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x enables y: A top level technique x enables a tactic y, that is, the property indicates that a technique x is used to put a particular tactic y into action. In other words, x renders y capable or able for some task.",
            insertText: 'enables',
            range: range,
        }
        ];
        }
    
function provideCompletionItems(model, position) {
    var textUntilPosition = model.getValueInRange({
        startLineNumber: 1,
        startColumn: 1,
        endLineNumber: position.lineNumber,
        endColumn: position.column,
    });
    var match = textUntilPosition.match(
        /d3f:/
    );
    if (!match) {
        return { suggestions: [] };
    }
    var word = model.getWordUntilPosition(position);
    var range = {
        startLineNumber: position.lineNumber,
        endLineNumber: position.lineNumber,
        startColumn: word.startColumn,
        endColumn: word.endColumn,
    };
    return {
        suggestions: createD3fCompletion(range),
    };
}
    