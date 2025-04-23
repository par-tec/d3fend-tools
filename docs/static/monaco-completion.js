
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
            label: 'Restore Access',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restoring an entity's access to resources.",
            insertText: 'RestoreAccess',
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
            label: 'Access Policy Administration',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Access policy administration is the systematic process of defining, implementing, and managing access control policies that dictate user permissions to resources.",
            insertText: 'AccessPolicyAdministration',
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
            label: 'Local File Permissions',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restricting access to a local file by configuring operating system functionality.",
            insertText: 'LocalFilePermissions',
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
            label: 'Credential Eviction',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Credential Eviction techniques disable or remove compromised credentials from a computer network.",
            insertText: 'CredentialEviction',
            range: range,
        }
        ,
        {
            label: 'Credential Revocation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Deleting a set of credentials permanently to prevent them from being used to authenticate.",
            insertText: 'CredentialRevocation',
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
            label: 'Agent Authentication',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Agent authentication is the process of verifying the identities of agents to ensure they are authorized and trustworthy participants within a system.",
            insertText: 'AgentAuthentication',
            range: range,
        }
        ,
        {
            label: 'Password Authentication',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Password authentication is a security mechanism used to verify the identity of a user or entity attempting to access a system or resource by requiring the input of a secret string of characters, known as a password, that is associated with the user or entity.",
            insertText: 'PasswordAuthentication',
            range: range,
        }
        ,
        {
            label: 'Token-based Authentication',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Token-based authentication is an authentication protocol where users verify their identity in exchange for a\u00a0unique access token. Users can then access the website, application, or resource for the life of the token without having to re-enter their credentials.",
            insertText: 'Token-basedAuthentication',
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
            label: 'Certificate-based Authentication',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Requiring a digital certificate in order to authenticate a user.",
            insertText: 'Certificate-basedAuthentication',
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
            label: 'Direct Physical Link Mapping',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Direct physical link mapping creates a physical link map by direct observation and recording of the physical network links.",
            insertText: 'DirectPhysicalLinkMapping',
            range: range,
        }
        ,
        {
            label: 'Object Eviction',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Terminate or remove an object from a host machine. This is the broadest class for object eviction.",
            insertText: 'ObjectEviction',
            range: range,
        }
        ,
        {
            label: 'DNS Cache Eviction',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Flushing DNS to clear any IP addresses or other DNS records from the cache.",
            insertText: 'DNSCacheEviction',
            range: range,
        }
        ,
        {
            label: 'Domain Registration Takedown',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "The process of performing a takedown of the attacker's domain registration infrastructure.",
            insertText: 'DomainRegistrationTakedown',
            range: range,
        }
        ,
        {
            label: 'File Eviction',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "File eviction techniques delete files from system storage.",
            insertText: 'FileEviction',
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
            label: 'Registry Key Deletion',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Delete a registry key.",
            insertText: 'RegistryKeyDeletion',
            range: range,
        }
        ,
        {
            label: 'Disk Formatting',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Disk Formatting is the process of preparing a data storage device, such as a hard drive, solid-state drive, or USB flash drive, for initial use.",
            insertText: 'DiskFormatting',
            range: range,
        }
        ,
        {
            label: 'Disk Erasure',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Disk Erasure is the process of securely deleting all data on a disk to ensure that it cannot be recovered by any means.",
            insertText: 'DiskErasure',
            range: range,
        }
        ,
        {
            label: 'Disk Partitioning',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Disk Partitioning is the process of dividing a disk into multiple distinct sections, known as partitions.",
            insertText: 'DiskPartitioning',
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
            label: 'Session Termination',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Forcefully end all active sessions associated with compromised accounts or devices.",
            insertText: 'SessionTermination',
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
            label: 'Host Shutdown',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Initiating a host's shutdown sequence to terminate all running processes.",
            insertText: 'HostShutdown',
            range: range,
        }
        ,
        {
            label: 'Host Reboot',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Initiating a host's reboot sequence to terminate all running processes.",
            insertText: 'HostReboot',
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
            label: 'Restore Object',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restoring an object for an entity to access. This is the broadest class for object restoral.",
            insertText: 'RestoreObject',
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
            label: 'Access Mediation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Access mediation is the process of granting or denying specific requests to: 1) obtain and use information and related information processing services; and 2) enter specific physical facilities (e.g., Federal buildings, military establishments, border crossing entrances).",
            insertText: 'AccessMediation',
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
            label: 'Physical Access Mediation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Physical access mediation is the process of granting or denying specific requests to enter specific physical facilities (e.g., Federal buildings, military establishments, border crossing entrances.)",
            insertText: 'PhysicalAccessMediation',
            range: range,
        }
        ,
        {
            label: 'Network Access Mediation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Network access mediation is the control method for authorizing access to a system by a user (or a process acting on behalf of a user) communicating through a network, including a local area network, a wide area network, and the Internet.",
            insertText: 'NetworkAccessMediation',
            range: range,
        }
        ,
        {
            label: 'LAN Access Mediation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "LAN access mediation encompasses the application of strict access control policies, systematic verification of devices, and authentication mechanisms to govern connectivity to a Local Area Network.",
            insertText: 'LANAccessMediation',
            range: range,
        }
        ,
        {
            label: 'Routing Access Mediation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Routing access mediation is a network security approach that manages and controls access at the network layer using VPNs, tunneling protocols, firewall rules, and traffic inspection to ensure secure and efficient data routing.",
            insertText: 'RoutingAccessMediation',
            range: range,
        }
        ,
        {
            label: 'Network Resource Access Mediation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Control of access to organizational systems and services by users or processes over a network.",
            insertText: 'NetworkResourceAccessMediation',
            range: range,
        }
        ,
        {
            label: 'Remote File Access Mediation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Remote file access mediation is the process of managing and securing access to file systems over a network to ensure that only authorized users or processes can interact with remote files.",
            insertText: 'RemoteFileAccessMediation',
            range: range,
        }
        ,
        {
            label: 'Web Session Access Mediation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Web session access mediation secures user sessions in web applications by employing robust authentication and integrity validation, along with adaptive threat mitigation techniques, to ensure that access to web resources is authorized and protected from session-related attacks.",
            insertText: 'WebSessionAccessMediation',
            range: range,
        }
        ,
        {
            label: 'Endpoint-based Web Server Access Mediation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Endpoint-based web server access mediation regulates web server access directly from user endpoints by implementing mechanisms such as client-side certificates and endpoint security software to authenticate devices and ensure compliant access.",
            insertText: 'EndpointBasedWebServerAccessMediation',
            range: range,
        }
        ,
        {
            label: 'Proxy-based Web Server Access Mediation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Proxy-based web server access mediation focuses on the regulation of web server access through intermediary proxy servers.",
            insertText: 'ProxyBasedWebServerAccessMediation',
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
            label: 'System Call Filtering',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Controlling access to local computer system resources with kernel-level capabilities.",
            insertText: 'SystemCallFiltering',
            range: range,
        }
        ,
        {
            label: 'Local File Access Mediation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Restricting access to a local file by configuring operating system functionality.",
            insertText: 'LocalFileAccessMediation',
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
            label: 'Source Code Hardening',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Hardening source code with the intention of making it more difficult to exploit and less error prone.",
            insertText: 'SourceCodeHardening',
            range: range,
        }
        ,
        {
            label: 'Integer Range Validation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Ensuring that an integer is within a valid range.",
            insertText: 'IntegerRangeValidation',
            range: range,
        }
        ,
        {
            label: 'Reference Nullification',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Invalidating all pointers that reference a specific memory block, ensuring that the block cannot be accessed or modified after deallocation.",
            insertText: 'ReferenceNullification',
            range: range,
        }
        ,
        {
            label: 'Trusted Library',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "A trusted library is a collection of pre-verified and secure code modules or components that are used within software applications to perform specific functions. These libraries are considered reliable and have been vetted for security vulnerabilities, ensuring they do not introduce risks into the application.",
            insertText: 'TrustedLibrary',
            range: range,
        }
        ,
        {
            label: 'Variable Type Validation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Ensuring that a variable has the correct type.",
            insertText: 'VariableTypeValidation',
            range: range,
        }
        ,
        {
            label: 'Credential Scrubbing',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "The systematic removal of hard-coded credentials from source code to prevent accidental exposure and unauthorized access.",
            insertText: 'CredentialScrubbing',
            range: range,
        }
        ,
        {
            label: 'Variable Initialization',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Setting variables to a known value before use.",
            insertText: 'VariableInitialization',
            range: range,
        }
        ,
        {
            label: 'Pointer Validation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Ensuring that a pointer variable has the required properties for use.",
            insertText: 'PointerValidation',
            range: range,
        }
        ,
        {
            label: 'Memory Block Start Validation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Ensuring that a pointer accurately references the beginning of a designated memory block.",
            insertText: 'MemoryBlockStartValidation',
            range: range,
        }
        ,
        {
            label: 'Null Pointer Checking',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Checking if a pointer is NULL.",
            insertText: 'NullPointerChecking',
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
            label: 'Token Binding',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Token binding is a security mechanism used to enhance the protection of tokens, such as cookies or OAuth tokens, by binding them to a specific connection.",
            insertText: 'TokenBinding',
            range: range,
        }
        ,
        {
            label: 'Credential Rotation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Credential rotation is a security procedure in which authentication credentials, such as passwords, API keys, or certificates, are regularly changed or replaced to minimize the risk of unauthorized access.",
            insertText: 'CredentialRotation',
            range: range,
        }
        ,
        {
            label: 'Certificate Rotation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Certificate rotation involves replacing digital certificates and their private keys to maintain cryptographic integrity and trust, mitigating key compromise risks and ensuring continuous secure communications.",
            insertText: 'CertificateRotation',
            range: range,
        }
        ,
        {
            label: 'Password Rotation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Password rotation is a security policy that mandates the periodic change of user account passwords to mitigate the risk of unauthorized access due to compromised credentials.",
            insertText: 'PasswordRotation',
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
            label: 'Certificate Pinning',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Persisting either a server's X.509 certificate or their public key and comparing that to server's presented identity to allow for greater client confidence in the remote server's identity for SSL connections.",
            insertText: 'CertificatePinning',
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
            label: 'Stack Frame Canary Validation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Comparing a value stored in a stack frame with a known good value in order to prevent or detect a memory segment overwrite.",
            insertText: 'StackFrameCanaryValidation',
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
            label: 'Execution Isolation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Execution Isolation techniques prevent application processes from accessing non-essential system resources, such as memory, devices, or files.",
            insertText: 'ExecutionIsolation',
            range: range,
        }
        ,
        {
            label: 'Application-based Process Isolation',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Application code which prevents its own subroutines from accessing intra-process / internal memory space.",
            insertText: 'Application-basedProcessIsolation',
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
            label: 'Encrypted Tunnels',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Encrypted encapsulation of routable network traffic.",
            insertText: 'EncryptedTunnels',
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
            label: 'Emulated File Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Emulating instructions in a file looking for specific patterns.",
            insertText: 'EmulatedFileAnalysis',
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
            label: 'Platform Monitoring',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Monitoring platform components such as operating systems software, hardware devices, or firmware.",
            insertText: 'PlatformMonitoring',
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
            label: 'Network Traffic Signature Analysis',
            kind: monaco.languages.CompletionItemKind.Interface,
            documentation: "Analyzing network traffic and compares it to known signatures",
            insertText: 'NetworkTrafficSignatureAnalysis',
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
            label: 'Acquire Access',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may purchase or otherwise acquire an existing access to a target system or network. A variety of online services and initial access broker networks are available to sell access to previously compromised systems.(Citation: Microsoft Ransomware as a Service)(Citation: CrowdStrike Access Brokers)(Citation: Krebs Access Brokers Fortune 500) In some cases, adversary groups may form partnerships to share compromised systems with each other.(Citation: CISA Karakurt 2022)",
            insertText: 'T1650',
            range: range,
        }
        ,
        {
            label: 'Establish Accounts',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create and cultivate accounts with services that can be used during targeting. Adversaries can create accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations. This development could be applied to social media, website, or other publicly available information that could be referenced and scrutinized for legitimacy over the course of an operation using that persona or identity.(Citation: NEWSCASTER2014)(Citation: BlackHatRobinSage)",
            insertText: 'T1585',
            range: range,
        }
        ,
        {
            label: 'Social Media Accounts',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create and cultivate social media accounts that can be used during targeting. Adversaries can create social media accounts that can be used to build a persona to further operations. Persona development consists of the development of public information, presence, history and appropriate affiliations.(Citation: NEWSCASTER2014)(Citation: BlackHatRobinSage)",
            insertText: 'T1585.001',
            range: range,
        }
        ,
        {
            label: 'Email Accounts',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create email accounts that can be used during targeting. Adversaries can use accounts created with email providers to further their operations, such as leveraging them to conduct [Phishing for Information](https://attack.mitre.org/techniques/T1598) or [Phishing](https://attack.mitre.org/techniques/T1566).(Citation: Mandiant APT1) Establishing email accounts may also allow adversaries to abuse free services \u2013 such as trial periods \u2013 to [Acquire Infrastructure](https://attack.mitre.org/techniques/T1583) for follow-on purposes.(Citation: Free Trial PurpleUrchin)",
            insertText: 'T1585.002',
            range: range,
        }
        ,
        {
            label: 'Cloud Accounts',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create accounts with cloud providers that can be used during targeting. Adversaries can use cloud accounts to further their operations, including leveraging cloud storage services such as Dropbox, MEGA, Microsoft OneDrive, or AWS S3 buckets for [Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002) or to [Upload Tool](https://attack.mitre.org/techniques/T1608/002)s. Cloud accounts can also be used in the acquisition of infrastructure, such as [Virtual Private Server](https://attack.mitre.org/techniques/T1583/003)s or [Serverless](https://attack.mitre.org/techniques/T1583/007) infrastructure. Establishing cloud accounts may allow adversaries to develop sophisticated capabilities without managing their own servers.(Citation: Awake Security C2 Cloud)",
            insertText: 'T1585.003',
            range: range,
        }
        ,
        {
            label: 'Compromise Accounts',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may compromise accounts with services that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating accounts (i.e. [Establish Accounts](https://attack.mitre.org/techniques/T1585)), adversaries may compromise existing accounts. Utilizing an existing persona may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona.",
            insertText: 'T1586',
            range: range,
        }
        ,
        {
            label: 'Social Media Accounts',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may compromise social media accounts that can be used during targeting. For operations incorporating social engineering, the utilization of an online persona may be important. Rather than creating and cultivating social media profiles (i.e. [Social Media Accounts](https://attack.mitre.org/techniques/T1585/001)), adversaries may compromise existing social media accounts. Utilizing an existing persona may engender a level of trust in a potential victim if they have a relationship, or knowledge of, the compromised persona.",
            insertText: 'T1586.001',
            range: range,
        }
        ,
        {
            label: 'Email Accounts',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may compromise email accounts that can be used during targeting. Adversaries can use compromised email accounts to further their operations, such as leveraging them to conduct [Phishing for Information](https://attack.mitre.org/techniques/T1598), [Phishing](https://attack.mitre.org/techniques/T1566), or large-scale spam email campaigns. Utilizing an existing persona with a compromised email account may engender a level of trust in a potential victim if they have a relationship with, or knowledge of, the compromised persona. Compromised email accounts can also be used in the acquisition of infrastructure (ex: [Domains](https://attack.mitre.org/techniques/T1583/001)).",
            insertText: 'T1586.002',
            range: range,
        }
        ,
        {
            label: 'Cloud Accounts',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may compromise cloud accounts that can be used during targeting. Adversaries can use compromised cloud accounts to further their operations, including leveraging cloud storage services such as Dropbox, Microsoft OneDrive, or AWS S3 buckets for [Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002) or to [Upload Tool](https://attack.mitre.org/techniques/T1608/002)s. Cloud accounts can also be used in the acquisition of infrastructure, such as [Virtual Private Server](https://attack.mitre.org/techniques/T1583/003)s or [Serverless](https://attack.mitre.org/techniques/T1583/007) infrastructure. Compromising cloud accounts may allow adversaries to develop sophisticated capabilities without managing their own servers.(Citation: Awake Security C2 Cloud)",
            insertText: 'T1586.003',
            range: range,
        }
        ,
        {
            label: 'Develop Capabilities',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may build capabilities that can be used during targeting. Rather than purchasing, freely downloading, or stealing capabilities, adversaries may develop their own capabilities in-house. This is the process of identifying development requirements and building solutions such as malware, exploits, and self-signed certificates. Adversaries may develop capabilities to support their operations throughout numerous phases of the adversary lifecycle.(Citation: Mandiant APT1)(Citation: Kaspersky Sofacy)(Citation: Bitdefender StrongPity June 2020)(Citation: Talos Promethium June 2020)",
            insertText: 'T1587',
            range: range,
        }
        ,
        {
            label: 'Malware',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may develop malware and malware components that can be used during targeting. Building malicious software can include the development of payloads, droppers, post-compromise tools, backdoors (including backdoored images), packers, C2 protocols, and the creation of infected removable media. Adversaries may develop malware to support their operations, creating a means for maintaining control of remote machines, evading defenses, and executing post-compromise behaviors.(Citation: Mandiant APT1)(Citation: Kaspersky Sofacy)(Citation: ActiveMalwareEnergy)(Citation: FBI Flash FIN7 USB)",
            insertText: 'T1587.001',
            range: range,
        }
        ,
        {
            label: 'Code Signing Certificates',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create self-signed code signing certificates that can be used during targeting. Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted. Code signing provides a level of authenticity for a program from the developer and a guarantee that the program has not been tampered with.(Citation: Wikipedia Code Signing) Users and/or security tools may trust a signed piece of code more than an unsigned piece of code even if they don't know who issued the certificate or who the author is.",
            insertText: 'T1587.002',
            range: range,
        }
        ,
        {
            label: 'Digital Certificates',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create self-signed SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are designed to instill trust. They include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate with its owner. In the case of self-signing, digital certificates will lack the element of trust associated with the signature of a third-party certificate authority (CA).",
            insertText: 'T1587.003',
            range: range,
        }
        ,
        {
            label: 'Exploits',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may develop exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software. Rather than finding/modifying exploits from online or purchasing them from exploit vendors, an adversary may develop their own exploits.(Citation: NYTStuxnet) Adversaries may use information acquired via [Vulnerabilities](https://attack.mitre.org/techniques/T1588/006) to focus exploit development efforts. As part of the exploit development process, adversaries may uncover exploitable vulnerabilities through methods such as fuzzing and patch analysis.(Citation: Irongeek Sims BSides 2017)",
            insertText: 'T1587.004',
            range: range,
        }
        ,
        {
            label: 'Stage Capabilities',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may upload, install, or otherwise set up capabilities that can be used during targeting. To support their operations, an adversary may need to take capabilities they developed ([Develop Capabilities](https://attack.mitre.org/techniques/T1587)) or obtained ([Obtain Capabilities](https://attack.mitre.org/techniques/T1588)) and stage them on infrastructure under their control. These capabilities may be staged on infrastructure that was previously purchased/rented by the adversary ([Acquire Infrastructure](https://attack.mitre.org/techniques/T1583)) or was otherwise compromised by them ([Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)). Capabilities may also be staged on web services, such as GitHub or Pastebin, or on Platform-as-a-Service (PaaS) offerings that enable users to easily provision applications.(Citation: Volexity Ocean Lotus November 2020)(Citation: Dragos Heroku Watering Hole)(Citation: Malwarebytes Heroku Skimmers)(Citation: Netskope GCP Redirection)(Citation: Netskope Cloud Phishing)",
            insertText: 'T1608',
            range: range,
        }
        ,
        {
            label: 'Upload Malware',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may upload malware to third-party or adversary controlled infrastructure to make it accessible during targeting. Malicious software can include payloads, droppers, post-compromise tools, backdoors, and a variety of other malicious content. Adversaries may upload malware to support their operations, such as making a payload available to a victim network to enable [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) by placing it on an Internet accessible web server.",
            insertText: 'T1608.001',
            range: range,
        }
        ,
        {
            label: 'Upload Tool',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may upload tools to third-party or adversary controlled infrastructure to make it accessible during targeting. Tools can be open or closed source, free or commercial. Tools can be used for malicious purposes by an adversary, but (unlike malware) were not intended to be used for those purposes (ex: [PsExec](https://attack.mitre.org/software/S0029)). Adversaries may upload tools to support their operations, such as making a tool available to a victim network to enable [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105) by placing it on an Internet accessible web server.",
            insertText: 'T1608.002',
            range: range,
        }
        ,
        {
            label: 'Install Digital Certificate',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may install SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are files that can be installed on servers to enable secure communications between systems. Digital certificates include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate securely with its owner. Certificates can be uploaded to a server, then the server can be configured to use the certificate to enable encrypted communication with it.(Citation: DigiCert Install SSL Cert)",
            insertText: 'T1608.003',
            range: range,
        }
        ,
        {
            label: 'Drive-by Target',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may prepare an operational environment to infect systems that visit a website over the normal course of browsing. Endpoint systems may be compromised through browsing to adversary controlled sites, as in [Drive-by Compromise](https://attack.mitre.org/techniques/T1189). In such cases, the user's web browser is typically targeted for exploitation (often not requiring any extra user interaction once landing on the site), but adversaries may also set up websites for non-exploitation behavior such as [Application Access Token](https://attack.mitre.org/techniques/T1550/001). Prior to [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), adversaries must stage resources needed to deliver that exploit to users who browse to an adversary controlled site. Drive-by content can be staged on adversary controlled infrastructure that has been acquired ([Acquire Infrastructure](https://attack.mitre.org/techniques/T1583)) or previously compromised ([Compromise Infrastructure](https://attack.mitre.org/techniques/T1584)).",
            insertText: 'T1608.004',
            range: range,
        }
        ,
        {
            label: 'Link Target',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may put in place resources that are referenced by a link that can be used during targeting. An adversary may rely upon a user clicking a malicious link in order to divulge information (including credentials) or to gain execution, as in [Malicious Link](https://attack.mitre.org/techniques/T1204/001). Links can be used for spearphishing, such as sending an email accompanied by social engineering text to coax the user to actively click or copy and paste a URL into a browser. Prior to a phish for information (as in [Spearphishing Link](https://attack.mitre.org/techniques/T1598/003)) or a phish to gain initial access to a system (as in [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002)), an adversary must set up the resources for a link target for the spearphishing link.",
            insertText: 'T1608.005',
            range: range,
        }
        ,
        {
            label: 'SEO Poisoning',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may poison mechanisms that influence search engine optimization (SEO) to further lure staged capabilities towards potential victims. Search engines typically display results to users based on purchased ads as well as the site\u2019s ranking/score/reputation calculated by their web crawlers and algorithms.(Citation: Atlas SEO)(Citation: MalwareBytes SEO)",
            insertText: 'T1608.006',
            range: range,
        }
        ,
        {
            label: 'Obtain Capabilities',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may buy and/or steal capabilities that can be used during targeting. Rather than developing their own capabilities in-house, adversaries may purchase, freely download, or steal them. Activities may include the acquisition of malware, software (including licenses), exploits, certificates, and information relating to vulnerabilities. Adversaries may obtain capabilities to support their operations throughout numerous phases of the adversary lifecycle.",
            insertText: 'T1588',
            range: range,
        }
        ,
        {
            label: 'Malware',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may buy, steal, or download malware that can be used during targeting. Malicious software can include payloads, droppers, post-compromise tools, backdoors, packers, and C2 protocols. Adversaries may acquire malware to support their operations, obtaining a means for maintaining control of remote machines, evading defenses, and executing post-compromise behaviors.",
            insertText: 'T1588.001',
            range: range,
        }
        ,
        {
            label: 'Tool',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may buy, steal, or download software tools that can be used during targeting. Tools can be open or closed source, free or commercial. A tool can be used for malicious purposes by an adversary, but (unlike malware) were not intended to be used for those purposes (ex: [PsExec](https://attack.mitre.org/software/S0029)). Tool acquisition can involve the procurement of commercial software licenses, including for red teaming tools such as [Cobalt Strike](https://attack.mitre.org/software/S0154). Commercial software may be obtained through purchase, stealing licenses (or licensed copies of the software), or cracking trial versions.(Citation: Recorded Future Beacon 2019)",
            insertText: 'T1588.002',
            range: range,
        }
        ,
        {
            label: 'Code Signing Certificates',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may buy and/or steal code signing certificates that can be used during targeting. Code signing is the process of digitally signing executables and scripts to confirm the software author and guarantee that the code has not been altered or corrupted. Code signing provides a level of authenticity for a program from the developer and a guarantee that the program has not been tampered with.(Citation: Wikipedia Code Signing) Users and/or security tools may trust a signed piece of code more than an unsigned piece of code even if they don't know who issued the certificate or who the author is.",
            insertText: 'T1588.003',
            range: range,
        }
        ,
        {
            label: 'Digital Certificates',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may buy and/or steal SSL/TLS certificates that can be used during targeting. SSL/TLS certificates are designed to instill trust. They include information about the key, information about its owner's identity, and the digital signature of an entity that has verified the certificate's contents are correct. If the signature is valid, and the person examining the certificate trusts the signer, then they know they can use that key to communicate with its owner.",
            insertText: 'T1588.004',
            range: range,
        }
        ,
        {
            label: 'Exploits',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may buy, steal, or download exploits that can be used during targeting. An exploit takes advantage of a bug or vulnerability in order to cause unintended or unanticipated behavior to occur on computer hardware or software. Rather than developing their own exploits, an adversary may find/modify exploits from online or purchase them from exploit vendors.(Citation: Exploit Database)(Citation: TempertonDarkHotel)(Citation: NationsBuying)",
            insertText: 'T1588.005',
            range: range,
        }
        ,
        {
            label: 'Vulnerabilities',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may acquire information about vulnerabilities that can be used during targeting. A vulnerability is a weakness in computer hardware or software that can, potentially, be exploited by an adversary to cause unintended or unanticipated behavior to occur. Adversaries may find vulnerability information by searching open databases or gaining access to closed vulnerability databases.(Citation: National Vulnerability Database)",
            insertText: 'T1588.006',
            range: range,
        }
        ,
        {
            label: 'Artificial Intelligence',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may obtain access to generative artificial intelligence tools, such as large language models (LLMs), to aid various techniques during targeting. These tools may be used to inform, bolster, and enable a variety of malicious tasks including conducting [Reconnaissance](https://attack.mitre.org/tactics/TA0043), creating basic scripts, assisting social engineering, and even developing payloads.(Citation: MSFT-AI)",
            insertText: 'T1588.007',
            range: range,
        }
        ,
        {
            label: 'Acquire Infrastructure',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may buy, lease, rent, or obtain infrastructure that can be used during targeting. A wide variety of infrastructure exists for hosting and orchestrating adversary operations. Infrastructure solutions include physical or cloud servers, domains, and third-party web services.(Citation: TrendmicroHideoutsLease) Some infrastructure providers offer free trial periods, enabling infrastructure acquisition at limited to no cost.(Citation: Free Trial PurpleUrchin) Additionally, botnets are available for rent or purchase.",
            insertText: 'T1583',
            range: range,
        }
        ,
        {
            label: 'Domains',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may acquire domains that can be used during targeting. Domain names are the human readable names used to represent one or more IP addresses. They can be purchased or, in some cases, acquired for free.",
            insertText: 'T1583.001',
            range: range,
        }
        ,
        {
            label: 'DNS Server',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may set up their own Domain Name System (DNS) servers that can be used during targeting. During post-compromise activity, adversaries may utilize DNS traffic for various tasks, including for Command and Control (ex: [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)). Instead of hijacking existing DNS servers, adversaries may opt to configure and run their own DNS servers in support of operations.",
            insertText: 'T1583.002',
            range: range,
        }
        ,
        {
            label: 'Virtual Private Server',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may rent Virtual Private Servers (VPSs)\u00a0that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. By utilizing a VPS, adversaries can make it difficult to physically tie back operations to them. The use of cloud infrastructure can also make it easier for adversaries to rapidly provision, modify, and shut down their infrastructure.",
            insertText: 'T1583.003',
            range: range,
        }
        ,
        {
            label: 'Server',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may buy, lease, rent, or obtain physical servers\u00a0that can be used during targeting. Use of servers allows an adversary to stage, launch, and execute an operation. During post-compromise activity, adversaries may utilize servers for various tasks, such as watering hole operations in [Drive-by Compromise](https://attack.mitre.org/techniques/T1189), enabling [Phishing](https://attack.mitre.org/techniques/T1566) operations, or facilitating [Command and Control](https://attack.mitre.org/tactics/TA0011). Instead of compromising a third-party [Server](https://attack.mitre.org/techniques/T1584/004) or renting a [Virtual Private Server](https://attack.mitre.org/techniques/T1583/003), adversaries may opt to configure and run their own servers in support of operations. Free trial periods of cloud servers may also be abused.(Citation: Free Trial PurpleUrchin)(Citation: Freejacked)",
            insertText: 'T1583.004',
            range: range,
        }
        ,
        {
            label: 'Botnet',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may buy, lease, or rent a network of compromised systems\u00a0that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks.(Citation: Norton Botnet) Adversaries may purchase a subscription to use an existing botnet from a booter/stresser service. With a botnet at their disposal, adversaries may perform follow-on activity such as large-scale [Phishing](https://attack.mitre.org/techniques/T1566) or Distributed Denial of Service (DDoS).(Citation: Imperva DDoS for Hire)(Citation: Krebs-Anna)(Citation: Krebs-Bazaar)(Citation: Krebs-Booter)",
            insertText: 'T1583.005',
            range: range,
        }
        ,
        {
            label: 'Web Services',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may register for web services\u00a0that can be used during targeting. A variety of popular websites exist for adversaries to register for a web-based service that can be abused during later stages of the adversary lifecycle, such as during Command and Control ([Web Service](https://attack.mitre.org/techniques/T1102)), [Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567), or [Phishing](https://attack.mitre.org/techniques/T1566). Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise.(Citation: FireEye APT29) By utilizing a web service, adversaries can make it difficult to physically tie back operations to them.",
            insertText: 'T1583.006',
            range: range,
        }
        ,
        {
            label: 'Serverless',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may purchase and configure serverless cloud infrastructure, such as Cloudflare Workers or AWS Lambda functions, that can be used during targeting. By utilizing serverless infrastructure, adversaries can make it more difficult to attribute infrastructure used during operations back to them.",
            insertText: 'T1583.007',
            range: range,
        }
        ,
        {
            label: 'Malvertising',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may purchase online advertisements that can be abused to distribute malware to victims. Ads can be purchased to plant as well as favorably position artifacts in specific locations  online, such as prominently placed within search engine results. These ads may make it more difficult for users to distinguish between actual search results and advertisements.(Citation: spamhaus-malvertising) Purchased ads may also target specific audiences using the advertising network\u2019s capabilities, potentially further taking advantage of the trust inherently given to search engines and popular websites.",
            insertText: 'T1583.008',
            range: range,
        }
        ,
        {
            label: 'Compromise Infrastructure',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may compromise third-party infrastructure that can be used during targeting. Infrastructure solutions include physical or cloud servers, domains, network devices, and third-party web and DNS services. Instead of buying, leasing, or renting infrastructure an adversary may compromise infrastructure and use it during other phases of the adversary lifecycle.(Citation: Mandiant APT1)(Citation: ICANNDomainNameHijacking)(Citation: Talos DNSpionage Nov 2018)(Citation: FireEye EPS Awakens Part 2) Additionally, adversaries may compromise numerous machines to form a botnet they can leverage.",
            insertText: 'T1584',
            range: range,
        }
        ,
        {
            label: 'Domains',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may hijack domains and/or subdomains that can be used during targeting. Domain registration hijacking is the act of changing the registration of a domain name without the permission of the original registrant.(Citation: ICANNDomainNameHijacking) Adversaries may gain access to an email account for the person listed as the owner of the domain. The adversary can then claim that they forgot their password in order to make changes to the domain registration. Other possibilities include social engineering a domain registration help desk to gain access to an account or taking advantage of renewal process gaps.(Citation: Krebs DNS Hijack 2019)",
            insertText: 'T1584.001',
            range: range,
        }
        ,
        {
            label: 'DNS Server',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may compromise third-party DNS servers that can be used during targeting. During post-compromise activity, adversaries may utilize DNS traffic for various tasks, including for Command and Control (ex: [Application Layer Protocol](https://attack.mitre.org/techniques/T1071)). Instead of setting up their own DNS servers, adversaries may compromise third-party DNS servers in support of operations.",
            insertText: 'T1584.002',
            range: range,
        }
        ,
        {
            label: 'Virtual Private Server',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may compromise third-party Virtual Private Servers (VPSs) that can be used during targeting. There exist a variety of cloud service providers that will sell virtual machines/containers as a service. Adversaries may compromise VPSs purchased by third-party entities. By compromising a VPS to use as infrastructure, adversaries can make it difficult to physically tie back operations to themselves.(Citation: NSA NCSC Turla OilRig)",
            insertText: 'T1584.003',
            range: range,
        }
        ,
        {
            label: 'Server',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may compromise third-party servers that can be used during targeting. Use of servers allows an adversary to stage, launch, and execute an operation. During post-compromise activity, adversaries may utilize servers for various tasks, including for Command and Control.(Citation: TrendMicro EarthLusca 2022) Instead of purchasing a [Server](https://attack.mitre.org/techniques/T1583/004) or [Virtual Private Server](https://attack.mitre.org/techniques/T1583/003), adversaries may compromise third-party servers in support of operations.",
            insertText: 'T1584.004',
            range: range,
        }
        ,
        {
            label: 'Botnet',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may compromise numerous third-party systems to form a botnet\u00a0that can be used during targeting. A botnet is a network of compromised systems that can be instructed to perform coordinated tasks.(Citation: Norton Botnet) Instead of purchasing/renting a botnet from a booter/stresser service, adversaries may build their own botnet by compromising numerous third-party systems.(Citation: Imperva DDoS for Hire) Adversaries may also conduct a takeover of an existing botnet, such as redirecting bots to adversary-controlled C2 servers.(Citation: Dell Dridex Oct 2015) With a botnet at their disposal, adversaries may perform follow-on activity such as large-scale [Phishing](https://attack.mitre.org/techniques/T1566) or Distributed Denial of Service (DDoS).",
            insertText: 'T1584.005',
            range: range,
        }
        ,
        {
            label: 'Web Services',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may compromise access to third-party web services\u00a0that can be used during targeting. A variety of popular websites exist for legitimate users to register for web-based services, such as GitHub, Twitter, Dropbox, Google, SendGrid, etc. Adversaries may try to take ownership of a legitimate user's access to a web service and use that web service as infrastructure in support of cyber operations. Such web services can be abused during later stages of the adversary lifecycle, such as during Command and Control ([Web Service](https://attack.mitre.org/techniques/T1102)), [Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567), or [Phishing](https://attack.mitre.org/techniques/T1566).(Citation: Recorded Future Turla Infra 2020) Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. By utilizing a web service, particularly when access is stolen from legitimate users, adversaries can make it difficult to physically tie back operations to them. Additionally, leveraging compromised web-based email services may allow adversaries to leverage the trust associated with legitimate domains.",
            insertText: 'T1584.006',
            range: range,
        }
        ,
        {
            label: 'Serverless',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may compromise serverless cloud infrastructure, such as Cloudflare Workers or AWS Lambda functions, that can be used during targeting. By utilizing serverless infrastructure, adversaries can make it more difficult to attribute infrastructure used during operations back to them.",
            insertText: 'T1584.007',
            range: range,
        }
        ,
        {
            label: 'Network Devices',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may compromise third-party network devices that can be used during targeting. Network devices, such as small office/home office (SOHO) routers, may be compromised where the adversary's ultimate goal is not [Initial Access](https://attack.mitre.org/tactics/TA0001) to that environment -- instead leveraging these devices to support additional targeting.",
            insertText: 'T1584.008',
            range: range,
        }
        ,
        {
            label: 'Search Victim-Owned Websites',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search websites owned by the victim for information that can be used during targeting. Victim-owned websites may contain a variety of details, including names of departments/divisions, physical locations, and data about key employees such as names, roles, and contact info (ex: [Email Addresses](https://attack.mitre.org/techniques/T1589/002)). These sites may also have details highlighting business operations and relationships.(Citation: Comparitech Leak)",
            insertText: 'T1594',
            range: range,
        }
        ,
        {
            label: 'Search Closed Sources',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search and gather information about victims from closed sources that can be used during targeting. Information about victims may be available for purchase from reputable private sources and databases, such as paid subscriptions to feeds of technical/threat intelligence data.(Citation: D3Secutrity CTI Feeds) Adversaries may also purchase information from less-reputable sources such as dark web or cybercrime blackmarkets.(Citation: ZDNET Selling Data)",
            insertText: 'T1597',
            range: range,
        }
        ,
        {
            label: 'Threat Intel Vendors',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search private data from threat intelligence vendors for information that can be used during targeting. Threat intelligence vendors may offer paid feeds or portals that offer more data than what is publicly reported. Although sensitive details (such as customer names and other identifiers) may be redacted, this information may contain trends regarding breaches such as target industries, attribution claims, and successful TTPs/countermeasures.(Citation: D3Secutrity CTI Feeds)",
            insertText: 'T1597.001',
            range: range,
        }
        ,
        {
            label: 'Purchase Technical Data',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may purchase technical information about victims that can be used during targeting. Information about victims may be available for purchase within reputable private sources and databases, such as paid subscriptions to feeds of scan databases or other data aggregation services. Adversaries may also purchase information from less-reputable sources such as dark web or cybercrime blackmarkets.",
            insertText: 'T1597.002',
            range: range,
        }
        ,
        {
            label: 'Gather Victim Identity Information',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather information about the victim's identity that can be used during targeting. Information about identities may include a variety of details, including personal data (ex: employee names, email addresses, security question responses, etc.) as well as sensitive details such as credentials or multi-factor authentication (MFA) configurations.",
            insertText: 'T1589',
            range: range,
        }
        ,
        {
            label: 'Credentials',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather credentials that can be used during targeting. Account credentials gathered by adversaries may be those directly associated with the target victim organization or attempt to take advantage of the tendency for users to use the same passwords across personal and business accounts.",
            insertText: 'T1589.001',
            range: range,
        }
        ,
        {
            label: 'Email Addresses',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather email addresses that can be used during targeting. Even if internal instances exist, organizations may have public-facing email infrastructure and addresses for employees.",
            insertText: 'T1589.002',
            range: range,
        }
        ,
        {
            label: 'Employee Names',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather employee names that can be used during targeting. Employee names be used to derive email addresses as well as to help guide other reconnaissance efforts and/or craft more-believable lures.",
            insertText: 'T1589.003',
            range: range,
        }
        ,
        {
            label: 'Search Open Websites/Domains',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search freely available websites and/or domains for information about victims that can be used during targeting. Information about victims may be available in various online sites, such as social media, new sites, or those hosting information about business operations such as hiring or requested/rewarded contracts.(Citation: Cyware Social Media)(Citation: SecurityTrails Google Hacking)(Citation: ExploitDB GoogleHacking)",
            insertText: 'T1593',
            range: range,
        }
        ,
        {
            label: 'Social Media',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search social media for information about victims that can be used during targeting. Social media sites may contain various information about a victim organization, such as business announcements as well as information about the roles, locations, and interests of staff.",
            insertText: 'T1593.001',
            range: range,
        }
        ,
        {
            label: 'Search Engines',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use search engines to collect information about victims that can be used during targeting. Search engine services typical crawl online sites to index context and may provide users with specialized syntax to search for specific keywords or specific types of content (i.e. filetypes).(Citation: SecurityTrails Google Hacking)(Citation: ExploitDB GoogleHacking)",
            insertText: 'T1593.002',
            range: range,
        }
        ,
        {
            label: 'Code Repositories',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search public code repositories for information about victims that can be used during targeting. Victims may store code in repositories on various third-party websites such as GitHub, GitLab, SourceForge, and BitBucket. Users typically interact with code repositories through a web application or command-line utilities such as git.",
            insertText: 'T1593.003',
            range: range,
        }
        ,
        {
            label: 'Active Scanning',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting. Active scans are those where the adversary probes victim infrastructure via network traffic, as opposed to other forms of reconnaissance that do not involve direct interaction.",
            insertText: 'T1595',
            range: range,
        }
        ,
        {
            label: 'Scanning IP Blocks',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may scan victim IP blocks to gather information that can be used during targeting. Public IP addresses may be allocated to organizations by block, or a range of sequential addresses.",
            insertText: 'T1595.001',
            range: range,
        }
        ,
        {
            label: 'Vulnerability Scanning',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may scan victims for vulnerabilities that can be used during targeting. Vulnerability scans typically check if the configuration of a target host/application (ex: software and version) potentially aligns with the target of a specific exploit the adversary may seek to use.",
            insertText: 'T1595.002',
            range: range,
        }
        ,
        {
            label: 'Wordlist Scanning',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may iteratively probe infrastructure using brute-forcing and crawling techniques. While this technique employs similar methods to [Brute Force](https://attack.mitre.org/techniques/T1110), its goal is the identification of content and infrastructure rather than the discovery of valid credentials. Wordlists used in these scans may contain generic, commonly used names and file extensions or terms specific to a particular software. Adversaries may also create custom, target-specific wordlists using data gathered from other Reconnaissance techniques (ex: [Gather Victim Org Information](https://attack.mitre.org/techniques/T1591), or [Search Victim-Owned Websites](https://attack.mitre.org/techniques/T1594)).",
            insertText: 'T1595.003',
            range: range,
        }
        ,
        {
            label: 'Gather Victim Org Information',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather information about the victim's organization that can be used during targeting. Information about an organization may include a variety of details, including the names of divisions/departments, specifics of business operations, as well as the roles and responsibilities of key employees.",
            insertText: 'T1591',
            range: range,
        }
        ,
        {
            label: 'Determine Physical Locations',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather the victim's physical location(s) that can be used during targeting. Information about physical locations of a target organization may include a variety of details, including where key resources and infrastructure are housed. Physical locations may also indicate what legal jurisdiction and/or authorities the victim operates within.",
            insertText: 'T1591.001',
            range: range,
        }
        ,
        {
            label: 'Business Relationships',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather information about the victim's business relationships that can be used during targeting. Information about an organization\u2019s business relationships may include a variety of details, including second or third-party organizations/domains (ex: managed service providers, contractors, etc.) that have connected (and potentially elevated) network access. This information may also reveal supply chains and shipment paths for the victim\u2019s hardware and software resources.",
            insertText: 'T1591.002',
            range: range,
        }
        ,
        {
            label: 'Identify Business Tempo',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather information about the victim's business tempo that can be used during targeting. Information about an organization\u2019s business tempo may include a variety of details, including operational hours/days of the week. This information may also reveal times/dates of purchases and shipments of the victim\u2019s hardware and software resources.",
            insertText: 'T1591.003',
            range: range,
        }
        ,
        {
            label: 'Identify Roles',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather information about identities and roles within the victim organization that can be used during targeting. Information about business roles may reveal a variety of targetable details, including identifiable information for key personnel as well as what data/resources they have access to.",
            insertText: 'T1591.004',
            range: range,
        }
        ,
        {
            label: 'Gather Victim Host Information',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather information about the victim's hosts that can be used during targeting. Information about hosts may include a variety of details, including administrative data (ex: name, assigned IP, functionality, etc.) as well as specifics regarding its configuration (ex: operating system, language, etc.).",
            insertText: 'T1592',
            range: range,
        }
        ,
        {
            label: 'Hardware',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather information about the victim's host hardware that can be used during targeting. Information about hardware infrastructure may include a variety of details such as types and versions on specific hosts, as well as the presence of additional components that might be indicative of added defensive protections (ex: card/biometric readers, dedicated encryption hardware, etc.).",
            insertText: 'T1592.001',
            range: range,
        }
        ,
        {
            label: 'Software',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather information about the victim's host software that can be used during targeting. Information about installed software may include a variety of details such as types and versions on specific hosts, as well as the presence of additional components that might be indicative of added defensive protections (ex: antivirus, SIEMs, etc.).",
            insertText: 'T1592.002',
            range: range,
        }
        ,
        {
            label: 'Firmware',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather information about the victim's host firmware that can be used during targeting. Information about host firmware may include a variety of details such as type and versions on specific hosts, which may be used to infer more information about hosts in the environment (ex: configuration, purpose, age/patch level, etc.).",
            insertText: 'T1592.003',
            range: range,
        }
        ,
        {
            label: 'Client Configurations',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather information about the victim's client configurations that can be used during targeting. Information about client configurations may include a variety of details and settings, including operating system/version, virtualization, architecture (ex: 32 or 64 bit), language, and/or time zone.",
            insertText: 'T1592.004',
            range: range,
        }
        ,
        {
            label: 'Phishing for Information',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may send phishing messages to elicit sensitive information that can be used during targeting. Phishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Phishing for information is different from [Phishing](https://attack.mitre.org/techniques/T1566) in that the objective is gathering data from the victim rather than executing malicious code.",
            insertText: 'T1598',
            range: range,
        }
        ,
        {
            label: 'Spearphishing Service',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may send spearphishing messages via third-party services to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)) and/or sending multiple, seemingly urgent messages.",
            insertText: 'T1598.001',
            range: range,
        }
        ,
        {
            label: 'Spearphishing Attachment',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may send spearphishing messages with a malicious attachment to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)) and/or sending multiple, seemingly urgent messages.",
            insertText: 'T1598.002',
            range: range,
        }
        ,
        {
            label: 'Spearphishing Link',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may send spearphishing messages with a malicious link to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: [Establish Accounts](https://attack.mitre.org/techniques/T1585) or [Compromise Accounts](https://attack.mitre.org/techniques/T1586)) and/or sending multiple, seemingly urgent messages.",
            insertText: 'T1598.003',
            range: range,
        }
        ,
        {
            label: 'Spearphishing Voice',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use voice communications to elicit sensitive information that can be used during targeting. Spearphishing for information is an attempt to trick targets into divulging information, frequently credentials or other actionable information. Spearphishing for information frequently involves social engineering techniques, such as posing as a source with a reason to collect information (ex: [Impersonation](https://attack.mitre.org/techniques/T1656)) and/or creating a sense of urgency or alarm for the recipient.",
            insertText: 'T1598.004',
            range: range,
        }
        ,
        {
            label: 'Search Open Technical Databases',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search freely available technical databases for information about victims that can be used during targeting. Information about victims may be available in online databases and repositories, such as registrations of domains/certificates as well as public collections of network data/artifacts gathered from traffic and/or scans.(Citation: WHOIS)(Citation: DNS Dumpster)(Citation: Circl Passive DNS)(Citation: Medium SSL Cert)(Citation: SSLShopper Lookup)(Citation: DigitalShadows CDN)(Citation: Shodan)",
            insertText: 'T1596',
            range: range,
        }
        ,
        {
            label: 'DNS/Passive DNS',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search DNS data for information about victims that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target\u2019s subdomains, mail servers, and other hosts.",
            insertText: 'T1596.001',
            range: range,
        }
        ,
        {
            label: 'WHOIS',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search public WHOIS data for information about victims that can be used during targeting. WHOIS data is stored by regional Internet registries (RIR) responsible for allocating and assigning Internet resources such as domain names. Anyone can query WHOIS servers for information about a registered domain, such as assigned IP blocks, contact information, and DNS nameservers.(Citation: WHOIS)",
            insertText: 'T1596.002',
            range: range,
        }
        ,
        {
            label: 'Digital Certificates',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search public digital certificate data for information about victims that can be used during targeting. Digital certificates are issued by a certificate authority (CA) in order to cryptographically verify the origin of signed content. These certificates, such as those used for encrypted web traffic (HTTPS SSL/TLS communications), contain information about the registered organization such as name and location.",
            insertText: 'T1596.003',
            range: range,
        }
        ,
        {
            label: 'CDNs',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search content delivery network (CDN) data about victims that can be used during targeting. CDNs allow an organization to host content from a distributed, load balanced array of servers. CDNs may also allow organizations to customize content delivery based on the requestor\u2019s geographical region.",
            insertText: 'T1596.004',
            range: range,
        }
        ,
        {
            label: 'Scan Databases',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search within public scan databases for information about victims that can be used during targeting. Various online services continuously publish the results of Internet scans/surveys, often harvesting information such as active IP addresses, hostnames, open ports, certificates, and even server banners.(Citation: Shodan)",
            insertText: 'T1596.005',
            range: range,
        }
        ,
        {
            label: 'Gather Victim Network Information',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather information about the victim's networks that can be used during targeting. Information about networks may include a variety of details, including administrative data (ex: IP ranges, domain names, etc.) as well as specifics regarding its topology and operations.",
            insertText: 'T1590',
            range: range,
        }
        ,
        {
            label: 'Domain Properties',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather information about the victim's network domain(s) that can be used during targeting. Information about domains and their properties may include a variety of details, including what domain(s) the victim owns as well as administrative data (ex: name, registrar, etc.) and more directly actionable information such as contacts (email addresses and phone numbers), business addresses, and name servers.",
            insertText: 'T1590.001',
            range: range,
        }
        ,
        {
            label: 'DNS',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather information about the victim's DNS that can be used during targeting. DNS information may include a variety of details, including registered name servers as well as records that outline addressing for a target\u2019s subdomains, mail servers, and other hosts. DNS, MX, TXT, and SPF records may also reveal the use of third party cloud and SaaS providers, such as Office 365, G Suite, Salesforce, or Zendesk.(Citation: Sean Metcalf Twitter DNS Records)",
            insertText: 'T1590.002',
            range: range,
        }
        ,
        {
            label: 'Network Trust Dependencies',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather information about the victim's network trust dependencies that can be used during targeting. Information about network trusts may include a variety of details, including second or third-party organizations/domains (ex: managed service providers, contractors, etc.) that have connected (and potentially elevated) network access.",
            insertText: 'T1590.003',
            range: range,
        }
        ,
        {
            label: 'Network Topology',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather information about the victim's network topology that can be used during targeting. Information about network topologies may include a variety of details, including the physical and/or logical arrangement of both external-facing and internal network environments. This information may also include specifics regarding network devices (gateways, routers, etc.) and other infrastructure.",
            insertText: 'T1590.004',
            range: range,
        }
        ,
        {
            label: 'IP Addresses',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather the victim's IP addresses that can be used during targeting. Public IP addresses may be allocated to organizations by block, or a range of sequential addresses. Information about assigned IP addresses may include a variety of details, such as which IP addresses are in use. IP addresses may also enable an adversary to derive other details about a victim, such as organizational size, physical location(s), Internet service provider, and or where/how their publicly-facing infrastructure is hosted.",
            insertText: 'T1590.005',
            range: range,
        }
        ,
        {
            label: 'Network Security Appliances',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather information about the victim's network security appliances that can be used during targeting. Information about network security appliances may include a variety of details, such as the existence and specifics of deployed firewalls, content filters, and proxies/bastion hosts. Adversaries may also target information about victim network-based intrusion detection systems (NIDS) or other appliances related to defensive cybersecurity operations.",
            insertText: 'T1590.006',
            range: range,
        }
        ,
        {
            label: 'Data Compressed',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network. The compression is done separately from the exfiltration channel and is performed using a custom program or algorithm, or a more common compression library or utility such as 7zip, RAR, ZIP, or zlib.",
            insertText: 'T1002',
            range: range,
        }
        ,
        {
            label: 'Data Encrypted',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Data is encrypted before being exfiltrated in order to hide the information that is being exfiltrated from detection or to make the exfiltration less conspicuous upon inspection by a defender. The encryption is performed by a utility, programming library, or custom algorithm on the data itself and is considered separate from any encryption performed by the command and control or file transfer protocol. Common file archive formats that can encrypt files are RAR and zip.",
            insertText: 'T1022',
            range: range,
        }
        ,
        {
            label: 'Scheduled Transfer',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may schedule data exfiltration to be performed only at certain times of day or at certain intervals. This could be done to blend traffic patterns with normal activity or availability.",
            insertText: 'T1029',
            range: range,
        }
        ,
        {
            label: 'Data Transfer Size Limits',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may exfiltrate data in fixed size chunks instead of whole files or limit packet sizes below certain thresholds. This approach may be used to avoid triggering network data transfer threshold alerts.",
            insertText: 'T1030',
            range: range,
        }
        ,
        {
            label: 'Exfiltration Over C2 Channel',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may steal data by exfiltrating it over an existing command and control channel. Stolen data is encoded into the normal communications channel using the same protocol as command and control communications.",
            insertText: 'T1041',
            range: range,
        }
        ,
        {
            label: 'Transfer Data to Cloud Account',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may exfiltrate data by transferring the data, including through sharing/syncing and creating backups of cloud environments, to another cloud account they control on the same service.",
            insertText: 'T1537',
            range: range,
        }
        ,
        {
            label: 'Exfiltration Over Other Network Medium',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to exfiltrate data over a different network medium than the command and control channel. If the command and control network is a wired Internet connection, the exfiltration may occur, for example, over a WiFi connection, modem, cellular data connection, Bluetooth, or another radio frequency (RF) channel.",
            insertText: 'T1011',
            range: range,
        }
        ,
        {
            label: 'Exfiltration Over Bluetooth',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to exfiltrate data over Bluetooth rather than the command and control channel. If the command and control network is a wired Internet connection, an adversary may opt to exfiltrate data using a Bluetooth communication channel.",
            insertText: 'T1011.001',
            range: range,
        }
        ,
        {
            label: 'Automated Exfiltration',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may exfiltrate data, such as sensitive documents, through the use of automated processing after being gathered during Collection.(Citation: ESET Gamaredon June 2020)",
            insertText: 'T1020',
            range: range,
        }
        ,
        {
            label: 'Traffic Duplication',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may leverage traffic mirroring in order to automate data exfiltration over compromised infrastructure. Traffic mirroring is a native feature for some devices, often used for network analysis. For example, devices may be configured to forward network traffic to one or more destinations for analysis by a network analyzer or other monitoring device. (Citation: Cisco Traffic Mirroring)(Citation: Juniper Traffic Mirroring)",
            insertText: 'T1020.001',
            range: range,
        }
        ,
        {
            label: 'Exfiltration Over Physical Medium',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to exfiltrate data via a physical medium, such as a removable drive. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a physical medium or device introduced by a user. Such media could be an external hard drive, USB drive, cellular phone, MP3 player, or other removable storage and processing device. The physical medium or device could be used as the final exfiltration point or to hop between otherwise disconnected systems.",
            insertText: 'T1052',
            range: range,
        }
        ,
        {
            label: 'Exfiltration over USB',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to exfiltrate data over a USB connected physical device. In certain circumstances, such as an air-gapped network compromise, exfiltration could occur via a USB device introduced by a user. The USB device could be used as the final exfiltration point or to hop between otherwise disconnected systems.",
            insertText: 'T1052.001',
            range: range,
        }
        ,
        {
            label: 'Exfiltration Over Alternative Protocol',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.",
            insertText: 'T1048',
            range: range,
        }
        ,
        {
            label: 'Exfiltration Over Symmetric Encrypted Non-C2 Protocol',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may steal data by exfiltrating it over a symmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.",
            insertText: 'T1048.001',
            range: range,
        }
        ,
        {
            label: 'Exfiltration Over Asymmetric Encrypted Non-C2 Protocol',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may steal data by exfiltrating it over an asymmetrically encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.",
            insertText: 'T1048.002',
            range: range,
        }
        ,
        {
            label: 'Exfiltration Over Unencrypted Non-C2 Protocol',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.(Citation: copy_cmd_cisco)",
            insertText: 'T1048.003',
            range: range,
        }
        ,
        {
            label: 'Exfiltration Over Web Service',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use an existing, legitimate external Web service to exfiltrate data rather than their primary command and control channel. Popular Web services acting as an exfiltration mechanism may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to compromise. Firewall rules may also already exist to permit traffic to these services.",
            insertText: 'T1567',
            range: range,
        }
        ,
        {
            label: 'Exfiltration to Code Repository',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may exfiltrate data to a code repository rather than over their primary command and control channel. Code repositories are often accessible via an API (ex: https://api.github.com). Access to these APIs are often over HTTPS, which gives the adversary an additional level of protection.",
            insertText: 'T1567.001',
            range: range,
        }
        ,
        {
            label: 'Exfiltration to Cloud Storage',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may exfiltrate data to a cloud storage service rather than over their primary command and control channel. Cloud storage services allow for the storage, edit, and retrieval of data from a remote cloud storage server over the Internet.",
            insertText: 'T1567.002',
            range: range,
        }
        ,
        {
            label: 'Exfiltration to Text Storage Sites',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may exfiltrate data to text storage sites instead of their primary command and control channel. Text storage sites, such as <code>pastebin[.]com</code>, are commonly used by developers to share code and other information.",
            insertText: 'T1567.003',
            range: range,
        }
        ,
        {
            label: 'Exfiltration Over Webhook',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may exfiltrate data to a webhook endpoint rather than over their primary command and control channel. Webhooks are simple mechanisms for allowing a server to push data over HTTP/S to a client without the need for the client to continuously poll the server.(Citation: RedHat Webhooks) Many public and commercial services, such as Discord, Slack, and `webhook.site`, support the creation of webhook endpoints that can be used by other services, such as Github, Jira, or Trello.(Citation: Discord Intro to Webhooks) When changes happen in the linked services (such as pushing a repository update or modifying a ticket), these services will automatically post the data to the webhook endpoint for use by the consuming application.",
            insertText: 'T1567.004',
            range: range,
        }
        ,
        {
            label: 'Replication Through Removable Media',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may move onto systems, possibly those on disconnected or air-gapped networks, by copying malware to removable media and taking advantage of Autorun features when the media is inserted into a system and executes. In the case of Lateral Movement, this may occur through modification of executable files stored on removable media or by copying malware and renaming it to look like a legitimate file to trick users into executing it on a separate system. In the case of Initial Access, this may occur through manual manipulation of the media, modification of systems used to initially format the media, or modification to the media's firmware itself.",
            insertText: 'T1091',
            range: range,
        }
        ,
        {
            label: 'External Remote Services',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as [Windows Remote Management](https://attack.mitre.org/techniques/T1021/006) and [VNC](https://attack.mitre.org/techniques/T1021/005) can also be used externally.(Citation: MacOS VNC software for Remote Desktop)",
            insertText: 'T1133',
            range: range,
        }
        ,
        {
            label: 'Drive-by Compromise',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gain access to a system through a user visiting a website over the normal course of browsing. With this technique, the user's web browser is typically targeted for exploitation, but adversaries may also use compromised websites for non-exploitation behavior such as acquiring [Application Access Token](https://attack.mitre.org/techniques/T1550/001).",
            insertText: 'T1189',
            range: range,
        }
        ,
        {
            label: 'Exploit Public-Facing Application',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network. The weakness in the system can be a software bug, a temporary glitch, or a misconfiguration.",
            insertText: 'T1190',
            range: range,
        }
        ,
        {
            label: 'Spearphishing Link',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of links to download malware contained in email, instead of attaching malicious files to the email itself, to avoid defenses that may inspect email attachments.",
            insertText: 'T1192',
            range: range,
        }
        ,
        {
            label: 'Spearphishing Attachment',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon [User Execution](https://attack.mitre.org/techniques/T1204) to gain execution.",
            insertText: 'T1193',
            range: range,
        }
        ,
        {
            label: 'Spearphishing via Service',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Spearphishing via service is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of third party services rather than directly via enterprise email channels.",
            insertText: 'T1194',
            range: range,
        }
        ,
        {
            label: 'Trusted Relationship',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may breach or otherwise leverage organizations who have access to intended victims. Access through trusted third party relationship abuses an existing connection that may not be protected or receives less scrutiny than standard mechanisms of gaining access to a network.",
            insertText: 'T1199',
            range: range,
        }
        ,
        {
            label: 'Hardware Additions',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may introduce computer accessories, networking hardware, or other computing devices into a system or network that can be used as a vector to gain access. Rather than just connecting and distributing payloads via removable storage (i.e. [Replication Through Removable Media](https://attack.mitre.org/techniques/T1091)), more robust hardware additions can be used to introduce new functionalities and/or features into a system that can then be abused.",
            insertText: 'T1200',
            range: range,
        }
        ,
        {
            label: 'Content Injection',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gain access and continuously communicate with victims by injecting malicious content into systems through online network traffic. Rather than luring victims to malicious payloads hosted on a compromised website (i.e., [Drive-by Target](https://attack.mitre.org/techniques/T1608/004) followed by [Drive-by Compromise](https://attack.mitre.org/techniques/T1189)), adversaries may initially access victims through compromised data-transfer channels where they can manipulate traffic and/or inject their own content. These compromised online network channels may also be used to deliver additional payloads (i.e., [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)) and other data to already compromised systems.(Citation: ESET MoustachedBouncer)",
            insertText: 'T1659',
            range: range,
        }
        ,
        {
            label: 'Supply Chain Compromise',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may manipulate products or product delivery mechanisms prior to receipt by a final consumer for the purpose of data or system compromise.",
            insertText: 'T1195',
            range: range,
        }
        ,
        {
            label: 'Compromise Software Dependencies and Development Tools',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may manipulate software dependencies and development tools prior to receipt by a final consumer for the purpose of data or system compromise. Applications often depend on external software to function properly. Popular open source projects that are used as dependencies in many applications may be targeted as a means to add malicious code to users of the dependency.(Citation: Trendmicro NPM Compromise)",
            insertText: 'T1195.001',
            range: range,
        }
        ,
        {
            label: 'Compromise Software Supply Chain',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise. Supply chain compromise of software can take place in a number of ways, including manipulation of the application source code, manipulation of the update/distribution mechanism for that software, or replacing compiled releases with a modified version.",
            insertText: 'T1195.002',
            range: range,
        }
        ,
        {
            label: 'Compromise Hardware Supply Chain',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may manipulate hardware components in products prior to receipt by a final consumer for the purpose of data or system compromise. By modifying hardware or firmware in the supply chain, adversaries can insert a backdoor into consumer networks that may be difficult to detect and give the adversary a high degree of control over the system. Hardware backdoors may be inserted into various devices, such as servers, workstations, network infrastructure, or peripherals.",
            insertText: 'T1195.003',
            range: range,
        }
        ,
        {
            label: 'Valid Accounts',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access, network devices, and remote desktop.(Citation: volexity_0day_sophos_FW) Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.",
            insertText: 'T1078',
            range: range,
        }
        ,
        {
            label: 'Default Accounts',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may obtain and abuse credentials of a default account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Default accounts are those that are built-into an OS, such as the Guest or Administrator accounts on Windows systems. Default accounts also include default factory/provider set accounts on other types of systems, software, or devices, including the root user account in AWS and the default service account in Kubernetes.(Citation: Microsoft Local Accounts Feb 2019)(Citation: AWS Root User)(Citation: Threat Matrix for Kubernetes)",
            insertText: 'T1078.001',
            range: range,
        }
        ,
        {
            label: 'Domain Accounts',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may obtain and abuse credentials of a domain account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.(Citation: TechNet Credential Theft) Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover users, administrators, and services.(Citation: Microsoft AD Accounts)",
            insertText: 'T1078.002',
            range: range,
        }
        ,
        {
            label: 'Local Accounts',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may obtain and abuse credentials of a local account as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.",
            insertText: 'T1078.003',
            range: range,
        }
        ,
        {
            label: 'Cloud Accounts',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Valid accounts in cloud environments may allow adversaries to perform actions to achieve Initial Access, Persistence, Privilege Escalation, or Defense Evasion. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application. Cloud Accounts can exist solely in the cloud; alternatively, they may be hybrid-joined between on-premises systems and the cloud through syncing or federation with other identity sources such as Windows Active Directory. (Citation: AWS Identity Federation)(Citation: Google Federating GC)(Citation: Microsoft Deploying AD Federation)",
            insertText: 'T1078.004',
            range: range,
        }
        ,
        {
            label: 'Phishing',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may send phishing messages to gain access to victim systems. All forms of phishing are electronically delivered social engineering. Phishing can be targeted, known as spearphishing. In spearphishing, a specific individual, company, or industry will be targeted by the adversary. More generally, adversaries can conduct non-targeted phishing, such as in mass malware spam campaigns.",
            insertText: 'T1566',
            range: range,
        }
        ,
        {
            label: 'Spearphishing Attachment',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems. Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon [User Execution](https://attack.mitre.org/techniques/T1204) to gain execution.(Citation: Unit 42 DarkHydrus July 2018) Spearphishing may also involve social engineering techniques, such as posing as a trusted source.",
            insertText: 'T1566.001',
            range: range,
        }
        ,
        {
            label: 'Spearphishing Link',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems. Spearphishing with a link is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of links to download malware contained in email, instead of attaching malicious files to the email itself, to avoid defenses that may inspect email attachments. Spearphishing may also involve social engineering techniques, such as posing as a trusted source.",
            insertText: 'T1566.002',
            range: range,
        }
        ,
        {
            label: 'Spearphishing via Service',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may send spearphishing messages via third-party services in an attempt to gain access to victim systems. Spearphishing via service is a specific variant of spearphishing. It is different from other forms of spearphishing in that it employs the use of third party services rather than directly via enterprise email channels.",
            insertText: 'T1566.003',
            range: range,
        }
        ,
        {
            label: 'Spearphishing Voice',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use voice communications to ultimately gain access to victim systems. Spearphishing voice is a specific variant of spearphishing. It is different from other forms of spearphishing in that is employs the use of manipulating a user into providing access to systems through a phone call or other forms of voice communications. Spearphishing frequently involves social engineering techniques, such as posing as a trusted source (ex: [Impersonation](https://attack.mitre.org/techniques/T1656)) and/or creating a sense of urgency or alarm for the recipient.",
            insertText: 'T1566.004',
            range: range,
        }
        ,
        {
            label: 'Data from Local System',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search local system sources, such as file systems and configuration files or local databases, to find files of interest and sensitive data prior to Exfiltration.",
            insertText: 'T1005',
            range: range,
        }
        ,
        {
            label: 'Data from Removable Media',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search connected removable media on computers they have compromised to find files of interest. Sensitive data can be collected from any removable media (optical disk drive, USB memory, etc.) connected to the compromised system prior to Exfiltration. Interactive command shells may be in use, and common functionality within [cmd](https://attack.mitre.org/software/S0106) may be used to gather information.",
            insertText: 'T1025',
            range: range,
        }
        ,
        {
            label: 'Data from Network Shared Drive',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search network shares on computers they have compromised to find files of interest. Sensitive data can be collected from remote systems via shared network drives (host shared directory, network file server, etc.) that are accessible from the current system prior to Exfiltration. Interactive command shells may be in use, and common functionality within [cmd](https://attack.mitre.org/software/S0106) may be used to gather information.",
            insertText: 'T1039',
            range: range,
        }
        ,
        {
            label: 'Screen Capture',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation. Screen capturing functionality may be included as a feature of a remote access tool used in post-compromise operations. Taking a screenshot is also typically possible through native utilities or API calls, such as <code>CopyFromScreen</code>, <code>xwd</code>, or <code>screencapture</code>.(Citation: CopyFromScreen .NET)(Citation: Antiquated Mac Malware)",
            insertText: 'T1113',
            range: range,
        }
        ,
        {
            label: 'Clipboard Data',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may collect data stored in the clipboard from users copying information within or between applications.",
            insertText: 'T1115',
            range: range,
        }
        ,
        {
            label: 'Automated Collection',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Once established within a system or network, an adversary may use automated techniques for collecting internal data. Methods for performing this technique could include use of a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) to search for and copy information fitting set criteria such as file type, location, or name at specific time intervals.",
            insertText: 'T1119',
            range: range,
        }
        ,
        {
            label: 'Audio Capture',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary can leverage a computer's peripheral devices (e.g., microphones and webcams) or applications (e.g., voice and video call services) to capture audio recordings for the purpose of listening into sensitive conversations to gather information.(Citation: ESET Attor Oct 2019)",
            insertText: 'T1123',
            range: range,
        }
        ,
        {
            label: 'Video Capture',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary can leverage a computer's peripheral devices (e.g., integrated cameras or webcams) or applications (e.g., video call services) to capture video recordings for the purpose of gathering information. Images may also be captured from devices or applications, potentially in specified intervals, in lieu of video files.",
            insertText: 'T1125',
            range: range,
        }
        ,
        {
            label: 'Browser Session Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may take advantage of security vulnerabilities and inherent functionality in browser software to change content, modify user-behaviors, and intercept information as part of various browser session hijacking techniques.(Citation: Wikipedia Man in the Browser)",
            insertText: 'T1185',
            range: range,
        }
        ,
        {
            label: 'Data from Cloud Storage',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may access data from cloud storage.",
            insertText: 'T1530',
            range: range,
        }
        ,
        {
            label: 'Data Staged',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may stage collected data in a central location or directory prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitre.org/techniques/T1560). Interactive command shells may be used, and common functionality within [cmd](https://attack.mitre.org/software/S0106) and bash may be used to copy data into a staging location.(Citation: PWC Cloud Hopper April 2017)",
            insertText: 'T1074',
            range: range,
        }
        ,
        {
            label: 'Local Data Staging',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may stage collected data in a central location or directory on the local system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitre.org/techniques/T1560). Interactive command shells may be used, and common functionality within [cmd](https://attack.mitre.org/software/S0106) and bash may be used to copy data into a staging location.",
            insertText: 'T1074.001',
            range: range,
        }
        ,
        {
            label: 'Remote Data Staging',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may stage data collected from multiple systems in a central location or directory on one system prior to Exfiltration. Data may be kept in separate files or combined into one file through techniques such as [Archive Collected Data](https://attack.mitre.org/techniques/T1560). Interactive command shells may be used, and common functionality within [cmd](https://attack.mitre.org/software/S0106) and bash may be used to copy data into a staging location.",
            insertText: 'T1074.002',
            range: range,
        }
        ,
        {
            label: 'Data from Configuration Repository',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may collect data related to managed devices from configuration repositories. Configuration repositories are used by management systems in order to configure, manage, and control data on remote systems. Configuration repositories may also facilitate remote access and administration of devices.",
            insertText: 'T1602',
            range: range,
        }
        ,
        {
            label: 'SNMP (MIB Dump)',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may target the Management Information Base (MIB) to collect and/or mine valuable information in a network managed using Simple Network Management Protocol (SNMP).",
            insertText: 'T1602.001',
            range: range,
        }
        ,
        {
            label: 'Network Device Configuration Dump',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may access network configuration files to collect sensitive data about the device and the network. The network configuration is a file containing parameters that determine the operation of the device. The device typically stores an in-memory copy of the configuration while operating, and a separate configuration on non-volatile storage to load after device reset. Adversaries can inspect the configuration files to reveal information about the target network and its layout, the network device and its software, or identifying legitimate accounts and credentials for later use.",
            insertText: 'T1602.002',
            range: range,
        }
        ,
        {
            label: 'Email Collection',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may target user email to collect sensitive information. Emails may contain sensitive data, including trade secrets or personal information, that can prove valuable to adversaries. Adversaries can collect or forward email from mail servers or clients.",
            insertText: 'T1114',
            range: range,
        }
        ,
        {
            label: 'Local Email Collection',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may target user email on local systems to collect sensitive information. Files containing email data can be acquired from a user\u2019s local system, such as Outlook storage or cache files.",
            insertText: 'T1114.001',
            range: range,
        }
        ,
        {
            label: 'Remote Email Collection',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may target an Exchange server, Office 365, or Google Workspace to collect sensitive information. Adversaries may leverage a user's credentials and interact directly with the Exchange server to acquire information from within a network. Adversaries may also access externally facing Exchange services, Office 365, or Google Workspace to access email using credentials or access tokens. Tools such as [MailSniper](https://attack.mitre.org/software/S0413) can be used to automate searches for specific keywords.",
            insertText: 'T1114.002',
            range: range,
        }
        ,
        {
            label: 'Email Forwarding Rule',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may setup email forwarding rules to collect sensitive information. Adversaries may abuse email forwarding rules to monitor the activities of a victim, steal information, and further gain intelligence on the victim or the victim\u2019s organization to use as part of further exploits or operations.(Citation: US-CERT TA18-068A 2018) Furthermore, email forwarding rules can allow adversaries to maintain persistent access to victim's emails even after compromised credentials are reset by administrators.(Citation: Pfammatter - Hidden Inbox Rules) Most email clients allow users to create inbox rules for various email functions, including forwarding to a different recipient. These rules may be created through a local email application, a web interface, or by command-line interface. Messages can be forwarded to internal or external recipients, and there are no restrictions limiting the extent of this rule. Administrators may also create forwarding rules for user accounts with the same considerations and outcomes.(Citation: Microsoft Tim McMichael Exchange Mail Forwarding 2)(Citation: Mac Forwarding Rules)",
            insertText: 'T1114.003',
            range: range,
        }
        ,
        {
            label: 'Archive Collected Data',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may compress and/or encrypt data that is collected prior to exfiltration. Compressing the data can help to obfuscate the collected data and minimize the amount of data sent over the network.(Citation: DOJ GRU Indictment Jul 2018) Encryption can be used to hide information that is being exfiltrated from detection or make exfiltration less conspicuous upon inspection by a defender.",
            insertText: 'T1560',
            range: range,
        }
        ,
        {
            label: 'Archive via Utility',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use utilities to compress and/or encrypt collected data prior to exfiltration. Many utilities include functionalities to compress, encrypt, or otherwise package data into a format that is easier/more secure to transport.",
            insertText: 'T1560.001',
            range: range,
        }
        ,
        {
            label: 'Archive via Library',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party libraries. Many libraries exist that can archive data, including [Python](https://attack.mitre.org/techniques/T1059/006) rarfile (Citation: PyPI RAR), libzip (Citation: libzip), and zlib (Citation: Zlib Github). Most libraries include functionality to encrypt and/or compress data.",
            insertText: 'T1560.002',
            range: range,
        }
        ,
        {
            label: 'Archive via Custom Method',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may compress or encrypt data that is collected prior to exfiltration using a custom method. Adversaries may choose to use custom archival methods, such as encryption with XOR or stream ciphers implemented with no external library or utility references. Custom implementations of well-known compression algorithms have also been used.(Citation: ESET Sednit Part 2)",
            insertText: 'T1560.003',
            range: range,
        }
        ,
        {
            label: 'Input Capture',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use methods of capturing user input to obtain credentials or collect information. During normal system usage, users often provide credentials to various different locations, such as login pages/portals or system dialog boxes. Input capture mechanisms may be transparent to the user (e.g. [Credential API Hooking](https://attack.mitre.org/techniques/T1056/004)) or rely on deceiving the user into providing input into what they believe to be a genuine service (e.g. [Web Portal Capture](https://attack.mitre.org/techniques/T1056/003)).",
            insertText: 'T1056',
            range: range,
        }
        ,
        {
            label: 'Keylogging',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may log user keystrokes to intercept credentials as the user types them. Keylogging is likely to be used to acquire credentials for new access opportunities when [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) efforts are not effective, and may require an adversary to intercept keystrokes on a system for a substantial period of time before credentials can be successfully captured. In order to increase the likelihood of capturing credentials quickly, an adversary may also perform actions such as clearing browser cookies to force users to reauthenticate to systems.(Citation: Talos Kimsuky Nov 2021)",
            insertText: 'T1056.001',
            range: range,
        }
        ,
        {
            label: 'GUI Input Capture',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may mimic common operating system GUI components to prompt users for credentials with a seemingly legitimate prompt. When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task (ex: [Bypass User Account Control](https://attack.mitre.org/techniques/T1548/002)).",
            insertText: 'T1056.002',
            range: range,
        }
        ,
        {
            label: 'Web Portal Capture',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may install code on externally facing portals, such as a VPN login page, to capture and transmit credentials of users who attempt to log into the service. For example, a compromised login page may log provided user credentials before logging the user in to the service.",
            insertText: 'T1056.003',
            range: range,
        }
        ,
        {
            label: 'Credential API Hooking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may hook into Windows application programming interface (API) functions to collect user credentials. Malicious hooking mechanisms may capture API calls that include parameters that reveal user authentication credentials.(Citation: Microsoft TrojanSpy:Win32/Ursnif.gen!I Sept 2017) Unlike [Keylogging](https://attack.mitre.org/techniques/T1056/001),  this technique focuses specifically on API functions that include parameters that reveal user credentials. Hooking involves redirecting calls to these functions and can be implemented via:",
            insertText: 'T1056.004',
            range: range,
        }
        ,
        {
            label: 'Adversary-in-the-Middle',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to position themselves between two or more networked devices using an adversary-in-the-middle (AiTM) technique to support follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040), [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002), or replay attacks ([Exploitation for Credential Access](https://attack.mitre.org/techniques/T1212)). By abusing features of common networking protocols that can determine the flow of network traffic (e.g. ARP, DNS, LLMNR, etc.), adversaries may force a device to communicate through an adversary controlled system so they can collect information or perform additional actions.(Citation: Rapid7 MiTM Basics)",
            insertText: 'T1557',
            range: range,
        }
        ,
        {
            label: 'LLMNR/NBT-NS Poisoning and SMB Relay',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "By responding to LLMNR/NBT-NS network traffic, adversaries may spoof an authoritative source for name resolution to force communication with an adversary controlled system. This activity may be used to collect or relay authentication materials.",
            insertText: 'T1557.001',
            range: range,
        }
        ,
        {
            label: 'ARP Cache Poisoning',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may poison Address Resolution Protocol (ARP) caches to position themselves between the communication of two or more networked devices. This activity may be used to enable follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040) or [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002).",
            insertText: 'T1557.002',
            range: range,
        }
        ,
        {
            label: 'DHCP Spoofing',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may redirect network traffic to adversary-owned systems by spoofing Dynamic Host Configuration Protocol (DHCP) traffic and acting as a malicious DHCP server on the victim network. By achieving the adversary-in-the-middle (AiTM) position, adversaries may collect network communications, including passed credentials, especially those sent over insecure, unencrypted protocols. This may also enable follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040) or [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002).",
            insertText: 'T1557.003',
            range: range,
        }
        ,
        {
            label: 'Evil Twin',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may host seemingly genuine Wi-Fi access points to deceive users into connecting to malicious networks as a way of supporting follow-on behaviors such as [Network Sniffing](https://attack.mitre.org/techniques/T1040), [Transmitted Data Manipulation](https://attack.mitre.org/techniques/T1565/002), or [Input Capture](https://attack.mitre.org/techniques/T1056).(Citation: Australia \u2018Evil Twin\u2019)",
            insertText: 'T1557.004',
            range: range,
        }
        ,
        {
            label: 'Data from Information Repositories',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may leverage information repositories to mine valuable information. Information repositories are tools that allow for storage of information, typically to facilitate collaboration or information sharing between users, and can store a wide variety of data that may aid adversaries in further objectives, or direct access to the target information. Adversaries may also abuse external sharing features to share sensitive documents with recipients outside of the organization.",
            insertText: 'T1213',
            range: range,
        }
        ,
        {
            label: 'Confluence',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "",
            insertText: 'T1213.001',
            range: range,
        }
        ,
        {
            label: 'Sharepoint',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may leverage the SharePoint repository as a source to mine valuable information. SharePoint will often contain useful information for an adversary to learn about the structure and functionality of the internal network and systems. For example, the following is a list of example information that may hold potential value to an adversary and may also be found on SharePoint:",
            insertText: 'T1213.002',
            range: range,
        }
        ,
        {
            label: 'Code Repositories',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may leverage code repositories to collect valuable information. Code repositories are tools/services that store source code and automate software builds. They may be hosted internally or privately on third party sites such as Github, GitLab, SourceForge, and BitBucket. Users typically interact with code repositories through a web application or command-line utilities such as git.",
            insertText: 'T1213.003',
            range: range,
        }
        ,
        {
            label: 'Customer Relationship Management Software',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may leverage Customer Relationship Management (CRM) software to mine valuable information. CRM software is used to assist organizations in tracking and managing customer interactions, as well as storing customer data.",
            insertText: 'T1213.004',
            range: range,
        }
        ,
        {
            label: 'Messaging Applications',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may leverage chat and messaging applications, such as Microsoft Teams, Google Chat, and Slack, to mine valuable information.",
            insertText: 'T1213.005',
            range: range,
        }
        ,
        {
            label: 'Data Encrypted for Impact',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources. They can attempt to render stored data inaccessible by encrypting files or data on local and remote drives and withholding access to a decryption key. This may be done in order to extract monetary compensation from a victim in exchange for decryption or a decryption key (ransomware) or to render data permanently inaccessible in cases where the key is not saved or transmitted.(Citation: US-CERT Ransomware 2016)(Citation: FireEye WannaCry 2017)(Citation: US-CERT NotPetya 2017)(Citation: US-CERT SamSam 2018)",
            insertText: 'T1486',
            range: range,
        }
        ,
        {
            label: 'Disk Structure Wipe',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may corrupt or wipe the disk data structures on hard drive necessary to boot systems; targeting specific critical systems as well as a large number of systems in a network to interrupt availability to system and network resources.",
            insertText: 'T1487',
            range: range,
        }
        ,
        {
            label: 'Disk Content Wipe',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may erase the contents of storage devices on specific systems as well as large numbers of systems in a network to interrupt availability to system and network resources.",
            insertText: 'T1488',
            range: range,
        }
        ,
        {
            label: 'Service Stop',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services or processes can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment.(Citation: Talos Olympic Destroyer 2018)(Citation: Novetta Blockbuster)",
            insertText: 'T1489',
            range: range,
        }
        ,
        {
            label: 'Inhibit System Recovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted system to prevent recovery.(Citation: Talos Olympic Destroyer 2018)(Citation: FireEye WannaCry 2017) This may deny access to available backups and recovery options.",
            insertText: 'T1490',
            range: range,
        }
        ,
        {
            label: 'Stored Data Manipulation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may insert, delete, or manipulate data at rest in order to manipulate external outcomes or hide activity.(Citation: FireEye APT38 Oct 2018)(Citation: DOJ Lazarus Sony 2018) By manipulating stored data, adversaries may attempt to affect a business process, organizational understanding, and decision making.",
            insertText: 'T1492',
            range: range,
        }
        ,
        {
            label: 'Transmitted Data Manipulation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity.(Citation: FireEye APT38 Oct 2018)(Citation: DOJ Lazarus Sony 2018) By manipulating transmitted data, adversaries may attempt to affect a business process, organizational understanding, and decision making.",
            insertText: 'T1493',
            range: range,
        }
        ,
        {
            label: 'Runtime Data Manipulation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify systems in order to manipulate the data as it is accessed and displayed to an end user.(Citation: FireEye APT38 Oct 2018)(Citation: DOJ Lazarus Sony 2018) By manipulating runtime data, adversaries may attempt to affect a business process, organizational understanding, and decision making.",
            insertText: 'T1494',
            range: range,
        }
        ,
        {
            label: 'Firmware Corruption',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may overwrite or corrupt the flash memory contents of system BIOS or other firmware in devices attached to a system in order to render them inoperable or unable to boot, thus denying the availability to use the devices and/or the system.(Citation: Symantec Chernobyl W95.CIH) Firmware is software that is loaded and executed from non-volatile memory on hardware devices in order to initialize and manage device functionality. These devices may include the motherboard, hard drive, or video cards.",
            insertText: 'T1495',
            range: range,
        }
        ,
        {
            label: 'System Shutdown/Reboot',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may shutdown/reboot systems to interrupt access to, or aid in the destruction of, those systems. Operating systems may contain commands to initiate a shutdown/reboot of a machine or network device. In some cases, these commands may also be used to initiate a shutdown/reboot of a remote computer or network device via [Network Device CLI](https://attack.mitre.org/techniques/T1059/008) (e.g. <code>reload</code>).(Citation: Microsoft Shutdown Oct 2017)(Citation: alert_TA18_106A)",
            insertText: 'T1529',
            range: range,
        }
        ,
        {
            label: 'Account Access Removal',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may interrupt availability of system and network resources by inhibiting access to accounts utilized by legitimate users. Accounts may be deleted, locked, or manipulated (ex: changed credentials) to remove access to accounts. Adversaries may also subsequently log off and/or perform a [System Shutdown/Reboot](https://attack.mitre.org/techniques/T1529) to set malicious changes into place.(Citation: CarbonBlack LockerGoga 2019)(Citation: Unit42 LockerGoga 2019)",
            insertText: 'T1531',
            range: range,
        }
        ,
        {
            label: 'Financial Theft',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may steal monetary resources from targets through extortion, social engineering, technical theft, or other methods aimed at their own financial gain at the expense of the availability of these resources for victims. Financial theft is the ultimate objective of several popular campaign types including extortion by ransomware,(Citation: FBI-ransomware) business email compromise (BEC) and fraud,(Citation: FBI-BEC) \"pig butchering,\"(Citation: wired-pig butchering) bank hacking,(Citation: DOJ-DPRK Heist) and exploiting cryptocurrency networks.(Citation: BBC-Ronin)",
            insertText: 'T1657',
            range: range,
        }
        ,
        {
            label: 'Data Destruction',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources. Data destruction is likely to render stored data irrecoverable by forensic techniques through overwriting files or data on local and remote drives.(Citation: Symantec Shamoon 2012)(Citation: FireEye Shamoon Nov 2016)(Citation: Palo Alto Shamoon Nov 2016)(Citation: Kaspersky StoneDrill 2017)(Citation: Unit 42 Shamoon3 2018)(Citation: Talos Olympic Destroyer 2018) Common operating system file deletion commands such as <code>del</code> and <code>rm</code> often only remove pointers to files without wiping the contents of the files themselves, making the files recoverable by proper forensic methodology. This behavior is distinct from [Disk Content Wipe](https://attack.mitre.org/techniques/T1561/001) and [Disk Structure Wipe](https://attack.mitre.org/techniques/T1561/002) because individual files are destroyed rather than sections of a storage disk or the disk's logical structure.",
            insertText: 'T1485',
            range: range,
        }
        ,
        {
            label: 'Lifecycle-Triggered Deletion',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify the lifecycle policies of a cloud storage bucket to destroy all objects stored within.",
            insertText: 'T1485.001',
            range: range,
        }
        ,
        {
            label: 'Defacement',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify visual content available internally or externally to an enterprise network, thus affecting the integrity of the original content. Reasons for [Defacement](https://attack.mitre.org/techniques/T1491) include delivering messaging, intimidation, or claiming (possibly false) credit for an intrusion. Disturbing or offensive images may be used as a part of [Defacement](https://attack.mitre.org/techniques/T1491) in order to cause user discomfort, or to pressure compliance with accompanying messages.",
            insertText: 'T1491',
            range: range,
        }
        ,
        {
            label: 'Internal Defacement',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may deface systems internal to an organization in an attempt to intimidate or mislead users, thus discrediting the integrity of the systems. This may take the form of modifications to internal websites, or directly to user systems with the replacement of the desktop wallpaper.(Citation: Novetta Blockbuster) Disturbing or offensive images may be used as a part of [Internal Defacement](https://attack.mitre.org/techniques/T1491/001) in order to cause user discomfort, or to pressure compliance with accompanying messages. Since internally defacing systems exposes an adversary's presence, it often takes place after other intrusion goals have been accomplished.(Citation: Novetta Blockbuster Destructive Malware)",
            insertText: 'T1491.001',
            range: range,
        }
        ,
        {
            label: 'External Defacement',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may deface systems external to an organization in an attempt to deliver messaging, intimidate, or otherwise mislead an organization or users. [External Defacement](https://attack.mitre.org/techniques/T1491/002) may ultimately cause users to distrust the systems and to question/discredit the system\u2019s integrity. Externally-facing websites are a common victim of defacement; often targeted by adversary and hacktivist groups in order to push a political message or spread propaganda.(Citation: FireEye Cyber Threats to Media Industries)(Citation: Kevin Mandia Statement to US Senate Committee on Intelligence)(Citation: Anonymous Hackers Deface Russian Govt Site) [External Defacement](https://attack.mitre.org/techniques/T1491/002) may be used as a catalyst to trigger events, or as a response to actions taken by an organization or government. Similarly, website defacement may also be used as setup, or a precursor, for future attacks such as [Drive-by Compromise](https://attack.mitre.org/techniques/T1189).(Citation: Trend Micro Deep Dive Into Defacement)",
            insertText: 'T1491.002',
            range: range,
        }
        ,
        {
            label: 'Disk Wipe',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may wipe or corrupt raw disk data on specific systems or in large numbers in a network to interrupt availability to system and network resources. With direct write access to a disk, adversaries may attempt to overwrite portions of disk data. Adversaries may opt to wipe arbitrary portions of disk data and/or wipe disk structures like the master boot record (MBR). A complete wipe of all disk sectors may be attempted.",
            insertText: 'T1561',
            range: range,
        }
        ,
        {
            label: 'Disk Content Wipe',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may erase the contents of storage devices on specific systems or in large numbers in a network to interrupt availability to system and network resources.",
            insertText: 'T1561.001',
            range: range,
        }
        ,
        {
            label: 'Disk Structure Wipe',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may corrupt or wipe the disk data structures on a hard drive necessary to boot a system; targeting specific critical systems or in large numbers in a network to interrupt availability to system and network resources.",
            insertText: 'T1561.002',
            range: range,
        }
        ,
        {
            label: 'Network Denial of Service',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users. Network DoS can be performed by exhausting the network bandwidth services rely on. Example resources include specific websites, email services, DNS, and web-based applications. Adversaries have been observed conducting network DoS attacks for political purposes(Citation: FireEye OpPoisonedHandover February 2016) and to support other malicious activities, including distraction(Citation: FSISAC FraudNetDoS September 2012), hacktivism, and extortion.(Citation: Symantec DDoS October 2014)",
            insertText: 'T1498',
            range: range,
        }
        ,
        {
            label: 'Direct Network Flood',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target. This DoS attack may also reduce the availability and functionality of the targeted system(s) and network. [Direct Network Flood](https://attack.mitre.org/techniques/T1498/001)s are when one or more systems are used to send a high-volume of network packets towards the targeted service's network. Almost any network protocol may be used for flooding. Stateless protocols such as UDP or ICMP are commonly used but stateful protocols such as TCP can be used as well.",
            insertText: 'T1498.001',
            range: range,
        }
        ,
        {
            label: 'Reflection Amplification',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to cause a denial of service (DoS) by reflecting a high-volume of network traffic to a target. This type of Network DoS takes advantage of a third-party server intermediary that hosts and will respond to a given spoofed source IP address. This third-party server is commonly termed a reflector. An adversary accomplishes a reflection attack by sending packets to reflectors with the spoofed address of the victim. Similar to Direct Network Floods, more than one system may be used to conduct the attack, or a botnet may be used. Likewise, one or more reflectors may be used to focus traffic on the target.(Citation: Cloudflare ReflectionDoS May 2017) This Network DoS attack may also reduce the availability and functionality of the targeted system(s) and network.",
            insertText: 'T1498.002',
            range: range,
        }
        ,
        {
            label: 'Service Exhaustion Flood',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may target the different network services provided by systems to conduct a denial of service (DoS). Adversaries often target the availability of DNS and web services, however others have been targeted as well.(Citation: Arbor AnnualDoSreport Jan 2018) Web server software can be attacked through a variety of means, some of which apply generally while others are specific to the software being used to provide the service.",
            insertText: 'T1499.002',
            range: range,
        }
        ,
        {
            label: 'Endpoint Denial of Service',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users. Endpoint DoS can be performed by exhausting the system resources those services are hosted on or exploiting the system to cause a persistent crash condition. Example services include websites, email services, DNS, and web-based applications. Adversaries have been observed conducting DoS attacks for political purposes(Citation: FireEye OpPoisonedHandover February 2016) and to support other malicious activities, including distraction(Citation: FSISAC FraudNetDoS September 2012), hacktivism, and extortion.(Citation: Symantec DDoS October 2014)",
            insertText: 'T1499',
            range: range,
        }
        ,
        {
            label: 'OS Exhaustion Flood',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may launch a denial of service (DoS) attack targeting an endpoint's operating system (OS). A system's OS is responsible for managing the finite resources as well as preventing the entire system from being overwhelmed by excessive demands on its capacity. These attacks do not need to exhaust the actual resources on a system; the attacks may simply exhaust the limits and available resources that an OS self-imposes.",
            insertText: 'T1499.001',
            range: range,
        }
        ,
        {
            label: 'Application Exhaustion Flood',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may target resource intensive features of applications to cause a denial of service (DoS), denying availability to those applications. For example, specific features in web applications may be highly resource intensive. Repeated requests to those features may be able to exhaust system resources and deny access to the application or the server itself.(Citation: Arbor AnnualDoSreport Jan 2018)",
            insertText: 'T1499.003',
            range: range,
        }
        ,
        {
            label: 'Application or System Exploitation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may exploit software vulnerabilities that can cause an application or system to crash and deny availability to users. (Citation: Sucuri BIND9 August 2015) Some systems may automatically restart critical applications and services when crashes occur, but they can likely be re-exploited to cause a persistent denial of service (DoS) condition.",
            insertText: 'T1499.004',
            range: range,
        }
        ,
        {
            label: 'Data Manipulation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may insert, delete, or manipulate data in order to influence external outcomes or hide activity, thus threatening the integrity of the data.(Citation: Sygnia Elephant Beetle Jan 2022) By manipulating data, adversaries may attempt to affect a business process, organizational understanding, or decision making.",
            insertText: 'T1565',
            range: range,
        }
        ,
        {
            label: 'Stored Data Manipulation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may insert, delete, or manipulate data at rest in order to influence external outcomes or hide activity, thus threatening the integrity of the data.(Citation: FireEye APT38 Oct 2018)(Citation: DOJ Lazarus Sony 2018) By manipulating stored data, adversaries may attempt to affect a business process, organizational understanding, and decision making.",
            insertText: 'T1565.001',
            range: range,
        }
        ,
        {
            label: 'Transmitted Data Manipulation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may alter data en route to storage or other systems in order to manipulate external outcomes or hide activity, thus threatening the integrity of the data.(Citation: FireEye APT38 Oct 2018)(Citation: DOJ Lazarus Sony 2018) By manipulating transmitted data, adversaries may attempt to affect a business process, organizational understanding, and decision making.",
            insertText: 'T1565.002',
            range: range,
        }
        ,
        {
            label: 'Runtime Data Manipulation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify systems in order to manipulate the data as it is accessed and displayed to an end user, thus threatening the integrity of the data.(Citation: FireEye APT38 Oct 2018)(Citation: DOJ Lazarus Sony 2018) By manipulating runtime data, adversaries may attempt to affect a business process, organizational understanding, and decision making.",
            insertText: 'T1565.003',
            range: range,
        }
        ,
        {
            label: 'Resource Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may leverage the resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability.",
            insertText: 'T1496',
            range: range,
        }
        ,
        {
            label: 'Compute Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may leverage the compute resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability.",
            insertText: 'T1496.001',
            range: range,
        }
        ,
        {
            label: 'Bandwidth Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may leverage the network bandwidth resources of co-opted systems to complete resource-intensive tasks, which may impact system and/or hosted service availability.",
            insertText: 'T1496.002',
            range: range,
        }
        ,
        {
            label: 'SMS Pumping',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may leverage messaging services for SMS pumping, which may impact system and/or hosted service availability.(Citation: Twilio SMS Pumping) SMS pumping is a type of telecommunications fraud whereby a threat actor first obtains a set of phone numbers from a telecommunications provider, then leverages a victim\u2019s messaging infrastructure to send large amounts of SMS messages to numbers in that set. By generating SMS traffic to their phone number set, a threat actor may earn payments from the telecommunications provider.(Citation: Twilio SMS Pumping Fraud)",
            insertText: 'T1496.003',
            range: range,
        }
        ,
        {
            label: 'Cloud Service Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may leverage compromised software-as-a-service (SaaS) applications to complete resource-intensive tasks, which may impact hosted service availability.",
            insertText: 'T1496.004',
            range: range,
        }
        ,
        {
            label: 'Application Deployment Software',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may deploy malicious software to systems within a network using application deployment systems employed by enterprise administrators. The permissions required for this action vary by system configuration; local credentials may be sufficient with direct access to the deployment server, or specific domain credentials may be required. However, the system may require an administrative account to log in or to perform software deployment.",
            insertText: 'T1017',
            range: range,
        }
        ,
        {
            label: 'Windows Remote Management',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Windows Remote Management (WinRM) is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services). (Citation: Microsoft WinRM) It may be called with the <code>winrm</code> command or by any number of programs such as PowerShell. (Citation: Jacobsen 2014)",
            insertText: 'T1028',
            range: range,
        }
        ,
        {
            label: 'Shared Webroot',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "**This technique has been deprecated and should no longer be used.**",
            insertText: 'T1051',
            range: range,
        }
        ,
        {
            label: 'Software Deployment Tools',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gain access to and use centralized software suites installed within an enterprise to execute commands and move laterally through the network. Configuration management and software deployment applications may be used in an enterprise network or cloud environment for routine administration purposes. These systems may also be integrated into CI/CD pipelines. Examples of such solutions include: SCCM, HBSS, Altiris, AWS Systems Manager, Microsoft Intune, Azure Arc, and GCP Deployment Manager.",
            insertText: 'T1072',
            range: range,
        }
        ,
        {
            label: 'Pass the Hash',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. In this technique, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems.",
            insertText: 'T1075',
            range: range,
        }
        ,
        {
            label: 'Remote Desktop Protocol',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS). (Citation: TechNet Remote Desktop Services) There are other implementations and third-party tools that provide graphical access [Remote Services](https://attack.mitre.org/techniques/T1021) similar to RDS.",
            insertText: 'T1076',
            range: range,
        }
        ,
        {
            label: 'Windows Admin Shares',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Windows systems have hidden network shares that are accessible only to administrators and provide the ability for remote file copy and other administrative functions. Example network shares include <code>C$</code>, <code>ADMIN$</code>, and <code>IPC$</code>.",
            insertText: 'T1077',
            range: range,
        }
        ,
        {
            label: 'Taint Shared Content',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "",
            insertText: 'T1080',
            range: range,
        }
        ,
        {
            label: 'Pass the Ticket',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system.",
            insertText: 'T1097',
            range: range,
        }
        ,
        {
            label: 'Component Object Model and Distributed COM',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "**This technique has been deprecated. Please use [Distributed Component Object Model](https://attack.mitre.org/techniques/T1021/003) and [Component Object Model](https://attack.mitre.org/techniques/T1559/001).**",
            insertText: 'T1175',
            range: range,
        }
        ,
        {
            label: 'SSH Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Secure Shell (SSH) is a standard means of remote access on Linux and macOS systems. It allows a user to connect to another system via an encrypted tunnel, commonly authenticating through a password, certificate or the use of an asymmetric encryption key pair.",
            insertText: 'T1184',
            range: range,
        }
        ,
        {
            label: 'Exploitation of Remote Services',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may exploit remote services to gain unauthorized access to internal systems once inside of a network. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.\u00a0A common goal for post-compromise exploitation of remote services is for lateral movement to enable access to a remote system.",
            insertText: 'T1210',
            range: range,
        }
        ,
        {
            label: 'Web Session Cookie',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries can use stolen session cookies to authenticate to web applications and services. This technique bypasses some multi-factor authentication protocols since the session is already authenticated.(Citation: Pass The Cookie)",
            insertText: 'T1506',
            range: range,
        }
        ,
        {
            label: 'Application Access Token',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems. These tokens are typically stolen from users and used in lieu of login credentials.",
            insertText: 'T1527',
            range: range,
        }
        ,
        {
            label: 'Internal Spearphishing',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "After they already have access to accounts or systems within the environment, adversaries may use internal spearphishing to gain access to additional information or compromise other users within the same organization. Internal spearphishing is multi-staged campaign where a legitimate account is initially compromised either by controlling the user's device or by compromising the account credentials of the user. Adversaries may then attempt to take advantage of the trusted internal account to increase the likelihood of tricking more victims into falling for phish attempts, often incorporating [Impersonation](https://attack.mitre.org/techniques/T1656).(Citation: Trend Micro - Int SP)",
            insertText: 'T1534',
            range: range,
        }
        ,
        {
            label: 'Lateral Tool Transfer',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may transfer tools or other files between systems in a compromised environment. Once brought into the victim environment (i.e., [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)) files may then be copied from one system to another to stage adversary tools or other files over the course of an operation.",
            insertText: 'T1570',
            range: range,
        }
        ,
        {
            label: 'Remote Service Session Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may take control of preexisting sessions with remote services to move laterally in an environment. Users may use valid credentials to log into a service specifically designed to accept remote connections, such as telnet, SSH, and RDP. When a user logs into a service, a session will be established that will allow them to maintain a continuous interaction with that service.",
            insertText: 'T1563',
            range: range,
        }
        ,
        {
            label: 'SSH Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may hijack a legitimate user's SSH session to move laterally within an environment. Secure Shell (SSH) is a standard means of remote access on Linux and macOS systems. It allows a user to connect to another system via an encrypted tunnel, commonly authenticating through a password, certificate or the use of an asymmetric encryption key pair.",
            insertText: 'T1563.001',
            range: range,
        }
        ,
        {
            label: 'RDP Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may hijack a legitimate user\u2019s remote desktop session to move laterally within an environment. Remote desktop is a common feature in operating systems. It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system. Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).(Citation: TechNet Remote Desktop Services)",
            insertText: 'T1563.002',
            range: range,
        }
        ,
        {
            label: 'Use Alternate Authentication Material',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use alternate authentication material, such as password hashes, Kerberos tickets, and application access tokens, in order to move laterally within an environment and bypass normal system access controls.",
            insertText: 'T1550',
            range: range,
        }
        ,
        {
            label: 'Application Access Token',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use stolen application access tokens to bypass the typical authentication process and access restricted accounts, information, or services on remote systems. These tokens are typically stolen from users or services and used in lieu of login credentials.",
            insertText: 'T1550.001',
            range: range,
        }
        ,
        {
            label: 'Pass the Hash',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may \u201cpass the hash\u201d using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash.",
            insertText: 'T1550.002',
            range: range,
        }
        ,
        {
            label: 'Pass the Ticket',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may \u201cpass the ticket\u201d using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls. Pass the ticket (PtT) is a method of authenticating to a system using Kerberos tickets without having access to an account's password. Kerberos authentication can be used as the first step to lateral movement to a remote system.",
            insertText: 'T1550.003',
            range: range,
        }
        ,
        {
            label: 'Web Session Cookie',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries can use stolen session cookies to authenticate to web applications and services. This technique bypasses some multi-factor authentication protocols since the session is already authenticated.(Citation: Pass The Cookie)",
            insertText: 'T1550.004',
            range: range,
        }
        ,
        {
            label: 'Remote Services',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a service that accepts remote connections, such as telnet, SSH, and VNC. The adversary may then perform actions as the logged-on user.",
            insertText: 'T1021',
            range: range,
        }
        ,
        {
            label: 'Remote Desktop Protocol',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into a computer using the Remote Desktop Protocol (RDP). The adversary may then perform actions as the logged-on user.",
            insertText: 'T1021.001',
            range: range,
        }
        ,
        {
            label: 'SMB/Windows Admin Shares',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with a remote network share using Server Message Block (SMB). The adversary may then perform actions as the logged-on user.",
            insertText: 'T1021.002',
            range: range,
        }
        ,
        {
            label: 'Distributed Component Object Model',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with remote machines by taking advantage of Distributed Component Object Model (DCOM). The adversary may then perform actions as the logged-on user.",
            insertText: 'T1021.003',
            range: range,
        }
        ,
        {
            label: 'SSH',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into remote machines using Secure Shell (SSH). The adversary may then perform actions as the logged-on user.",
            insertText: 'T1021.004',
            range: range,
        }
        ,
        {
            label: 'VNC',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to remotely control machines using Virtual Network Computing (VNC).  VNC is a platform-independent desktop sharing system that uses the RFB (\u201cremote framebuffer\u201d) protocol to enable users to remotely control another computer\u2019s display by relaying the screen, mouse, and keyboard inputs over the network.(Citation: The Remote Framebuffer Protocol)",
            insertText: 'T1021.005',
            range: range,
        }
        ,
        {
            label: 'Windows Remote Management',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to interact with remote systems using Windows Remote Management (WinRM). The adversary may then perform actions as the logged-on user.",
            insertText: 'T1021.006',
            range: range,
        }
        ,
        {
            label: 'Cloud Services',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may log into accessible cloud services within a compromised environment using [Valid Accounts](https://attack.mitre.org/techniques/T1078) that are synchronized with or federated to on-premises user identities. The adversary may then perform management actions or access cloud-hosted resources as the logged-on user.",
            insertText: 'T1021.007',
            range: range,
        }
        ,
        {
            label: 'Direct Cloud VM Connections',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may leverage [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log directly into accessible cloud hosted compute infrastructure through cloud native methods. Many cloud providers offer interactive connections to virtual infrastructure that can be accessed through the [Cloud API](https://attack.mitre.org/techniques/T1059/009), such as Azure Serial Console(Citation: Azure Serial Console), AWS EC2 Instance Connect(Citation: EC2 Instance Connect)(Citation: lucr-3: Getting SaaS-y in the cloud), and AWS System Manager.(Citation: AWS System Manager).",
            insertText: 'T1021.008',
            range: range,
        }
        ,
        {
            label: 'Fallback Channels',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use fallback or alternate communication channels if the primary channel is compromised or inaccessible in order to maintain reliable command and control and to avoid data transfer thresholds.",
            insertText: 'T1008',
            range: range,
        }
        ,
        {
            label: 'Custom Cryptographic Protocol',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use a custom cryptographic protocol or algorithm to hide command and control traffic. A simple scheme, such as XOR-ing the plaintext with a fixed key, will produce a very weak ciphertext.",
            insertText: 'T1024',
            range: range,
        }
        ,
        {
            label: 'Multiband Communication',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "**This technique has been deprecated and should no longer be used.**",
            insertText: 'T1026',
            range: range,
        }
        ,
        {
            label: 'Standard Cryptographic Protocol',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may explicitly employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if necessary secret keys are encoded and/or generated within malware samples/configuration files.",
            insertText: 'T1032',
            range: range,
        }
        ,
        {
            label: 'Commonly Used Port',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "**This technique has been deprecated. Please use [Non-Standard Port](https://attack.mitre.org/techniques/T1571) where appropriate.**",
            insertText: 'T1043',
            range: range,
        }
        ,
        {
            label: 'Uncommonly Used Port',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may conduct C2 communications over a non-standard port to bypass proxies and firewalls that have been improperly configured.",
            insertText: 'T1065',
            range: range,
        }
        ,
        {
            label: 'Multilayer Encryption',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary performs C2 communications using multiple layers of encryption, typically (but not exclusively) tunneling a custom encryption scheme within a protocol encryption scheme such as HTTPS or SMTPS.",
            insertText: 'T1079',
            range: range,
        }
        ,
        {
            label: 'Communication Through Removable Media',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries can perform command and control between compromised hosts on potentially disconnected networks using removable media to transfer commands from system to system.(Citation: ESET Sednit USBStealer 2014) Both systems would need to be compromised, with the likelihood that an Internet-connected system was compromised first and the second through lateral movement by [Replication Through Removable Media](https://attack.mitre.org/techniques/T1091). Commands and files would be relayed from the disconnected system to the Internet-connected system to which the adversary has direct access.",
            insertText: 'T1092',
            range: range,
        }
        ,
        {
            label: 'Custom Command and Control Protocol',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may communicate using a custom command and control protocol instead of encapsulating commands/data in an existing [Application Layer Protocol](https://attack.mitre.org/techniques/T1071). Implementations include mimicking well-known protocols or developing custom protocols (including raw sockets) on top of fundamental protocols provided by TCP/IP/another standard network stack.",
            insertText: 'T1094',
            range: range,
        }
        ,
        {
            label: 'Non-Application Layer Protocol',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use an OSI non-application layer protocol for communication between host and C2 server or among infected hosts within a network. The list of possible protocols is extensive.(Citation: Wikipedia OSI) Specific examples include use of network layer protocols, such as the Internet Control Message Protocol (ICMP), transport layer protocols, such as the User Datagram Protocol (UDP), session layer protocols, such as Socket Secure (SOCKS), as well as redirected/tunneled protocols, such as Serial over LAN (SOL).",
            insertText: 'T1095',
            range: range,
        }
        ,
        {
            label: 'Multi-Stage Channels',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create multiple stages for command and control that are employed under different conditions or for certain functions. Use of multiple stages may obfuscate the command and control channel to make detection more difficult.",
            insertText: 'T1104',
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
            label: 'Domain Fronting',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Domain fronting takes advantage of routing schemes in Content Delivery Networks (CDNs) and other services which host multiple domains to obfuscate the intended destination of HTTPS traffic or traffic tunneled through HTTPS. (Citation: Fifield Blocking Resistent Communication through domain fronting 2015) The technique involves using different domain names in the SNI field of the TLS header and the Host field of the HTTP header. If both domains are served from the same CDN, then the CDN may route to the address specified in the HTTP header after unwrapping the TLS header. A variation of the the technique, \"domainless\" fronting, utilizes a SNI field that is left blank; this may allow the fronting to work even when the CDN attempts to validate that the SNI and HTTP Host fields match (if the blank SNI fields are ignored).",
            insertText: 'T1172',
            range: range,
        }
        ,
        {
            label: 'Multi-hop Proxy',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "To disguise the source of malicious traffic, adversaries may chain together multiple proxies. Typically, a defender will be able to identify the last proxy traffic traversed before it enters their network; the defender may or may not be able to identify any previous proxies before the last-hop proxy. This technique makes identifying the original source of the malicious traffic even more difficult by requiring the defender to trace malicious traffic through several proxies to identify its source.",
            insertText: 'T1188',
            range: range,
        }
        ,
        {
            label: 'Remote Access Software',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may use legitimate desktop support and remote access software to establish an interactive command and control channel to target systems within networks. These services, such as `VNC`, `Team Viewer`, `AnyDesk`, `ScreenConnect`, `LogMein`, `AmmyyAdmin`, and other remote monitoring and management (RMM) tools, are commonly used as legitimate technical support software and may be allowed by application control within a target environment.(Citation: Symantec Living off the Land)(Citation: CrowdStrike 2015 Global Threat Report)(Citation: CrySyS Blog TeamSpy)",
            insertText: 'T1219',
            range: range,
        }
        ,
        {
            label: 'Domain Generation Algorithms',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may make use of Domain Generation Algorithms (DGAs) to dynamically identify a destination for command and control traffic rather than relying on a list of static IP addresses or domains. This has the advantage of making it much harder for defenders block, track, or take over the command and control channel, as there potentially could be thousands of domains that malware can check for instructions.(Citation: Cybereason Dissecting DGAs)(Citation: Cisco Umbrella DGA)(Citation: Unit 42 DGA Feb 2019)",
            insertText: 'T1483',
            range: range,
        }
        ,
        {
            label: 'Non-Standard Port',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may communicate using a protocol and port pairing that are typically not associated. For example, HTTPS over port 8088(Citation: Symantec Elfin Mar 2019) or port 587(Citation: Fortinet Agent Tesla April 2018) as opposed to the traditional port 443. Adversaries may make changes to the standard port used by a protocol to bypass filtering or muddle analysis/parsing of network data.",
            insertText: 'T1571',
            range: range,
        }
        ,
        {
            label: 'Protocol Tunneling',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may tunnel network communications to and from a victim system within a separate protocol to avoid detection/network filtering and/or enable access to otherwise unreachable systems. Tunneling involves explicitly encapsulating a protocol within another. This behavior may conceal malicious traffic by blending in with existing traffic and/or provide an outer layer of encryption (similar to a VPN). Tunneling could also enable routing of network packets that would otherwise not reach their intended destination, such as SMB, RDP, or other traffic that would be filtered by network appliances or not routed over the Internet.",
            insertText: 'T1572',
            range: range,
        }
        ,
        {
            label: 'Hide Infrastructure',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may manipulate network traffic in order to hide and evade detection of their C2 infrastructure. This can be accomplished in various ways including by identifying and filtering traffic from defensive tools,(Citation: TA571) masking malicious domains to obfuscate the true destination from both automated scanning tools and security researchers,(Citation: Schema-abuse)(Citation: Facad1ng)(Citation: Browser-updates) and otherwise hiding malicious artifacts to delay discovery and prolong the effectiveness of adversary infrastructure that could otherwise be identified, blocked, or taken down entirely.",
            insertText: 'T1665',
            range: range,
        }
        ,
        {
            label: 'Data Encoding',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may encode data to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system. Use of data encoding may adhere to existing protocol specifications and includes use of ASCII, Unicode, Base64, MIME, or other binary-to-text and character encoding systems.(Citation: Wikipedia Binary-to-text Encoding) (Citation: Wikipedia Character Encoding) Some data encoding systems may also result in data compression, such as gzip.",
            insertText: 'T1132',
            range: range,
        }
        ,
        {
            label: 'Standard Encoding',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may encode data with a standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a standard data encoding system that adheres to existing protocol specifications. Common data encoding schemes include ASCII, Unicode, hexadecimal, Base64, and MIME.(Citation: Wikipedia Binary-to-text Encoding)(Citation: Wikipedia Character Encoding) Some data encoding systems may also result in data compression, such as gzip.",
            insertText: 'T1132.001',
            range: range,
        }
        ,
        {
            label: 'Non-Standard Encoding',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may encode data with a non-standard data encoding system to make the content of command and control traffic more difficult to detect. Command and control (C2) information can be encoded using a non-standard data encoding system that diverges from existing protocol specifications. Non-standard data encoding schemes may be based on or related to standard data encoding schemes, such as a modified Base64 encoding for the message body of an HTTP request.(Citation: Wikipedia Binary-to-text Encoding) (Citation: Wikipedia Character Encoding)",
            insertText: 'T1132.002',
            range: range,
        }
        ,
        {
            label: 'Traffic Signaling',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries use traffic signaling techniques, such as sending specific network sequences or magic packets, to covertly trigger actions like opening ports, activating backdoors, or installing filters, facilitating command and control, persistence, and defense evasion.",
            insertText: 'T1205',
            range: range,
        }
        ,
        {
            label: 'Port Knocking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use port knocking to hide open ports used for persistence or command and control. To enable a port, an adversary sends a series of attempted connections to a predefined sequence of closed ports. After the sequence is completed, opening a port is often accomplished by the host based firewall, but could also be implemented by custom software.",
            insertText: 'T1205.001',
            range: range,
        }
        ,
        {
            label: 'Socket Filters',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attach filters to a network socket to monitor then activate backdoors used for persistence or command and control. With elevated permissions, adversaries can use features such as the `libpcap` library to open sockets and install filters to allow or disallow certain types of data to come through the socket. The filter may apply to all traffic passing through the specified network interface (or every interface if not specified). When the network interface receives a packet matching the filter criteria, additional actions can be triggered on the host, such as activation of a reverse shell.",
            insertText: 'T1205.002',
            range: range,
        }
        ,
        {
            label: 'Encrypted Channel',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may employ an encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if secret keys are encoded and/or generated within malware samples/configuration files.",
            insertText: 'T1573',
            range: range,
        }
        ,
        {
            label: 'Symmetric Cryptography',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may employ a known symmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Symmetric encryption algorithms use the same key for plaintext encryption and ciphertext decryption. Common symmetric encryption algorithms include AES, DES, 3DES, Blowfish, and RC4.",
            insertText: 'T1573.001',
            range: range,
        }
        ,
        {
            label: 'Asymmetric Cryptography',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may employ a known asymmetric encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Asymmetric cryptography, also known as public key cryptography, uses a keypair per party: one public that can be freely distributed, and one private. Due to how the keys are generated, the sender encrypts data with the receiver\u2019s public key and the receiver decrypts the data with their private key. This ensures that only the intended recipient can read the encrypted data. Common public key encryption algorithms include RSA and ElGamal.",
            insertText: 'T1573.002',
            range: range,
        }
        ,
        {
            label: 'Data Obfuscation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may obfuscate command and control traffic to make it more difficult to detect.(Citation: Bitdefender FunnyDream Campaign November 2020) Command and control (C2) communications are hidden (but not necessarily encrypted) in an attempt to make the content more difficult to discover or decipher and to make the communication less conspicuous and hide commands from being seen. This encompasses many methods, such as adding junk data to protocol traffic, using steganography, or impersonating legitimate protocols.",
            insertText: 'T1001',
            range: range,
        }
        ,
        {
            label: 'Junk Data',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may add junk data to protocols used for command and control to make detection more difficult.(Citation: FireEye SUNBURST Backdoor December 2020) By adding random or meaningless data to the protocols used for command and control, adversaries can prevent trivial methods for decoding, deciphering, or otherwise analyzing the traffic. Examples may include appending/prepending data with junk characters or writing junk characters between significant characters.",
            insertText: 'T1001.001',
            range: range,
        }
        ,
        {
            label: 'Steganography',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use steganographic techniques to hide command and control traffic to make detection efforts more difficult. Steganographic techniques can be used to hide data in digital messages that are transferred between systems. This hidden information can be used for command and control of compromised systems. In some cases, the passing of files embedded using steganography, such as image or document files, can be used for command and control.",
            insertText: 'T1001.002',
            range: range,
        }
        ,
        {
            label: 'Protocol or Service Impersonation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may impersonate legitimate protocols or web service traffic to disguise command and control activity and thwart analysis efforts. By impersonating legitimate protocols or web services, adversaries can make their command and control traffic blend in with legitimate network traffic.",
            insertText: 'T1001.003',
            range: range,
        }
        ,
        {
            label: 'Web Service',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use an existing, legitimate external Web service as a means for relaying data to/from a compromised system. Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.",
            insertText: 'T1102',
            range: range,
        }
        ,
        {
            label: 'Dead Drop Resolver',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use an existing, legitimate external Web service to host information that points to additional command and control (C2) infrastructure. Adversaries may post content, known as a dead drop resolver, on Web services with embedded (and often obfuscated/encoded) domains or IP addresses. Once infected, victims will reach out to and be redirected by these resolvers.",
            insertText: 'T1102.001',
            range: range,
        }
        ,
        {
            label: 'Bidirectional Communication',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use an existing, legitimate external Web service as a means for sending commands to and receiving output from a compromised system over the Web service channel. Compromised systems may leverage popular websites and social media to host command and control (C2) instructions. Those infected systems can then send the output from those commands back over that Web service channel. The return traffic may occur in a variety of ways, depending on the Web service being utilized. For example, the return traffic may take the form of the compromised system posting a comment on a forum, issuing a pull request to development project, updating a document hosted on a Web service, or by sending a Tweet.",
            insertText: 'T1102.002',
            range: range,
        }
        ,
        {
            label: 'One-Way Communication',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use an existing, legitimate external Web service as a means for sending commands to a compromised system without receiving return output over the Web service channel. Compromised systems may leverage popular websites and social media to host command and control (C2) instructions. Those infected systems may opt to send the output from those commands back over a different C2 channel, including to another distinct Web service. Alternatively, compromised systems may return no output at all in cases where adversaries want to send instructions to systems and do not want a response.",
            insertText: 'T1102.003',
            range: range,
        }
        ,
        {
            label: 'Dynamic Resolution',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations. This may be achieved by using malware that shares a common algorithm with the infrastructure the adversary uses to receive the malware's communications. These calculations can be used to dynamically adjust parameters such as the domain name, IP address, or port number the malware uses for command and control.",
            insertText: 'T1568',
            range: range,
        }
        ,
        {
            label: 'Fast Flux DNS',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use Fast Flux DNS to hide a command and control channel behind an array of rapidly changing IP addresses linked to a single domain resolution. This technique uses a fully qualified domain name, with multiple IP addresses assigned to it which are swapped with high frequency, using a combination of round robin IP addressing and short Time-To-Live (TTL) for a DNS resource record.(Citation: MehtaFastFluxPt1)(Citation: MehtaFastFluxPt2)(Citation: Fast Flux - Welivesecurity)",
            insertText: 'T1568.001',
            range: range,
        }
        ,
        {
            label: 'Domain Generation Algorithms',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may make use of Domain Generation Algorithms (DGAs) to dynamically identify a destination domain for command and control traffic rather than relying on a list of static IP addresses or domains. This has the advantage of making it much harder for defenders to block, track, or take over the command and control channel, as there potentially could be thousands of domains that malware can check for instructions.(Citation: Cybereason Dissecting DGAs)(Citation: Cisco Umbrella DGA)(Citation: Unit 42 DGA Feb 2019)",
            insertText: 'T1568.002',
            range: range,
        }
        ,
        {
            label: 'DNS Calculation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may perform calculations on addresses returned in DNS results to determine which port and IP address to use for command and control, rather than relying on a predetermined port number or the actual returned IP address. A IP and/or port number calculation can be used to bypass egress filtering on a C2 channel.(Citation: Meyers Numbered Panda)",
            insertText: 'T1568.003',
            range: range,
        }
        ,
        {
            label: 'Proxy',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use a connection proxy to direct network traffic between systems or act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including [HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries use these types of proxies to manage command and control communications, reduce the number of simultaneous outbound network connections, provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between victims to avoid suspicion. Adversaries may chain together multiple proxies to further disguise the source of malicious traffic.",
            insertText: 'T1090',
            range: range,
        }
        ,
        {
            label: 'Internal Proxy',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use an internal proxy to direct command and control traffic between two or more systems in a compromised environment. Many tools exist that enable traffic redirection through proxies or port redirection, including [HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries use internal proxies to manage command and control communications inside a compromised environment, to reduce the number of simultaneous outbound network connections, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths between infected systems to avoid suspicion. Internal proxy connections may use common peer-to-peer (p2p) networking protocols, such as SMB, to better blend in with the environment.",
            insertText: 'T1090.001',
            range: range,
        }
        ,
        {
            label: 'External Proxy',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use an external proxy to act as an intermediary for network communications to a command and control server to avoid direct connections to their infrastructure. Many tools exist that enable traffic redirection through proxies or port redirection, including [HTRAN](https://attack.mitre.org/software/S0040), ZXProxy, and ZXPortMap. (Citation: Trend Micro APT Attack Tools) Adversaries use these types of proxies to manage command and control communications, to provide resiliency in the face of connection loss, or to ride over existing trusted communications paths to avoid suspicion.",
            insertText: 'T1090.002',
            range: range,
        }
        ,
        {
            label: 'Multi-hop Proxy',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may chain together multiple proxies to disguise the source of malicious traffic. Typically, a defender will be able to identify the last proxy traffic traversed before it enters their network; the defender may or may not be able to identify any previous proxies before the last-hop proxy. This technique makes identifying the original source of the malicious traffic even more difficult by requiring the defender to trace malicious traffic through several proxies to identify its source.",
            insertText: 'T1090.003',
            range: range,
        }
        ,
        {
            label: 'Domain Fronting',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may take advantage of routing schemes in Content Delivery Networks (CDNs) and other services which host multiple domains to obfuscate the intended destination of HTTPS traffic or traffic tunneled through HTTPS. (Citation: Fifield Blocking Resistent Communication through domain fronting 2015) Domain fronting involves using different domain names in the SNI field of the TLS header and the Host field of the HTTP header. If both domains are served from the same CDN, then the CDN may route to the address specified in the HTTP header after unwrapping the TLS header. A variation of the the technique, \"domainless\" fronting, utilizes a SNI field that is left blank; this may allow the fronting to work even when the CDN attempts to validate that the SNI and HTTP Host fields match (if the blank SNI fields are ignored).",
            insertText: 'T1090.004',
            range: range,
        }
        ,
        {
            label: 'Application Layer Protocol',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.",
            insertText: 'T1071',
            range: range,
        }
        ,
        {
            label: 'Web Protocols',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.",
            insertText: 'T1071.001',
            range: range,
        }
        ,
        {
            label: 'File Transfer Protocols',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may communicate using application layer protocols associated with transferring files to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.",
            insertText: 'T1071.002',
            range: range,
        }
        ,
        {
            label: 'Mail Protocols',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may communicate using application layer protocols associated with electronic mail delivery to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.",
            insertText: 'T1071.003',
            range: range,
        }
        ,
        {
            label: 'DNS',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.",
            insertText: 'T1071.004',
            range: range,
        }
        ,
        {
            label: 'Publish/Subscribe Protocols',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may communicate using publish/subscribe (pub/sub) application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.",
            insertText: 'T1071.005',
            range: range,
        }
        ,
        {
            label: 'Network Sniffing',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may passively sniff network traffic to capture information about an environment, including authentication material passed over the network. Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.",
            insertText: 'T1040',
            range: range,
        }
        ,
        {
            label: 'Credentials in Files',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search local file systems and remote file shares for files containing passwords. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.",
            insertText: 'T1081',
            range: range,
        }
        ,
        {
            label: 'Multi-Factor Authentication Interception',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may target multi-factor authentication (MFA) mechanisms, (i.e., smart cards, token generators, etc.) to gain access to credentials that can be used to access systems, services, and network resources. Use of MFA is recommended and provides a higher level of security than usernames and passwords alone, but organizations should be aware of techniques that could be used to intercept and bypass these security mechanisms.",
            insertText: 'T1111',
            range: range,
        }
        ,
        {
            label: 'Bash History',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Bash keeps track of the commands users type on the command-line with the \"history\" utility. Once a user logs out, the history is flushed to the user\u2019s <code>.bash_history</code> file. For each user, this file resides at the same location: <code>~/.bash_history</code>. Typically, this file keeps track of the user\u2019s last 500 commands. Users often type usernames and passwords on the command-line as parameters to programs, which then get saved to this file when they log out. Attackers can abuse this by looking through the file for potential credentials. (Citation: External to DA, the OS X Way)",
            insertText: 'T1139',
            range: range,
        }
        ,
        {
            label: 'Input Prompt',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task (ex: [Bypass User Account Control](https://attack.mitre.org/techniques/T1088)).",
            insertText: 'T1141',
            range: range,
        }
        ,
        {
            label: 'Keychain',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Keychains are the built-in way for macOS to keep track of users' passwords and credentials for many services and features such as WiFi passwords, websites, secure notes, certificates, and Kerberos. Keychain files are located in <code>~/Library/Keychains/</code>,<code>/Library/Keychains/</code>, and <code>/Network/Library/Keychains/</code>. (Citation: Wikipedia keychain) The <code>security</code> command-line utility, which is built into macOS by default, provides a useful way to manage these credentials.",
            insertText: 'T1142',
            range: range,
        }
        ,
        {
            label: 'Private Keys',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures. (Citation: Wikipedia Public Key Crypto)",
            insertText: 'T1145',
            range: range,
        }
        ,
        {
            label: 'Securityd Memory',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "In OS X prior to El Capitan, users with root access can read plaintext keychain passwords of logged-in users because Apple\u2019s keychain implementation allows these credentials to be cached so that users are not repeatedly prompted for passwords. (Citation: OS X Keychain) (Citation: External to DA, the OS X Way) Apple\u2019s securityd utility takes the user\u2019s logon password, encrypts it with PBKDF2, and stores this master key in memory. Apple also uses a set of keys and algorithms to encrypt the user\u2019s password, but once the master key is found, an attacker need only iterate over the other values to unlock the final password. (Citation: OS X Keychain)",
            insertText: 'T1167',
            range: range,
        }
        ,
        {
            label: 'LLMNR/NBT-NS Poisoning and Relay',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. NBT-NS identifies systems on a local network by their NetBIOS name. (Citation: Wikipedia LLMNR) (Citation: TechNet NetBIOS)",
            insertText: 'T1171',
            range: range,
        }
        ,
        {
            label: 'Password Filter DLL',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Windows password filters are password policy enforcement mechanisms for both domain and local accounts. Filters are implemented as dynamic link libraries (DLLs) containing a method to validate potential passwords against password policies. Filter DLLs can be positioned on local computers for local accounts and/or domain controllers for domain accounts.",
            insertText: 'T1174',
            range: range,
        }
        ,
        {
            label: 'Hooking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Windows processes often leverage application programming interface (API) functions to perform tasks that require reusable system resources. Windows API functions are typically stored in dynamic-link libraries (DLLs) as exported functions.",
            insertText: 'T1179',
            range: range,
        }
        ,
        {
            label: 'Forced Authentication',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather credential material by invoking or forcing a user to automatically provide authentication information through a mechanism in which they can intercept.",
            insertText: 'T1187',
            range: range,
        }
        ,
        {
            label: 'Kerberoasting',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Service principal names (SPNs) are used to uniquely identify each instance of a Windows service. To enable authentication, Kerberos requires that SPNs be associated with at least one service logon account (an account specifically tasked with running a service (Citation: Microsoft Detecting Kerberoasting Feb 2018)). (Citation: Microsoft SPN) (Citation: Microsoft SetSPN) (Citation: SANS Attacking Kerberos Nov 2014) (Citation: Harmj0y Kerberoast Nov 2016)",
            insertText: 'T1208',
            range: range,
        }
        ,
        {
            label: 'Exploitation for Credential Access',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may exploit software vulnerabilities in an attempt to collect credentials. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.\u00a0",
            insertText: 'T1212',
            range: range,
        }
        ,
        {
            label: 'Credentials in Registry',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "The Windows Registry stores configuration information that can be used by the system or other programs. Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services. Sometimes these credentials are used for automatic logons.",
            insertText: 'T1214',
            range: range,
        }
        ,
        {
            label: 'Credentials from Web Browsers',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may acquire credentials from web browsers by reading files specific to the target browser.  (Citation: Talos Olympic Destroyer 2018)",
            insertText: 'T1503',
            range: range,
        }
        ,
        {
            label: 'Cloud Instance Metadata API',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data.",
            insertText: 'T1522',
            range: range,
        }
        ,
        {
            label: 'Steal Application Access Token',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries can steal application access tokens as a means of acquiring credentials to access remote systems and resources.",
            insertText: 'T1528',
            range: range,
        }
        ,
        {
            label: 'Steal Web Session Cookie',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may steal web application or service session cookies and use them to gain access to web applications or Internet services as an authenticated user without needing credentials. Web applications and services often use session cookies as an authentication token after a user has authenticated to a website.",
            insertText: 'T1539',
            range: range,
        }
        ,
        {
            label: 'Multi-Factor Authentication Request Generation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to bypass multi-factor authentication (MFA) mechanisms and gain access to accounts by generating MFA requests sent to users.",
            insertText: 'T1621',
            range: range,
        }
        ,
        {
            label: 'Steal or Forge Authentication Certificates',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may steal or forge certificates used for authentication to access remote systems or resources. Digital certificates are often used to sign and encrypt messages and/or files. Certificates are also used as authentication material. For example, Azure AD device certificates and Active Directory Certificate Services (AD CS) certificates bind to an identity and can be used as credentials for domain accounts.(Citation: O365 Blog Azure AD Device IDs)(Citation: Microsoft AD CS Overview)",
            insertText: 'T1649',
            range: range,
        }
        ,
        {
            label: 'Forge Web Credentials',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may forge credential materials that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies, tokens, or other materials to authenticate and authorize user access.",
            insertText: 'T1606',
            range: range,
        }
        ,
        {
            label: 'Web Cookies',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may forge web cookies that can be used to gain access to web applications or Internet services. Web applications and services (hosted in cloud SaaS environments or on-premise servers) often use session cookies to authenticate and authorize user access.",
            insertText: 'T1606.001',
            range: range,
        }
        ,
        {
            label: 'SAML Tokens',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may forge SAML tokens with any permissions claims and lifetimes if they possess a valid SAML token-signing certificate.(Citation: Microsoft SolarWinds Steps) The default lifetime of a SAML token is one hour, but the validity period can be specified in the <code>NotOnOrAfter</code> value of the <code>conditions ...</code> element in a token. This value can be changed using the <code>AccessTokenLifetime</code> in a <code>LifetimeTokenPolicy</code>.(Citation: Microsoft SAML Token Lifetimes) Forged SAML tokens enable adversaries to authenticate across services that use SAML 2.0 as an SSO (single sign-on) mechanism.(Citation: Cyberark Golden SAML)",
            insertText: 'T1606.002',
            range: range,
        }
        ,
        {
            label: 'Brute Force',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.(Citation: TrendMicro Pawn Storm Dec 2020) Without knowledge of the password for an account or set of accounts, an adversary may systematically guess the password using a repetitive or iterative mechanism.(Citation: Dragos Crashoverride 2018) Brute forcing passwords can take place via interaction with a service that will check the validity of those credentials or offline against previously acquired credential data, such as password hashes.",
            insertText: 'T1110',
            range: range,
        }
        ,
        {
            label: 'Password Guessing',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts. Without knowledge of the password for an account, an adversary may opt to systematically guess the password using a repetitive or iterative mechanism. An adversary may guess login credentials without prior knowledge of system or environment passwords during an operation by using a list of common passwords. Password guessing may or may not take into account the target's policies on password complexity or use policies that may lock accounts out after a number of failed attempts.",
            insertText: 'T1110.001',
            range: range,
        }
        ,
        {
            label: 'Password Cracking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained. [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) can be used to obtain password hashes, this may only get an adversary so far when [Pass the Hash](https://attack.mitre.org/techniques/T1550/002) is not an option. Further,  adversaries may leverage [Data from Configuration Repository](https://attack.mitre.org/techniques/T1602) in order to obtain hashed credentials for network devices.(Citation: US-CERT-TA18-106A)",
            insertText: 'T1110.002',
            range: range,
        }
        ,
        {
            label: 'Password Spraying',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. 'Password01'), or a small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords. (Citation: BlackHillsInfosec Password Spraying)",
            insertText: 'T1110.003',
            range: range,
        }
        ,
        {
            label: 'Credential Stuffing',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use credentials obtained from breach dumps of unrelated accounts to gain access to target accounts through credential overlap. Occasionally, large numbers of username and password pairs are dumped online when a website or service is compromised and the user account credentials accessed. The information may be useful to an adversary attempting to compromise accounts by taking advantage of the tendency for users to use the same passwords across personal and business accounts.",
            insertText: 'T1110.004',
            range: range,
        }
        ,
        {
            label: 'Steal or Forge Kerberos Tickets',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to subvert Kerberos authentication by stealing or forging Kerberos tickets to enable [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003). Kerberos is an authentication protocol widely used in modern Windows domain environments. In Kerberos environments, referred to as \u201crealms\u201d, there are three basic participants: client, service, and Key Distribution Center (KDC).(Citation: ADSecurity Kerberos Ring Decoder) Clients request access to a service and through the exchange of Kerberos tickets, originating from KDC, they are granted access after having successfully authenticated. The KDC is responsible for both authentication and ticket granting.  Adversaries may attempt to abuse Kerberos by stealing tickets or forging tickets to enable unauthorized access.",
            insertText: 'T1558',
            range: range,
        }
        ,
        {
            label: 'Golden Ticket',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket.(Citation: AdSecurity Kerberos GT Aug 2015) Golden tickets enable adversaries to generate authentication material for any account in Active Directory.(Citation: CERT-EU Golden Ticket Protection)",
            insertText: 'T1558.001',
            range: range,
        }
        ,
        {
            label: 'Silver Ticket',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries who have the password hash of a target service account (e.g. SharePoint, MSSQL) may forge Kerberos ticket granting service (TGS) tickets, also known as silver tickets. Kerberos TGS tickets are also known as service tickets.(Citation: ADSecurity Silver Tickets)",
            insertText: 'T1558.002',
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
            label: 'AS-REP Roasting',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may reveal credentials of accounts that have disabled Kerberos preauthentication by [Password Cracking](https://attack.mitre.org/techniques/T1110/002) Kerberos messages.(Citation: Harmj0y Roasting AS-REPs Jan 2017)",
            insertText: 'T1558.004',
            range: range,
        }
        ,
        {
            label: 'Ccache Files',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to steal Kerberos tickets stored in credential cache files (or ccache). These files are used for short term storage of a user's active session credentials. The ccache file is created upon user authentication and allows for access to multiple services without the user having to re-enter credentials.",
            insertText: 'T1558.005',
            range: range,
        }
        ,
        {
            label: 'Credentials from Password Stores',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search for common password storage locations to obtain user credentials.(Citation: F-Secure The Dukes) Passwords are stored in several places on a system, depending on the operating system or application holding the credentials. There are also specific applications and services that store passwords to make them easier for users to manage and maintain, such as password managers and cloud secrets vaults. Once credentials are obtained, they can be used to perform lateral movement and access restricted information.",
            insertText: 'T1555',
            range: range,
        }
        ,
        {
            label: 'Keychain',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may acquire credentials from Keychain. Keychain (or Keychain Services) is the macOS credential management system that stores account names, passwords, private keys, certificates, sensitive application data, payment data, and secure notes. There are three types of Keychains: Login Keychain, System Keychain, and Local Items (iCloud) Keychain. The default Keychain is the Login Keychain, which stores user passwords and information. The System Keychain stores items accessed by the operating system, such as items shared among users on a host. The Local Items (iCloud) Keychain is used for items synced with Apple\u2019s iCloud service.",
            insertText: 'T1555.001',
            range: range,
        }
        ,
        {
            label: 'Securityd Memory',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary with root access may gather credentials by reading `securityd`\u2019s memory. `securityd` is a service/daemon responsible for implementing security protocols such as encryption and authorization.(Citation: Apple Dev SecurityD) A privileged adversary may be able to scan through `securityd`'s memory to find the correct sequence of keys to decrypt the user\u2019s logon keychain. This may provide the adversary with various plaintext passwords, such as those for users, WiFi, mail, browsers, certificates, secure notes, etc.(Citation: OS X Keychain)(Citation: OSX Keydnap malware)",
            insertText: 'T1555.002',
            range: range,
        }
        ,
        {
            label: 'Credentials from Web Browsers',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may acquire credentials from web browsers by reading files specific to the target browser.(Citation: Talos Olympic Destroyer 2018) Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future. Web browsers typically store the credentials in an encrypted format within a credential store; however, methods exist to extract plaintext credentials from web browsers.",
            insertText: 'T1555.003',
            range: range,
        }
        ,
        {
            label: 'Windows Credential Manager',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may acquire credentials from the Windows Credential Manager. The Credential Manager stores credentials for signing into websites, applications, and/or devices that request authentication through NTLM or Kerberos in Credential Lockers (previously known as Windows Vaults).(Citation: Microsoft Credential Manager store)(Citation: Microsoft Credential Locker)",
            insertText: 'T1555.004',
            range: range,
        }
        ,
        {
            label: 'Password Managers',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may acquire user credentials from third-party password managers.(Citation: ise Password Manager February 2019) Password managers are applications designed to store user credentials, normally in an encrypted database. Credentials are typically accessible after a user provides a master password that unlocks the database. After the database is unlocked, these credentials may be copied to memory. These databases can be stored as files on disk.(Citation: ise Password Manager February 2019)",
            insertText: 'T1555.005',
            range: range,
        }
        ,
        {
            label: 'Cloud Secrets Management Stores',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may acquire credentials from cloud-native secret management solutions such as AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and Terraform Vault.",
            insertText: 'T1555.006',
            range: range,
        }
        ,
        {
            label: 'OS Credential Dumping',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to dump credentials to obtain account login and credential material, normally in the form of a hash or a clear text password. Credentials can be obtained from OS caches, memory, or structures.(Citation: Brining MimiKatz to Unix) Credentials can then be used to perform [Lateral Movement](https://attack.mitre.org/tactics/TA0008) and access restricted information.",
            insertText: 'T1003',
            range: range,
        }
        ,
        {
            label: 'LSASS Memory',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). After a user logs on, the system generates and stores a variety of credential materials in LSASS process memory. These credential materials can be harvested by an administrative user or SYSTEM and used to conduct [Lateral Movement](https://attack.mitre.org/tactics/TA0008) using [Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550).",
            insertText: 'T1003.001',
            range: range,
        }
        ,
        {
            label: 'Security Account Manager',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to extract credential material from the Security Account Manager (SAM) database either through in-memory techniques or through the Windows Registry where the SAM database is stored. The SAM is a database file that contains local accounts for the host, typically those found with the <code>net user</code> command. Enumerating the SAM database requires SYSTEM level access.",
            insertText: 'T1003.002',
            range: range,
        }
        ,
        {
            label: 'NTDS',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to access or create a copy of the Active Directory domain database in order to steal credential information, as well as obtain other information about domain members such as devices, users, and access rights. By default, the NTDS file (NTDS.dit) is located in <code>%SystemRoot%\\NTDS\\Ntds.dit</code> of a domain controller.(Citation: Wikipedia Active Directory)",
            insertText: 'T1003.003',
            range: range,
        }
        ,
        {
            label: 'LSA Secrets',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries with SYSTEM access to a host may attempt to access Local Security Authority (LSA) secrets, which can contain a variety of different credential materials, such as credentials for service accounts.(Citation: Passcape LSA Secrets)(Citation: Microsoft AD Admin Tier Model)(Citation: Tilbury Windows Credentials) LSA secrets are stored in the registry at <code>HKEY_LOCAL_MACHINE\\SECURITY\\Policy\\Secrets</code>. LSA secrets can also be dumped from memory.(Citation: ired Dumping LSA Secrets)",
            insertText: 'T1003.004',
            range: range,
        }
        ,
        {
            label: 'Cached Domain Credentials',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to access cached domain credentials used to allow authentication to occur in the event a domain controller is unavailable.(Citation: Microsoft - Cached Creds)",
            insertText: 'T1003.005',
            range: range,
        }
        ,
        {
            label: 'DCSync',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to access credentials and other sensitive information by abusing a Windows Domain Controller's application programming interface (API)(Citation: Microsoft DRSR Dec 2017) (Citation: Microsoft GetNCCChanges) (Citation: Samba DRSUAPI) (Citation: Wine API samlib.dll) to simulate the replication process from a remote domain controller using a technique called DCSync.",
            insertText: 'T1003.006',
            range: range,
        }
        ,
        {
            label: 'Proc Filesystem',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather credentials from the proc filesystem or `/proc`. The proc filesystem is a pseudo-filesystem used as an interface to kernel data structures for Linux based systems managing virtual memory. For each process, the `/proc/<PID>/maps` file shows how memory is mapped within the process\u2019s virtual address space. And `/proc/<PID>/mem`, exposed for debugging purposes, provides access to the process\u2019s virtual address space.(Citation: Picus Labs Proc cump 2022)(Citation: baeldung Linux proc map 2022)",
            insertText: 'T1003.007',
            range: range,
        }
        ,
        {
            label: '/etc/passwd and /etc/shadow',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to dump the contents of <code>/etc/passwd</code> and <code>/etc/shadow</code> to enable offline password cracking. Most modern Linux operating systems use a combination of <code>/etc/passwd</code> and <code>/etc/shadow</code> to store user account information including password hashes in <code>/etc/shadow</code>. By default, <code>/etc/shadow</code> is only readable by the root user.(Citation: Linux Password and Shadow File Formats)",
            insertText: 'T1003.008',
            range: range,
        }
        ,
        {
            label: 'Unsecured Credentials',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search compromised systems to find and obtain insecurely stored credentials. These credentials can be stored and/or misplaced in many locations on a system, including plaintext files (e.g. [Bash History](https://attack.mitre.org/techniques/T1552/003)), operating system or application-specific repositories (e.g. [Credentials in Registry](https://attack.mitre.org/techniques/T1552/002)),  or other specialized files/artifacts (e.g. [Private Keys](https://attack.mitre.org/techniques/T1552/004)).(Citation: Brining MimiKatz to Unix)",
            insertText: 'T1552',
            range: range,
        }
        ,
        {
            label: 'Credentials In Files',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search local file systems and remote file shares for files containing insecurely stored credentials. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.",
            insertText: 'T1552.001',
            range: range,
        }
        ,
        {
            label: 'Credentials in Registry',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search the Registry on compromised systems for insecurely stored credentials. The Windows Registry stores configuration information that can be used by the system or other programs. Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services. Sometimes these credentials are used for automatic logons.",
            insertText: 'T1552.002',
            range: range,
        }
        ,
        {
            label: 'Bash History',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search the bash command history on compromised systems for insecurely stored credentials. Bash keeps track of the commands users type on the command-line with the \"history\" utility. Once a user logs out, the history is flushed to the user\u2019s <code>.bash_history</code> file. For each user, this file resides at the same location: <code>~/.bash_history</code>. Typically, this file keeps track of the user\u2019s last 500 commands. Users often type usernames and passwords on the command-line as parameters to programs, which then get saved to this file when they log out. Adversaries can abuse this by looking through the file for potential credentials. (Citation: External to DA, the OS X Way)",
            insertText: 'T1552.003',
            range: range,
        }
        ,
        {
            label: 'Private Keys',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials. Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures.(Citation: Wikipedia Public Key Crypto) Common key and certificate file extensions include: .key, .pgp, .gpg, .ppk., .p12, .pem, .pfx, .cer, .p7b, .asc.",
            insertText: 'T1552.004',
            range: range,
        }
        ,
        {
            label: 'Cloud Instance Metadata API',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to access the Cloud Instance Metadata API to collect credentials and other sensitive data.",
            insertText: 'T1552.005',
            range: range,
        }
        ,
        {
            label: 'Group Policy Preferences',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to find unsecured credentials in Group Policy Preferences (GPP). GPP are tools that allow administrators to create domain policies with embedded credentials. These policies allow administrators to set local accounts.(Citation: Microsoft GPP 2016)",
            insertText: 'T1552.006',
            range: range,
        }
        ,
        {
            label: 'Container API',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather credentials via APIs within a containers environment. APIs in these environments, such as the Docker API and Kubernetes APIs, allow a user to remotely manage their container resources and cluster components.(Citation: Docker API)(Citation: Kubernetes API)",
            insertText: 'T1552.007',
            range: range,
        }
        ,
        {
            label: 'Chat Messages',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may directly collect unsecured credentials stored or passed through user communication services. Credentials may be sent and stored in user chat communication applications such as email, chat services like Slack or Teams, collaboration tools like Jira or Trello, and any other services that support user communication. Users may share various forms of credentials (such as usernames and passwords, API keys, or authentication tokens) on private or public corporate internal communications channels.",
            insertText: 'T1552.008',
            range: range,
        }
        ,
        {
            label: 'Modify Authentication Process',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify authentication mechanisms and processes to access user credentials or enable otherwise unwarranted access to accounts. The authentication process is handled by mechanisms, such as the Local Security Authentication Server (LSASS) process and the Security Accounts Manager (SAM) on Windows, pluggable authentication modules (PAM) on Unix-based systems, and authorization plugins on MacOS systems, responsible for gathering, storing, and validating credentials. By modifying an authentication process, an adversary may be able to authenticate to a service or system without using [Valid Accounts](https://attack.mitre.org/techniques/T1078).",
            insertText: 'T1556',
            range: range,
        }
        ,
        {
            label: 'Domain Controller Authentication',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may patch the authentication process on a domain controller to bypass the typical authentication mechanisms and enable access to accounts.",
            insertText: 'T1556.001',
            range: range,
        }
        ,
        {
            label: 'Password Filter DLL',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may register malicious password filter dynamic link libraries (DLLs) into the authentication process to acquire user credentials as they are validated.",
            insertText: 'T1556.002',
            range: range,
        }
        ,
        {
            label: 'Pluggable Authentication Modules',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify pluggable authentication modules (PAM) to access user credentials or enable otherwise unwarranted access to accounts. PAM is a modular system of configuration files, libraries, and executable files which guide authentication for many services. The most common authentication module is <code>pam_unix.so</code>, which retrieves, sets, and verifies account authentication information in <code>/etc/passwd</code> and <code>/etc/shadow</code>.(Citation: Apple PAM)(Citation: Man Pam_Unix)(Citation: Red Hat PAM)",
            insertText: 'T1556.003',
            range: range,
        }
        ,
        {
            label: 'Network Device Authentication',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use [Patch System Image](https://attack.mitre.org/techniques/T1601/001) to hard code a password in the operating system, thus bypassing of native authentication mechanisms for local accounts on network devices.",
            insertText: 'T1556.004',
            range: range,
        }
        ,
        {
            label: 'Reversible Encryption',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may abuse Active Directory authentication encryption properties to gain access to credentials on Windows systems. The <code>AllowReversiblePasswordEncryption</code> property specifies whether reversible password encryption for an account is enabled or disabled. By default this property is disabled (instead storing user credentials as the output of one-way hashing functions) and should not be enabled unless legacy or other software require it.(Citation: store_pwd_rev_enc)",
            insertText: 'T1556.005',
            range: range,
        }
        ,
        {
            label: 'Multi-Factor Authentication',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may disable or modify multi-factor authentication (MFA) mechanisms to enable persistent access to compromised accounts.",
            insertText: 'T1556.006',
            range: range,
        }
        ,
        {
            label: 'Hybrid Identity',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may patch, modify, or otherwise backdoor cloud authentication processes that are tied to on-premises user identities in order to bypass typical authentication mechanisms, access credentials, and enable persistent access to accounts.",
            insertText: 'T1556.007',
            range: range,
        }
        ,
        {
            label: 'Network Provider DLL',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may register malicious network provider dynamic link libraries (DLLs) to capture cleartext user credentials during the authentication process. Network provider DLLs allow Windows to interface with specific network protocols and can also support add-on credential management functions.(Citation: Network Provider API) During the logon process, Winlogon (the interactive logon module) sends credentials to the local `mpnotify.exe` process via RPC. The `mpnotify.exe` process then shares the credentials in cleartext with registered credential managers when notifying that a logon event is happening.(Citation: NPPSPY - Huntress)(Citation: NPPSPY Video)(Citation: NPLogonNotify)",
            insertText: 'T1556.008',
            range: range,
        }
        ,
        {
            label: 'Conditional Access Policies',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may disable or modify conditional access policies to enable persistent access to compromised accounts. Conditional access policies are additional verifications used by identity providers and identity and access management systems to determine whether a user should be granted access to a resource.",
            insertText: 'T1556.009',
            range: range,
        }
        ,
        {
            label: 'System Service Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may try to gather information about registered local system services. Adversaries may obtain information about services using tools as well as OS utility commands such as <code>sc query</code>, <code>tasklist /svc</code>, <code>systemctl --type=service</code>, and <code>net start</code>.",
            insertText: 'T1007',
            range: range,
        }
        ,
        {
            label: 'Application Window Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used.(Citation: Prevailion DarkWatchman 2021) For example, information about application windows could be used identify potential data to collect as well as identifying security tooling ([Security Software Discovery](https://attack.mitre.org/techniques/T1518/001)) to evade.(Citation: ESET Grandoreiro April 2020)",
            insertText: 'T1010',
            range: range,
        }
        ,
        {
            label: 'Query Registry',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.",
            insertText: 'T1012',
            range: range,
        }
        ,
        {
            label: 'Remote System Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used such as  [Ping](https://attack.mitre.org/software/S0097) or <code>net view</code> using [Net](https://attack.mitre.org/software/S0039).",
            insertText: 'T1018',
            range: range,
        }
        ,
        {
            label: 'System Owner/User Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to identify the primary user, currently logged in user, set of users that commonly uses a system, or whether a user is actively using the system. They may do this, for example, by retrieving account usernames or by using [OS Credential Dumping](https://attack.mitre.org/techniques/T1003). The information may be collected in a number of different ways using other Discovery techniques, because user and username details are prevalent throughout a system and include running process ownership, file/directory ownership, session information, and system logs. Adversaries may use the information from [System Owner/User Discovery](https://attack.mitre.org/techniques/T1033) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
            insertText: 'T1033',
            range: range,
        }
        ,
        {
            label: 'Network Service Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port and/or vulnerability scans using tools that are brought onto a system.(Citation: CISA AR21-126A FIVEHANDS May 2021)",
            insertText: 'T1046',
            range: range,
        }
        ,
        {
            label: 'System Network Connections Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.",
            insertText: 'T1049',
            range: range,
        }
        ,
        {
            label: 'Process Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to get information about running processes on a system. Information obtained could be used to gain an understanding of common software/applications running on systems within the network. Administrator or otherwise elevated access may provide better process details. Adversaries may use the information from [Process Discovery](https://attack.mitre.org/techniques/T1057) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
            insertText: 'T1057',
            range: range,
        }
        ,
        {
            label: 'Security Software Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on the system. This may include things such as local firewall rules and anti-virus. Adversaries may use the information from [Security Software Discovery](https://attack.mitre.org/techniques/T1063) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
            insertText: 'T1063',
            range: range,
        }
        ,
        {
            label: 'System Information Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture. Adversaries may use the information from [System Information Discovery](https://attack.mitre.org/techniques/T1082) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
            insertText: 'T1082',
            range: range,
        }
        ,
        {
            label: 'File and Directory Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Adversaries may use the information from [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
            insertText: 'T1083',
            range: range,
        }
        ,
        {
            label: 'Peripheral Device Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to gather information about attached peripheral devices and components connected to a computer system.(Citation: Peripheral Discovery Linux)(Citation: Peripheral Discovery macOS) Peripheral devices could include auxiliary resources that support a variety of functionalities such as keyboards, printers, cameras, smart card readers, or removable storage. The information may be used to enhance their awareness of the system and network environment or may be used for further actions.",
            insertText: 'T1120',
            range: range,
        }
        ,
        {
            label: 'System Time Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may gather the system time and/or time zone settings from a local or remote system. The system time is set and stored by services, such as the Windows Time Service on Windows or <code>systemsetup</code> on macOS.(Citation: MSDN System Time)(Citation: Technet Windows Time Service)(Citation: systemsetup mac time) These time settings may also be synchronized between systems and services in an enterprise network, typically accomplished with a network time server within a domain.(Citation: Mac Time Sync)(Citation: linux system time)",
            insertText: 'T1124',
            range: range,
        }
        ,
        {
            label: 'Network Share Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may look for folders and drives shared on remote systems as a means of identifying sources of information to gather as a precursor for Collection and to identify potential systems of interest for Lateral Movement. Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network.",
            insertText: 'T1135',
            range: range,
        }
        ,
        {
            label: 'Password Policy Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to access detailed information about the password policy used within an enterprise network or cloud environment. Password policies are a way to enforce complex passwords that are difficult to guess or crack through [Brute Force](https://attack.mitre.org/techniques/T1110). This information may help the adversary to create a list of common passwords and launch dictionary and/or brute force attacks which adheres to the policy (e.g. if the minimum password length should be 8, then not trying passwords such as 'pass123'; not checking for more than 3-4 passwords per account if the lockout is set to 6 as to not lock out accounts).",
            insertText: 'T1201',
            range: range,
        }
        ,
        {
            label: 'Browser Information Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may enumerate information about browsers to learn more about compromised environments. Data saved by browsers (such as bookmarks, accounts, and browsing history) may reveal a variety of personal information about users (e.g., banking sites, relationships/interests, social media, etc.) as well as details about internal network resources such as servers, tools/dashboards, or other related infrastructure.(Citation: Kaspersky Autofill)",
            insertText: 'T1217',
            range: range,
        }
        ,
        {
            label: 'Domain Trust Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to gather information on domain trust relationships that may be used to identify lateral movement opportunities in Windows multi-domain/forest environments. Domain trusts provide a mechanism for a domain to allow access to resources based on the authentication procedures of another domain.(Citation: Microsoft Trusts) Domain trusts allow the users of the trusted domain to access resources in the trusting domain. The information discovered may help the adversary conduct [SID-History Injection](https://attack.mitre.org/techniques/T1134/005), [Pass the Ticket](https://attack.mitre.org/techniques/T1550/003), and [Kerberoasting](https://attack.mitre.org/techniques/T1558/003).(Citation: AdSecurity Forging Trust Tickets)(Citation: Harmj0y Domain Trusts) Domain trusts can be enumerated using the `DSEnumerateDomainTrusts()` Win32 API call, .NET methods, and LDAP.(Citation: Harmj0y Domain Trusts) The Windows utility [Nltest](https://attack.mitre.org/software/S0359) is known to be used by adversaries to enumerate domain trusts.(Citation: Microsoft Operation Wilysupply)",
            insertText: 'T1482',
            range: range,
        }
        ,
        {
            label: 'Cloud Service Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may attempt to enumerate the cloud services running on a system after gaining access. These methods can differ from platform-as-a-service (PaaS), to infrastructure-as-a-service (IaaS), or software-as-a-service (SaaS). Many services exist throughout the various cloud providers and can include Continuous Integration and Continuous Delivery (CI/CD), Lambda Functions, Azure AD, etc. They may also include security services, such as AWS GuardDuty and Microsoft Defender for Cloud, and logging services, such as AWS CloudTrail and Google Cloud Audit Logs.",
            insertText: 'T1526',
            range: range,
        }
        ,
        {
            label: 'Cloud Service Dashboard',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information from an operational cloud environment, such as specific services, resources, and features. For example, the GCP Command Center can be used to view all assets, findings of potential security risks, and to run additional queries, such as finding public IP addresses and open ports.(Citation: Google Command Center Dashboard)",
            insertText: 'T1538',
            range: range,
        }
        ,
        {
            label: 'Cloud Infrastructure Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may attempt to discover infrastructure and resources that are available within an infrastructure-as-a-service (IaaS) environment. This includes compute service resources such as instances, virtual machines, and snapshots as well as resources of other services including the storage and database services.",
            insertText: 'T1580',
            range: range,
        }
        ,
        {
            label: 'Container and Resource Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to discover containers and other resources that are available within a containers environment. Other resources may include images, deployments, pods, nodes, and other information such as the status of a cluster.",
            insertText: 'T1613',
            range: range,
        }
        ,
        {
            label: 'Group Policy Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gather information on Group Policy settings to identify paths for privilege escalation, security measures applied within a domain, and to discover patterns in domain objects that can be manipulated or used to blend in the environment. Group Policy allows for centralized management of user and computer settings in Active Directory (AD). Group policy objects (GPOs) are containers for group policy settings made up of files stored within a predictable network path `\\<DOMAIN>\\SYSVOL\\<DOMAIN>\\Policies\\`.(Citation: TechNet Group Policy Basics)(Citation: ADSecurity GPO Persistence 2016)",
            insertText: 'T1615',
            range: range,
        }
        ,
        {
            label: 'Cloud Storage Object Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may enumerate objects in cloud storage infrastructure. Adversaries may use this information during automated discovery to shape follow-on behaviors, including requesting all or specific objects from cloud storage.  Similar to [File and Directory Discovery](https://attack.mitre.org/techniques/T1083) on a local host, after identifying available storage services (i.e. [Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580)) adversaries may access the contents/objects stored in cloud infrastructure.",
            insertText: 'T1619',
            range: range,
        }
        ,
        {
            label: 'Debugger Evasion',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may employ various means to detect and avoid debuggers. Debuggers are typically used by defenders to trace and/or analyze the execution of potential malware payloads.(Citation: ProcessHacker Github)",
            insertText: 'T1622',
            range: range,
        }
        ,
        {
            label: 'Device Driver Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to enumerate local device drivers on a victim host. Information about device drivers may highlight various insights that shape follow-on behaviors, such as the function/purpose of the host, present security tools (i.e. [Security Software Discovery](https://attack.mitre.org/techniques/T1518/001)) or other defenses (e.g., [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497)), as well as potential exploitable vulnerabilities (e.g., [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)).",
            insertText: 'T1652',
            range: range,
        }
        ,
        {
            label: 'Log Enumeration',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may enumerate system and service logs to find useful data. These logs may highlight various types of valuable insights for an adversary, such as user authentication records ([Account Discovery](https://attack.mitre.org/techniques/T1087)), security or vulnerable software ([Software Discovery](https://attack.mitre.org/techniques/T1518)), or hosts within a compromised network ([Remote System Discovery](https://attack.mitre.org/techniques/T1018)).",
            insertText: 'T1654',
            range: range,
        }
        ,
        {
            label: 'Software Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to get a listing of software and software versions that are installed on a system or in a cloud environment. Adversaries may use the information from [Software Discovery](https://attack.mitre.org/techniques/T1518) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
            insertText: 'T1518',
            range: range,
        }
        ,
        {
            label: 'Security Software Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on a system or in a cloud environment. This may include things such as cloud monitoring agents and anti-virus. Adversaries may use the information from [Security Software Discovery](https://attack.mitre.org/techniques/T1518/001) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.",
            insertText: 'T1518.001',
            range: range,
        }
        ,
        {
            label: 'System Location Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "",
            insertText: 'T1614',
            range: range,
        }
        ,
        {
            label: 'System Language Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to gather information about the system language of a victim in order to infer the geographical location of that host. This information may be used to shape follow-on behaviors, including whether the adversary infects the target and/or attempts specific actions. This decision may be employed by malware developers and operators to reduce their risk of attracting the attention of specific law enforcement agencies or prosecution/scrutiny from other entities.(Citation: Malware System Language Check)",
            insertText: 'T1614.001',
            range: range,
        }
        ,
        {
            label: 'System Network Configuration Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may look for details about the network configuration and settings, such as IP and/or MAC addresses, of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include [Arp](https://attack.mitre.org/software/S0099), [ipconfig](https://attack.mitre.org/software/S0100)/[ifconfig](https://attack.mitre.org/software/S0101), [nbtstat](https://attack.mitre.org/software/S0102), and [route](https://attack.mitre.org/software/S0103).",
            insertText: 'T1016',
            range: range,
        }
        ,
        {
            label: 'Internet Connection Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may check for Internet connectivity on compromised systems. This may be performed during automated discovery and can be accomplished in numerous ways such as using [Ping](https://attack.mitre.org/software/S0097), <code>tracert</code>, and GET requests to websites.",
            insertText: 'T1016.001',
            range: range,
        }
        ,
        {
            label: 'Wi-Fi Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may search for information about Wi-Fi networks, such as network names and passwords, on compromised systems. Adversaries may use Wi-Fi information as part of [Account Discovery](https://attack.mitre.org/techniques/T1087), [Remote System Discovery](https://attack.mitre.org/techniques/T1018), and other discovery or [Credential Access](https://attack.mitre.org/tactics/TA0006) activity to support both ongoing and future campaigns.",
            insertText: 'T1016.002',
            range: range,
        }
        ,
        {
            label: 'Permission Groups Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to discover group and permission settings. This information can help adversaries determine which user accounts and groups are available, the membership of users in particular groups, and which users and groups have elevated permissions.",
            insertText: 'T1069',
            range: range,
        }
        ,
        {
            label: 'Local Groups',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to find local system groups and permission settings. The knowledge of local system permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as the users found within the local administrators group.",
            insertText: 'T1069.001',
            range: range,
        }
        ,
        {
            label: 'Domain Groups',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to find domain-level groups and permission settings. The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as domain administrators.",
            insertText: 'T1069.002',
            range: range,
        }
        ,
        {
            label: 'Cloud Groups',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to find cloud groups and permission settings. The knowledge of cloud permission groups can help adversaries determine the particular roles of users and groups within an environment, as well as which users are associated with a particular group.",
            insertText: 'T1069.003',
            range: range,
        }
        ,
        {
            label: 'Account Discovery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to get a listing of valid accounts, usernames, or email addresses on a system or within a compromised environment. This information can help adversaries determine which accounts exist, which can aid in follow-on behavior such as brute-forcing, spear-phishing attacks, or account takeovers (e.g., [Valid Accounts](https://attack.mitre.org/techniques/T1078)).",
            insertText: 'T1087',
            range: range,
        }
        ,
        {
            label: 'Local Account',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to get a listing of local system accounts. This information can help adversaries determine which local accounts exist on a system to aid in follow-on behavior.",
            insertText: 'T1087.001',
            range: range,
        }
        ,
        {
            label: 'Email Account',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to get a listing of email addresses and accounts. Adversaries may try to dump Exchange address lists such as global address lists (GALs).(Citation: Microsoft Exchange Address Lists)",
            insertText: 'T1087.003',
            range: range,
        }
        ,
        {
            label: 'Cloud Account',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to get a listing of cloud accounts. Cloud accounts are those created and configured by an organization for use by users, remote support, services, or for administration of resources within a cloud service provider or SaaS application.",
            insertText: 'T1087.004',
            range: range,
        }
        ,
        {
            label: 'Domain Account',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to get a listing of domain accounts. This information can help adversaries determine which domain accounts exist to aid in follow-on behavior such as targeting specific accounts which possess particular privileges.",
            insertText: 'T1087.002',
            range: range,
        }
        ,
        {
            label: 'Service Execution',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may execute a binary, command, or script via a method that interacts with Windows services, such as the Service Control Manager. This can be done by either creating a new service or modifying an existing service. This technique is the execution used in conjunction with [New Service](https://attack.mitre.org/techniques/T1050) and [Modify Existing Service](https://attack.mitre.org/techniques/T1031) during service persistence or privilege escalation.",
            insertText: 'T1035',
            range: range,
        }
        ,
        {
            label: 'Windows Management Instrumentation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads. WMI is designed for programmers and is the infrastructure for management data and operations on Windows systems.(Citation: WMI 1-3) WMI is an administration feature that provides a uniform environment to access Windows system components.",
            insertText: 'T1047',
            range: range,
        }
        ,
        {
            label: 'Graphical User Interface',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "**This technique has been deprecated. Please use [Remote Services](https://attack.mitre.org/techniques/T1021) where appropriate.**",
            insertText: 'T1061',
            range: range,
        }
        ,
        {
            label: 'Scripting',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "**This technique has been deprecated. Please use [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059) where appropriate.**",
            insertText: 'T1064',
            range: range,
        }
        ,
        {
            label: 'Rundll32',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "The rundll32.exe program can be called to execute an arbitrary binary. Adversaries may take advantage of this functionality to proxy execution of code to avoid triggering security tools that may not monitor execution of the rundll32.exe process because of whitelists or false positives from Windows using rundll32.exe for normal operations.",
            insertText: 'T1085',
            range: range,
        }
        ,
        {
            label: 'PowerShell',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. (Citation: TechNet PowerShell) Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer.",
            insertText: 'T1086',
            range: range,
        }
        ,
        {
            label: 'Native API',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may interact with the native OS application programming interface (API) to execute behaviors. Native APIs provide a controlled means of calling low-level OS services within the kernel, such as those involving hardware/devices, memory, and processes.(Citation: NT API Windows)(Citation: Linux Kernel API) These native APIs are leveraged by the OS during system boot (when other system components are not yet initialized) as well as carrying out tasks and requests during routine operations.",
            insertText: 'T1106',
            range: range,
        }
        ,
        {
            label: 'Regsvr32',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. Regsvr32.exe can be used to execute arbitrary binaries. (Citation: Microsoft Regsvr32)",
            insertText: 'T1117',
            range: range,
        }
        ,
        {
            label: 'InstallUtil',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries. (Citation: MSDN InstallUtil) InstallUtil is located in the .NET directories on a Windows system: <code>C:\\Windows\\Microsoft.NET\\Framework\\v<version>\\InstallUtil.exe</code> and <code>C:\\Windows\\Microsoft.NET\\Framework64\\v<version>\\InstallUtil.exe</code>. InstallUtil.exe is digitally signed by Microsoft.",
            insertText: 'T1118',
            range: range,
        }
        ,
        {
            label: 'Regsvcs/Regasm',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies. Both are digitally signed by Microsoft. (Citation: MSDN Regsvcs) (Citation: MSDN Regasm)",
            insertText: 'T1121',
            range: range,
        }
        ,
        {
            label: 'Shared Modules',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may execute malicious payloads via loading shared modules. Shared modules are executable files that are loaded into processes to provide access to reusable code, such as specific custom functions or invoking OS API functions (i.e., [Native API](https://attack.mitre.org/techniques/T1106)).",
            insertText: 'T1129',
            range: range,
        }
        ,
        {
            label: 'Space after Filename',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries can hide a program's true filetype by changing the extension of a file. With certain file types (specifically this does not work with .app extensions), appending a space to the end of a filename will change how the file is processed by the operating system. For example, if there is a Mach-O executable file called evil.bin, when it is double clicked by a user, it will launch Terminal.app and execute. If this file is renamed to evil.txt, then when double clicked by a user, it will launch with the default text editing application (not executing the binary). However, if the file is renamed to \"evil.txt \" (note the space at the end), then when double clicked by a user, the true file type is determined by the OS and handled appropriately and the binary will be executed (Citation: Mac Backdoors are back).",
            insertText: 'T1151',
            range: range,
        }
        ,
        {
            label: 'Launchctl',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Launchctl controls the macOS launchd process which handles things like launch agents and launch daemons, but can execute other commands or programs itself. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from standard input. By loading or reloading launch agents or launch daemons, adversaries can install persistence or execute changes they made  (Citation: Sofacy Komplex Trojan). Running a command from launchctl is as simple as <code>launchctl submit -l <labelName> -- /Path/to/thing/to/execute \"arg\" \"arg\" \"arg\"</code>. Loading, unloading, or reloading launch agents or launch daemons can require elevated privileges.",
            insertText: 'T1152',
            range: range,
        }
        ,
        {
            label: 'Source',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "**This technique has been deprecated and should no longer be used.**",
            insertText: 'T1153',
            range: range,
        }
        ,
        {
            label: 'Trap',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "The <code>trap</code> command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common  keyboard interrupts like <code>ctrl+c</code> and <code>ctrl+d</code>. Adversaries can use this to register code to be executed when the shell encounters specific interrupts either to gain execution or as a persistence mechanism. Trap commands are of the following format <code>trap 'command list' signals</code> where \"command list\" will be executed when \"signals\" are received.(Citation: Trap Manual)(Citation: Cyberciti Trap Statements)",
            insertText: 'T1154',
            range: range,
        }
        ,
        {
            label: 'AppleScript',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "macOS and OS X applications send AppleEvent messages to each other for interprocess communications (IPC). These messages can be easily scripted with AppleScript for local or remote IPC. Osascript executes AppleScript and any other Open Scripting Architecture (OSA) language scripts. A list of OSA languages installed on a system can be found by using the <code>osalang</code> program.",
            insertText: 'T1155',
            range: range,
        }
        ,
        {
            label: 'Local Job Scheduling',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "On Linux and macOS systems, multiple methods are supported for creating pre-scheduled and periodic background jobs: cron, (Citation: Die.net Linux crontab Man Page) at, (Citation: Die.net Linux at Man Page) and launchd. (Citation: AppleDocs Scheduling Timed Jobs) Unlike [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053) on Windows systems, job scheduling on Linux-based systems cannot be done remotely unless used in conjunction within an established remote session, like secure shell (SSH).",
            insertText: 'T1168',
            range: range,
        }
        ,
        {
            label: 'Mshta',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Mshta.exe is a utility that executes Microsoft HTML Applications (HTA). HTA files have the file extension <code>.hta</code>. (Citation: Wikipedia HTML Application) HTAs are standalone applications that execute using the same models and technologies of Internet Explorer, but outside of the browser. (Citation: MSDN HTML Applications)",
            insertText: 'T1170',
            range: range,
        }
        ,
        {
            label: 'Dynamic Data Exchange',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Windows Dynamic Data Exchange (DDE) is a client-server protocol for one-time and/or continuous inter-process communication (IPC) between applications. Once a link is established, applications can autonomously exchange transactions consisting of strings, warm data links (notifications when a data item changes), hot data links (duplications of changes to a data item), and requests for command execution.",
            insertText: 'T1173',
            range: range,
        }
        ,
        {
            label: 'LSASS Driver',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "The Windows security subsystem is a set of components that manage and enforce the security policy for a computer or domain. The Local Security Authority (LSA) is the main component responsible for local security policy and user authentication. The LSA includes multiple dynamic link libraries (DLLs) associated with various other security functions, all of which run in the context of the LSA Subsystem Service (LSASS) lsass.exe process. (Citation: Microsoft Security Subsystem)",
            insertText: 'T1177',
            range: range,
        }
        ,
        {
            label: 'CMSTP',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "The Microsoft Connection Manager Profile Installer (CMSTP.exe) is a command-line program used to install Connection Manager service profiles. (Citation: Microsoft Connection Manager Oct 2009) CMSTP.exe accepts an installation information file (INF) as a parameter and installs a service profile leveraged for remote access connections.",
            insertText: 'T1191',
            range: range,
        }
        ,
        {
            label: 'Control Panel Items',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Windows Control Panel items are utilities that allow users to view and adjust computer settings. Control Panel items are registered executable (.exe) or Control Panel (.cpl) files, the latter are actually renamed dynamic-link library (.dll) files that export a CPlApplet function. (Citation: Microsoft Implementing CPL) (Citation: TrendMicro CPL Malware Jan 2014) Control Panel items can be executed directly from the command line, programmatically via an application programming interface (API) call, or by simply double-clicking the file. (Citation: Microsoft Implementing CPL) (Citation: TrendMicro CPL Malware Jan 2014) (Citation: TrendMicro CPL Malware Dec 2013)",
            insertText: 'T1196',
            range: range,
        }
        ,
        {
            label: 'Exploitation for Client Execution',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may exploit software vulnerabilities in client applications to execute code. Vulnerabilities can exist in software due to unsecure coding practices that can lead to unanticipated behavior. Adversaries can take advantage of certain vulnerabilities through targeted exploitation for the purpose of arbitrary code execution. Oftentimes the most valuable exploits to an offensive toolkit are those that can be used to obtain code execution on a remote system because they can be used to gain access to that system. Users will expect to see files related to the applications they commonly used to do work, so they are a useful target for exploit research and development because of their high utility.",
            insertText: 'T1203',
            range: range,
        }
        ,
        {
            label: 'Compiled HTML File',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Compiled HTML files (.chm) are commonly distributed as part of the Microsoft HTML Help system. CHM files are compressed compilations of various content such as HTML documents, images, and scripting/web related programming languages such VBA, JScript, Java, and ActiveX. (Citation: Microsoft HTML Help May 2018) CHM content is displayed using underlying components of the Internet Explorer browser (Citation: Microsoft HTML Help ActiveX) loaded by the HTML Help executable program (hh.exe). (Citation: Microsoft HTML Help Executable Program)",
            insertText: 'T1223',
            range: range,
        }
        ,
        {
            label: 'Container Administration Command',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse a container administration service to execute commands within a container. A container administration service such as the Docker daemon, the Kubernetes API server, or the kubelet may allow remote management of containers within an environment.(Citation: Docker Daemon CLI)(Citation: Kubernetes API)(Citation: Kubernetes Kubelet)",
            insertText: 'T1609',
            range: range,
        }
        ,
        {
            label: 'Deploy Container',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may deploy a container into an environment to facilitate execution or evade defenses. In some cases, adversaries may deploy a new container to execute processes associated with a particular image or deployment, such as processes that execute or download malware. In others, an adversary may deploy a new container configured without network rules, user limitations, etc. to bypass existing defenses within the environment. In Kubernetes environments, an adversary may attempt to deploy a privileged or vulnerable container into a specific node in order to [Escape to Host](https://attack.mitre.org/techniques/T1611) and access other containers running on the node. (Citation: AppSecco Kubernetes Namespace Breakout 2020)",
            insertText: 'T1610',
            range: range,
        }
        ,
        {
            label: 'Serverless Execution',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse serverless computing, integration, and automation services to execute arbitrary code in cloud environments. Many cloud providers offer a variety of serverless resources, including compute engines, application integration services, and web servers.",
            insertText: 'T1648',
            range: range,
        }
        ,
        {
            label: 'Cloud Administration Command',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse cloud management services to execute commands within virtual machines. Resources such as AWS Systems Manager, Azure RunCommand, and Runbooks allow users to remotely run scripts in virtual machines by leveraging installed virtual machine agents. (Citation: AWS Systems Manager Run Command)(Citation: Microsoft Run Command)",
            insertText: 'T1651',
            range: range,
        }
        ,
        {
            label: 'System Script Proxy Execution',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use trusted scripts, often signed with certificates, to proxy the execution of malicious files. Several Microsoft signed scripts that have been downloaded from Microsoft or are default on Windows installations can be used to proxy execution of other files.(Citation: LOLBAS Project) This behavior may be abused by adversaries to execute malicious files that could bypass application control and signature validation on systems.(Citation: GitHub Ultimate AppLocker Bypass List)",
            insertText: 'T1216',
            range: range,
        }
        ,
        {
            label: 'PubPrn',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use PubPrn to proxy execution of malicious remote files. PubPrn.vbs is a [Visual Basic](https://attack.mitre.org/techniques/T1059/005) script that publishes a printer to Active Directory Domain Services. The script may be signed by Microsoft and is commonly executed through the [Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) via <code>Cscript.exe</code>. For example, the following code publishes a printer within the specified domain: <code>cscript pubprn Printer1 LDAP://CN=Container1,DC=Domain1,DC=Com</code>.(Citation: pubprn)",
            insertText: 'T1216.001',
            range: range,
        }
        ,
        {
            label: 'SyncAppvPublishingServer',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse SyncAppvPublishingServer.vbs to proxy execution of malicious [PowerShell](https://attack.mitre.org/techniques/T1059/001) commands. SyncAppvPublishingServer.vbs is a Visual Basic script associated with how Windows virtualizes applications (Microsoft Application Virtualization, or App-V).(Citation: 1 - appv) For example, Windows may render Win32 applications to users as virtual applications, allowing users to launch and interact with them as if they were installed locally.(Citation: 2 - appv)(Citation: 3 - appv)",
            insertText: 'T1216.002',
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
            label: 'Launchctl',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse launchctl to execute commands or programs. Launchctl interfaces with launchd, the service management framework for macOS. Launchctl supports taking subcommands on the command-line, interactively, or even redirected from standard input.(Citation: Launchctl Man)",
            insertText: 'T1569.001',
            range: range,
        }
        ,
        {
            label: 'Service Execution',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse the Windows service control manager to execute malicious commands or payloads. The Windows service control manager (<code>services.exe</code>) is an interface to manage and manipulate services.(Citation: Microsoft Service Control Manager) The service control manager is accessible to users via GUI components as well as system utilities such as <code>sc.exe</code> and [Net](https://attack.mitre.org/software/S0039).",
            insertText: 'T1569.002',
            range: range,
        }
        ,
        {
            label: 'User Execution',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may rely upon specific actions by a user in order to gain execution. Users may be subjected to social engineering to get them to execute malicious code by, for example, opening a malicious document file or link. These user actions will typically be observed as follow-on behavior from forms of [Phishing](https://attack.mitre.org/techniques/T1566).",
            insertText: 'T1204',
            range: range,
        }
        ,
        {
            label: 'Malicious Link',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may rely upon a user clicking a malicious link in order to gain execution. Users may be subjected to social engineering to get them to click on a link that will lead to code execution. This user action will typically be observed as follow-on behavior from [Spearphishing Link](https://attack.mitre.org/techniques/T1566/002). Clicking on a link may also lead to other execution techniques such as exploitation of a browser or application vulnerability via [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203). Links may also lead users to download files that require execution via [Malicious File](https://attack.mitre.org/techniques/T1204/002).",
            insertText: 'T1204.001',
            range: range,
        }
        ,
        {
            label: 'Malicious File',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may rely upon a user opening a malicious file in order to gain execution. Users may be subjected to social engineering to get them to open a file that will lead to code execution. This user action will typically be observed as follow-on behavior from [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001). Adversaries may use several types of files that require a user to execute them, including .doc, .pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, and .cpl.",
            insertText: 'T1204.002',
            range: range,
        }
        ,
        {
            label: 'Malicious Image',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may rely on a user running a malicious image to facilitate execution. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be backdoored. Backdoored images may be uploaded to a public repository via [Upload Malware](https://attack.mitre.org/techniques/T1608/001), and users may then download and deploy an instance or container from the image without realizing the image is malicious, thus bypassing techniques that specifically achieve Initial Access. This can lead to the execution of malicious code, such as code that executes cryptocurrency mining, in the instance or container.(Citation: Summit Route Malicious AMIs)",
            insertText: 'T1204.003',
            range: range,
        }
        ,
        {
            label: 'Inter-Process Communication',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution. IPC is typically used by processes to share data, communicate with each other, or synchronize execution. IPC is also commonly used to avoid situations such as deadlocks, which occurs when processes are stuck in a cyclic waiting pattern.",
            insertText: 'T1559',
            range: range,
        }
        ,
        {
            label: 'Component Object Model',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use the Windows Component Object Model (COM) for local code execution. COM is an inter-process communication (IPC) component of the native Windows application programming interface (API) that enables interaction between software objects, or executable code that implements one or more interfaces.(Citation: Fireeye Hunting COM June 2019) Through COM, a client object can call methods of server objects, which are typically binary Dynamic Link Libraries (DLL) or executables (EXE).(Citation: Microsoft COM) Remote COM execution is facilitated by [Remote Services](https://attack.mitre.org/techniques/T1021) such as  [Distributed Component Object Model](https://attack.mitre.org/techniques/T1021/003) (DCOM).(Citation: Fireeye Hunting COM June 2019)",
            insertText: 'T1559.001',
            range: range,
        }
        ,
        {
            label: 'Dynamic Data Exchange',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use Windows Dynamic Data Exchange (DDE) to execute arbitrary commands. DDE is a client-server protocol for one-time and/or continuous inter-process communication (IPC) between applications. Once a link is established, applications can autonomously exchange transactions consisting of strings, warm data links (notifications when a data item changes), hot data links (duplications of changes to a data item), and requests for command execution.",
            insertText: 'T1559.002',
            range: range,
        }
        ,
        {
            label: 'XPC Services',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries can provide malicious content to an XPC service daemon for local code execution. macOS uses XPC services for basic inter-process communication between various processes, such as between the XPC Service daemon and third-party application privileged helper tools. Applications can send messages to the XPC Service daemon, which runs as root, using the low-level XPC Service <code>C API</code> or the high level <code>NSXPCConnection API</code> in order to handle tasks that require elevated privileges (such as network connections). Applications are responsible for providing the protocol definition which serves as a blueprint of the XPC services. Developers typically use XPC Services to provide applications stability and privilege separation between the application client and the daemon.(Citation: creatingXPCservices)(Citation: Designing Daemons Apple Dev)",
            insertText: 'T1559.003',
            range: range,
        }
        ,
        {
            label: 'Scheduled Task/Job',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "The sub-techniques of this are specific software implementations of scheduling capabilities",
            insertText: 'T1053',
            range: range,
        }
        ,
        {
            label: 'At (Linux) Execution',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse the [at](https://attack.mitre.org/software/S0110) utility to perform task scheduling for initial, recurring, or future execution of malicious code. The [at](https://attack.mitre.org/software/S0110) command within Linux operating systems enables administrators to schedule tasks.(Citation: Kifarunix - Task Scheduling in Linux)",
            insertText: 'T1053.001',
            range: range,
        }
        ,
        {
            label: 'At',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse the [at](https://attack.mitre.org/software/S0110) utility to perform task scheduling for initial or recurring execution of malicious code. The [at](https://attack.mitre.org/software/S0110) utility exists as an executable within Windows, Linux, and macOS for scheduling tasks at a specified time and date. Although deprecated in favor of [Scheduled Task](https://attack.mitre.org/techniques/T1053/005)'s [schtasks](https://attack.mitre.org/software/S0111) in Windows environments, using [at](https://attack.mitre.org/software/S0110) requires that the Task Scheduler service be running, and the user to be logged on as a member of the local Administrators group.",
            insertText: 'T1053.002',
            range: range,
        }
        ,
        {
            label: 'Cron',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse the <code>cron</code> utility to perform task scheduling for initial or recurring execution of malicious code.(Citation: 20 macOS Common Tools and Techniques) The <code>cron</code> utility is a time-based job scheduler for Unix-like operating systems.  The <code> crontab</code> file contains the schedule of cron entries to be run and the specified times for execution. Any <code>crontab</code> files are stored in operating system-specific file paths.",
            insertText: 'T1053.003',
            range: range,
        }
        ,
        {
            label: 'Launchd',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "This technique is deprecated due to the inaccurate usage. The report cited did not provide technical detail as to how the malware interacted directly with launchd rather than going through known services. Other system services are used to interact with launchd rather than launchd being used by itself.",
            insertText: 'T1053.004',
            range: range,
        }
        ,
        {
            label: 'Scheduled Task',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Renamed from ATT&CK to be consistent with at, launchd, cron siblings; name as is looks like parent.  Not sure why parent is not just Scheduled Task [Execution[.",
            insertText: 'T1053.005',
            range: range,
        }
        ,
        {
            label: 'Systemd Timers',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse systemd timers to perform task scheduling for initial or recurring execution of malicious code. Systemd timers are unit files with file extension <code>.timer</code> that control services. Timers can be set to run on a calendar event or after a time span relative to a starting point. They can be used as an alternative to [Cron](https://attack.mitre.org/techniques/T1053/003) in Linux environments.(Citation: archlinux Systemd Timers Aug 2020) Systemd timers may be activated remotely via the <code>systemctl</code> command line utility, which operates over [SSH](https://attack.mitre.org/techniques/T1021/004).(Citation: Systemd Remote Control)",
            insertText: 'T1053.006',
            range: range,
        }
        ,
        {
            label: 'Container Orchestration Job',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse task scheduling functionality provided by container orchestration tools such as Kubernetes to schedule deployment of containers configured to execute malicious code. Container orchestration jobs run these automated tasks at a specific date and time, similar to cron jobs on a Linux system. Deployments of this type can also be configured to maintain a quantity of containers over time, automating the process of maintaining persistence within a cluster.",
            insertText: 'T1053.007',
            range: range,
        }
        ,
        {
            label: 'Command and Scripting Interpreter',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of [Unix Shell](https://attack.mitre.org/techniques/T1059/004) while Windows installations include the [Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).",
            insertText: 'T1059',
            range: range,
        }
        ,
        {
            label: 'PowerShell',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system.(Citation: TechNet PowerShell) Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the <code>Start-Process</code> cmdlet which can be used to run an executable and the <code>Invoke-Command</code> cmdlet which runs a command locally or on a remote computer (though administrator permissions are required to use PowerShell to connect to remote systems).",
            insertText: 'T1059.001',
            range: range,
        }
        ,
        {
            label: 'AppleScript',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse AppleScript for execution. AppleScript is a macOS scripting language designed to control applications and parts of the OS via inter-application messages called AppleEvents.(Citation: Apple AppleScript) These AppleEvent messages can be sent independently or easily scripted with AppleScript. These events can locate open windows, send keystrokes, and interact with almost any open application locally or remotely.",
            insertText: 'T1059.002',
            range: range,
        }
        ,
        {
            label: 'Windows Command Shell',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse the Windows command shell for execution. The Windows command shell ([cmd](https://attack.mitre.org/software/S0106)) is the primary command prompt on Windows systems. The Windows command prompt can be used to control almost any aspect of a system, with various permission levels required for different subsets of commands. The command prompt can be invoked remotely via [Remote Services](https://attack.mitre.org/techniques/T1021) such as [SSH](https://attack.mitre.org/techniques/T1021/004).(Citation: SSH in Windows)",
            insertText: 'T1059.003',
            range: range,
        }
        ,
        {
            label: 'Unix Shell',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse Unix shell commands and scripts for execution. Unix shells are the primary command prompt on Linux and macOS systems, though many variations of the Unix shell exist (e.g. sh, bash, zsh, etc.) depending on the specific OS or distribution.(Citation: DieNet Bash)(Citation: Apple ZShell) Unix shells can control every aspect of a system, with certain commands requiring elevated privileges.",
            insertText: 'T1059.004',
            range: range,
        }
        ,
        {
            label: 'Visual Basic',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse Visual Basic (VB) for execution. VB is a programming language created by Microsoft with interoperability with many Windows technologies such as [Component Object Model](https://attack.mitre.org/techniques/T1559/001) and the [Native API](https://attack.mitre.org/techniques/T1106) through the Windows API. Although tagged as legacy with no planned future evolutions, VB is integrated and supported in the .NET Framework and cross-platform .NET Core.(Citation: VB .NET Mar 2020)(Citation: VB Microsoft)",
            insertText: 'T1059.005',
            range: range,
        }
        ,
        {
            label: 'Python',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse Python commands and scripts for execution. Python is a very popular scripting/programming language, with capabilities to perform many functions. Python can be executed interactively from the command-line (via the <code>python.exe</code> interpreter) or via scripts (.py) that can be written and distributed to different systems. Python code can also be compiled into binary executables.(Citation: Zscaler APT31 Covid-19 October 2020)",
            insertText: 'T1059.006',
            range: range,
        }
        ,
        {
            label: 'JavaScript',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse various implementations of JavaScript for execution. JavaScript (JS) is a platform-independent scripting language (compiled just-in-time at runtime) commonly associated with scripts in webpages, though JS can be executed in runtime environments outside the browser.(Citation: NodeJS)",
            insertText: 'T1059.007',
            range: range,
        }
        ,
        {
            label: 'Network Device CLI',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse scripting or built-in command line interpreters (CLI) on network devices to execute malicious command and payloads. The CLI is the primary means through which users and administrators interact with the device in order to view system information, modify device operations, or perform diagnostic and administrative functions. CLIs typically contain various permission levels required for different commands.",
            insertText: 'T1059.008',
            range: range,
        }
        ,
        {
            label: 'Cloud API',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse cloud APIs to execute malicious commands. APIs available in cloud environments provide various functionalities and are a feature-rich method for programmatic access to nearly all aspects of a tenant. These APIs may be utilized through various methods such as command line interpreters (CLIs), in-browser Cloud Shells, [PowerShell](https://attack.mitre.org/techniques/T1059/001) modules like Azure for PowerShell(Citation: Microsoft - Azure PowerShell), or software developer kits (SDKs) available for languages such as [Python](https://attack.mitre.org/techniques/T1059/006).",
            insertText: 'T1059.009',
            range: range,
        }
        ,
        {
            label: 'AutoHotKey & AutoIT',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may execute commands and perform malicious tasks using AutoIT and AutoHotKey automation scripts. AutoIT and AutoHotkey (AHK) are scripting languages that enable users to automate Windows tasks. These automation scripts can be used to perform a wide variety of actions, such as clicking on buttons, entering text, and opening and closing programs.(Citation: AutoIT)(Citation: AutoHotKey)",
            insertText: 'T1059.010',
            range: range,
        }
        ,
        {
            label: 'Lua',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse Lua commands and scripts for execution. Lua is a cross-platform scripting and programming language primarily designed for embedded use in applications. Lua can be executed on the command-line (through the stand-alone lua interpreter), via scripts (<code>.lua</code>), or from Lua-embedded programs (through the <code>struct lua_State</code>).(Citation: Lua main page)(Citation: Lua state)",
            insertText: 'T1059.011',
            range: range,
        }
        ,
        {
            label: 'System Binary Proxy Execution',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries. Binaries used in this technique are often Microsoft-signed files, indicating that they have been either downloaded from Microsoft or are already native in the operating system.(Citation: LOLBAS Project) Binaries signed with trusted digital certificates can typically execute on Windows systems protected by digital signature validation. Several Microsoft signed binaries that are default on Windows installations can be used to proxy execution of other files or commands.",
            insertText: 'T1218',
            range: range,
        }
        ,
        {
            label: 'Compiled HTML File',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code. CHM files are commonly distributed as part of the Microsoft HTML Help system. CHM files are compressed compilations of various content such as HTML documents, images, and scripting/web related programming languages such VBA, JScript, Java, and ActiveX. (Citation: Microsoft HTML Help May 2018) CHM content is displayed using underlying components of the Internet Explorer browser (Citation: Microsoft HTML Help ActiveX) loaded by the HTML Help executable program (hh.exe). (Citation: Microsoft HTML Help Executable Program)",
            insertText: 'T1218.001',
            range: range,
        }
        ,
        {
            label: 'Control Panel',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse control.exe to proxy execution of malicious payloads. The Windows Control Panel process binary (control.exe) handles execution of Control Panel items, which are utilities that allow users to view and adjust computer settings.",
            insertText: 'T1218.002',
            range: range,
        }
        ,
        {
            label: 'CMSTP',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse CMSTP to proxy execution of malicious code. The Microsoft Connection Manager Profile Installer (CMSTP.exe) is a command-line program used to install Connection Manager service profiles. (Citation: Microsoft Connection Manager Oct 2009) CMSTP.exe accepts an installation information file (INF) as a parameter and installs a service profile leveraged for remote access connections.",
            insertText: 'T1218.003',
            range: range,
        }
        ,
        {
            label: 'InstallUtil',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility. InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries. (Citation: MSDN InstallUtil) The InstallUtil binary may also be digitally signed by Microsoft and located in the .NET directories on a Windows system: <code>C:\\Windows\\Microsoft.NET\\Framework\\v<version>\\InstallUtil.exe</code> and <code>C:\\Windows\\Microsoft.NET\\Framework64\\v<version>\\InstallUtil.exe</code>.",
            insertText: 'T1218.004',
            range: range,
        }
        ,
        {
            label: 'Mshta',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility. There are several examples of different types of threats leveraging mshta.exe during initial compromise and for execution of code (Citation: Cylance Dust Storm) (Citation: Red Canary HTA Abuse Part Deux) (Citation: FireEye Attacks Leveraging HTA) (Citation: Airbus Security Kovter Analysis) (Citation: FireEye FIN7 April 2017)",
            insertText: 'T1218.005',
            range: range,
        }
        ,
        {
            label: 'Msiexec',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse msiexec.exe to proxy execution of malicious payloads. Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installation packages (.msi).(Citation: Microsoft msiexec) The Msiexec.exe binary may also be digitally signed by Microsoft.",
            insertText: 'T1218.007',
            range: range,
        }
        ,
        {
            label: 'Odbcconf',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse odbcconf.exe to proxy execution of malicious payloads. Odbcconf.exe is a Windows utility that allows you to configure Open Database Connectivity (ODBC) drivers and data source names.(Citation: Microsoft odbcconf.exe) The Odbcconf.exe binary may be digitally signed by Microsoft.",
            insertText: 'T1218.008',
            range: range,
        }
        ,
        {
            label: 'Regsvcs/Regasm',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. Regsvcs and Regasm are Windows command-line utilities that are used to register .NET [Component Object Model](https://attack.mitre.org/techniques/T1559/001) (COM) assemblies. Both are binaries that may be digitally signed by Microsoft. (Citation: MSDN Regsvcs) (Citation: MSDN Regasm)",
            insertText: 'T1218.009',
            range: range,
        }
        ,
        {
            label: 'Regsvr32',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse Regsvr32.exe to proxy execution of malicious code. Regsvr32.exe is a command-line program used to register and unregister object linking and embedding controls, including dynamic link libraries (DLLs), on Windows systems. The Regsvr32.exe binary may also be signed by Microsoft. (Citation: Microsoft Regsvr32)",
            insertText: 'T1218.010',
            range: range,
        }
        ,
        {
            label: 'Rundll32',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse rundll32.exe to proxy execution of malicious code. Using rundll32.exe, vice executing directly (i.e. [Shared Modules](https://attack.mitre.org/techniques/T1129)), may avoid triggering security tools that may not monitor execution of the rundll32.exe process because of allowlists or false positives from normal operations. Rundll32.exe is commonly associated with executing DLL payloads (ex: <code>rundll32.exe {DLLname, DLLfunction}</code>).",
            insertText: 'T1218.011',
            range: range,
        }
        ,
        {
            label: 'Verclsid',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse verclsid.exe to proxy execution of malicious code. Verclsid.exe is known as the Extension CLSID Verification Host and is responsible for verifying each shell extension before they are used by Windows Explorer or the Windows Shell.(Citation: WinOSBite verclsid.exe)",
            insertText: 'T1218.012',
            range: range,
        }
        ,
        {
            label: 'Mavinject',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse mavinject.exe to proxy execution of malicious code. Mavinject.exe is the Microsoft Application Virtualization Injector, a Windows utility that can inject code into external processes as part of Microsoft Application Virtualization (App-V).(Citation: LOLBAS Mavinject)",
            insertText: 'T1218.013',
            range: range,
        }
        ,
        {
            label: 'MMC',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse mmc.exe to proxy execution of malicious .msc files. Microsoft Management Console (MMC) is a binary that may be signed by Microsoft and is used in several ways in either its GUI or in a command prompt.(Citation: win_mmc)(Citation: what_is_mmc) MMC can be used to create, open, and save custom consoles that contain administrative tools created by Microsoft, called snap-ins. These snap-ins may be used to manage Windows systems locally or remotely. MMC can also be used to open Microsoft created .msc files to manage system configuration.(Citation: win_msc_files_overview)",
            insertText: 'T1218.014',
            range: range,
        }
        ,
        {
            label: 'Electron Applications',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse components of the Electron framework to execute malicious code. The Electron framework hosts many common applications such as Signal, Slack, and Microsoft Teams.(Citation: Electron 2) Originally developed by GitHub, Electron is a cross-platform desktop application development framework that employs web technologies like JavaScript, HTML, and CSS.(Citation: Electron 3) The Chromium engine is used to display web content and Node.js runs the backend code.(Citation: Electron 1)",
            insertText: 'T1218.015',
            range: range,
        }
        ,
        {
            label: 'Port Monitors',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "A port monitor can be set through the  (Citation: AddMonitor) API call to set a DLL to be loaded at startup. (Citation: AddMonitor) This DLL can be located in <code>C:\\Windows\\System32</code> and will be loaded by the print spooler service, spoolsv.exe, on boot. The spoolsv.exe process also runs under SYSTEM level permissions. (Citation: Bloxham) Alternatively, an arbitrary DLL can be loaded if permissions allow writing a fully-qualified pathname for that DLL to <code>HKLM\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors</code>.",
            insertText: 'T1013',
            range: range,
        }
        ,
        {
            label: 'Accessibility Features',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Windows contains accessibility features that may be launched with a key combination before a user has logged in (for example, when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system.",
            insertText: 'T1015',
            range: range,
        }
        ,
        {
            label: 'Path Interception',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "**This technique has been deprecated. Please use [Path Interception by PATH Environment Variable](https://attack.mitre.org/techniques/T1574/007), [Path Interception by Search Order Hijacking](https://attack.mitre.org/techniques/T1574/008), and/or [Path Interception by Unquoted Path](https://attack.mitre.org/techniques/T1574/009).**",
            insertText: 'T1034',
            range: range,
        }
        ,
        {
            label: 'DLL Search Order Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Windows systems use a common method to look for required DLLs to load into a program. (Citation: Microsoft DLL Search) Adversaries may take advantage of the Windows DLL search order and programs that ambiguously specify DLLs to gain privilege escalation and persistence.",
            insertText: 'T1038',
            range: range,
        }
        ,
        {
            label: 'File System Permissions Weakness',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.",
            insertText: 'T1044',
            range: range,
        }
        ,
        {
            label: 'New Service',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "When operating systems boot up, they can start programs or applications called services that perform background system functions. (Citation: TechNet Services) A service's configuration information, including the file path to the service's executable, is stored in the Windows Registry.",
            insertText: 'T1050',
            range: range,
        }
        ,
        {
            label: 'Service Registry Permissions Weakness',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Windows stores local service configuration information in the Registry under <code>HKLM\\SYSTEM\\CurrentControlSet\\Services</code>. The information stored under a service's Registry keys can be manipulated to modify a service's execution parameters through tools such as the service controller, sc.exe, [PowerShell](https://attack.mitre.org/techniques/T1086), or [Reg](https://attack.mitre.org/software/S0075). Access to Registry keys is controlled through Access Control Lists and permissions. (Citation: MSDN Registry Key Security)",
            insertText: 'T1058',
            range: range,
        }
        ,
        {
            label: 'Exploitation for Privilege Escalation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges. Exploitation of a software vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code. Security constructs such as permission levels will often hinder access to information and use of certain techniques, so adversaries will likely need to perform privilege escalation to include use of software exploitation to circumvent those restrictions.",
            insertText: 'T1068',
            range: range,
        }
        ,
        {
            label: 'Bypass User Account Control',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Windows User Account Control (UAC) allows a program to elevate its privileges to perform a task under administrator-level permissions by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action. (Citation: TechNet How UAC Works)",
            insertText: 'T1088',
            range: range,
        }
        ,
        {
            label: 'Web Shell',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to use the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server. In addition to a server-side script, a Web shell may have a client interface program that is used to talk to the Web server (see, for example, China Chopper Web shell client). (Citation: Lee 2013)",
            insertText: 'T1100',
            range: range,
        }
        ,
        {
            label: 'AppInit DLLs',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Dynamic-link libraries (DLLs) that are specified in the AppInit_DLLs value in the Registry keys <code>HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows</code> or <code>HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows</code> are loaded by user32.dll into every process that loads user32.dll. In practice this is nearly every program, since user32.dll is a very common library. (Citation: Elastic Process Injection July 2017) Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), these values can be abused to obtain persistence and privilege escalation by causing a malicious DLL to be loaded and run in the context of separate processes on the computer. (Citation: AppInit Registry)",
            insertText: 'T1103',
            range: range,
        }
        ,
        {
            label: 'Application Shimming',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time. For example, the application shimming feature allows developers to apply fixes to applications (without rewriting code) that were created for Windows XP so that it will work with Windows 10. (Citation: Elastic Process Injection July 2017) Within the framework, shims are created to act as a buffer between the program (or more specifically, the Import Address Table) and the Windows OS. When a program is executed, the shim cache is referenced to determine if the program requires the use of the shim database (.sdb). If so, the shim database uses [Hooking](https://attack.mitre.org/techniques/T1179) to redirect the code as necessary in order to communicate with the OS.",
            insertText: 'T1138',
            range: range,
        }
        ,
        {
            label: 'Plist Modification',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Property list (plist) files contain all of the information that macOS and OS X uses to configure applications and services. These files are UTF-8 encoded and formatted like XML documents via a series of keys surrounded by < >. They detail when programs should execute, file paths to the executables, program arguments, required OS permissions, and many others. plists are located in certain locations depending on their purpose such as <code>/Library/Preferences</code> (which execute with elevated privileges) and <code>~/Library/Preferences</code> (which execute with a user's privileges).",
            insertText: 'T1150',
            range: range,
        }
        ,
        {
            label: 'Dylib Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "macOS and OS X use a common method to look for required dynamic libraries (dylib) to load into a program based on search paths. Adversaries can take advantage of ambiguous paths to plant dylibs to gain privilege escalation or persistence.",
            insertText: 'T1157',
            range: range,
        }
        ,
        {
            label: 'Launch Daemon',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Per Apple\u2019s developer documentation, when macOS and OS X boot up, launchd is run to finish system initialization. This process loads the parameters for each launch-on-demand system-level daemon from the property list (plist) files found in <code>/System/Library/LaunchDaemons</code> and <code>/Library/LaunchDaemons</code> (Citation: AppleDocs Launch Agent Daemons). These LaunchDaemons have property list files which point to the executables that will be launched (Citation: Methods of Mac Malware Persistence).",
            insertText: 'T1160',
            range: range,
        }
        ,
        {
            label: 'Startup Items',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Per Apple\u2019s documentation, startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items (Citation: Startup Items). This is technically a deprecated version (superseded by Launch Daemons), and thus the appropriate folder, <code>/Library/StartupItems</code> isn\u2019t guaranteed to exist on the system by default, but does appear to exist by default on macOS Sierra. A startup item is a directory whose executable and configuration property list (plist), <code>StartupParameters.plist</code>, reside in the top-level directory.",
            insertText: 'T1165',
            range: range,
        }
        ,
        {
            label: 'Setuid and Setgid',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "When the setuid or setgid bits are set on Linux or macOS for an application, this means that the application will run with the privileges of the owning user or group respectively  (Citation: setuid man page). Normally an application is run in the current user\u2019s context, regardless of which user or group owns the application. There are instances where programs need to be executed in an elevated context to function properly, but the user running them doesn\u2019t need the elevated privileges. Instead of creating an entry in the sudoers file, which must be done by root, any user can specify the setuid or setgid flag to be set for their own applications. These bits are indicated with an \"s\" instead of an \"x\" when viewing a file's attributes via <code>ls -l</code>. The <code>chmod</code> program can set these bits with via bitmasking, <code>chmod 4777 [file]</code> or via shorthand naming, <code>chmod u+s [file]</code>.",
            insertText: 'T1166',
            range: range,
        }
        ,
        {
            label: 'Sudo',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "The sudoers file, <code>/etc/sudoers</code>, describes which users can run which commands and from which terminals. This also describes which commands users can run as other users or groups. This provides the idea of least privilege such that users are running in their lowest possible permissions for most of the time and only elevate to other users or permissions as needed, typically by prompting for a password. However, the sudoers file can also specify when to not prompt users for passwords with a line like <code>user1 ALL=(ALL) NOPASSWD: ALL</code> (Citation: OSX.Dok Malware).",
            insertText: 'T1169',
            range: range,
        }
        ,
        {
            label: 'SID-History Injection',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "The Windows security identifier (SID) is a unique value that identifies a user or group account. SIDs are used by Windows security in both security descriptors and access tokens. (Citation: Microsoft SID) An account can hold additional SIDs in the SID-History Active Directory attribute (Citation: Microsoft SID-History Attribute), allowing inter-operable account migration between domains (e.g., all values in SID-History are included in access tokens).",
            insertText: 'T1178',
            range: range,
        }
        ,
        {
            label: 'Extra Window Memory Injection',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Before creating a window, graphical Windows-based processes must prescribe to or register a windows class, which stipulate appearance and behavior (via windows procedures, which are functions that handle input/output of data). (Citation: Microsoft Window Classes) Registration of new windows classes can include a request for up to 40 bytes of extra window memory (EWM) to be appended to the allocated memory of each instance of that class. This EWM is intended to store data specific to that window and has specific application programming interface (API) functions to set and get its value. (Citation: Microsoft GetWindowLong function) (Citation: Microsoft SetWindowLong function)",
            insertText: 'T1181',
            range: range,
        }
        ,
        {
            label: 'AppCert DLLs',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Dynamic-link libraries (DLLs) that are specified in the AppCertDLLs Registry key under <code>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager</code> are loaded into every process that calls the ubiquitously used application programming interface (API) functions CreateProcess, CreateProcessAsUser, CreateProcessWithLoginW, CreateProcessWithTokenW, or WinExec. (Citation: Elastic Process Injection July 2017)",
            insertText: 'T1182',
            range: range,
        }
        ,
        {
            label: 'Image File Execution Options Injection',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Image File Execution Options (IFEO) enable a developer to attach a debugger to an application. When a process is created, a debugger present in an application\u2019s IFEO will be prepended to the application\u2019s name, effectively launching the new process under the debugger (e.g., \u201cC:\\dbg\\ntsd.exe -g  notepad.exe\u201d). (Citation: Microsoft Dev Blog IFEO Mar 2010)",
            insertText: 'T1183',
            range: range,
        }
        ,
        {
            label: 'Sudo Caching',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "The <code>sudo</code> command \"allows a system administrator to delegate authority to give certain users (or groups of users) the ability to run some (or all) commands as root or another user while providing an audit trail of the commands and their arguments.\" (Citation: sudo man page 2018) Since sudo was made for the system administrator, it has some useful configuration features such as a <code>timestamp_timeout</code> that is the amount of time in minutes between instances of <code>sudo</code> before it will re-prompt for a password. This is because <code>sudo</code> has the ability to cache credentials for a period of time. Sudo creates (or touches) a file at <code>/var/db/sudo</code> with a timestamp of when sudo was last run to determine this timeout. Additionally, there is a <code>tty_tickets</code> variable that treats each new tty (terminal session) in isolation. This means that, for example, the sudo timeout of one tty will not affect another tty (you will have to type the password again).",
            insertText: 'T1206',
            range: range,
        }
        ,
        {
            label: 'Parent PID Spoofing',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges. New processes are typically spawned directly from their parent, or calling, process unless explicitly specified. One way of explicitly assigning the PPID of a new process is via the <code>CreateProcess</code> API call, which supports a parameter that defines the PPID to use.(Citation: DidierStevens SelectMyParent Nov 2009) This functionality is used by Windows features such as User Account Control (UAC) to correctly set the PPID after a requested elevated process is spawned by SYSTEM (typically via <code>svchost.exe</code> or <code>consent.exe</code>) rather than the current user context.(Citation: Microsoft UAC Nov 2018)",
            insertText: 'T1502',
            range: range,
        }
        ,
        {
            label: 'PowerShell Profile',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gain persistence and elevate privileges in certain situations by abusing [PowerShell](https://attack.mitre.org/techniques/T1086) profiles. A PowerShell profile  (<code>profile.ps1</code>) is a script that runs when PowerShell starts and can be used as a logon script to customize user environments. PowerShell supports several profiles depending on the user or host program. For example, there can be different profiles for PowerShell host programs such as the PowerShell console, PowerShell ISE or Visual Studio Code. An administrator can also configure a profile that applies to all users and host programs on the local computer. (Citation: Microsoft About Profiles)",
            insertText: 'T1504',
            range: range,
        }
        ,
        {
            label: 'Elevated Execution with Prompt',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may leverage the AuthorizationExecuteWithPrivileges API to escalate privileges by prompting the user for credentials.(Citation: AppleDocs AuthorizationExecuteWithPrivileges) The purpose of this API is to give application developers an easy way to perform operations with root privileges, such as for application installation or updating.  This API does not validate that the program requesting root privileges comes from a reputable source or has been maliciously modified. Although this API is deprecated, it still fully functions in the latest releases of macOS. When calling this API, the user will be prompted to enter their credentials but no checks on the origin or integrity of the program are made. The program calling the API may also load world writable files which can be modified to perform malicious behavior with elevated privileges.",
            insertText: 'T1514',
            range: range,
        }
        ,
        {
            label: 'Emond',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use Event Monitor Daemon (emond) to establish persistence by scheduling malicious commands to run on predictable event triggers. Emond is a [Launch Daemon](https://attack.mitre.org/techniques/T1160) that accepts events from various services, runs them through a simple rules engine, and takes action. The emond binary at <code>/sbin/emond</code> will load any rules from the <code>/etc/emond.d/rules/</code> directory and take action once an explicitly defined event takes place. The rule files are in the plist format and define the name, event type, and action to take. Some examples of event types include system startup and user authentication. Examples of actions are to run a system command or send an email. The emond service will not launch if there is no file present in the QueueDirectories path <code>/private/var/db/emondClients</code>, specified in the [Launch Daemon](https://attack.mitre.org/techniques/T1160) configuration file at<code>/System/Library/LaunchDaemons/com.apple.emond.plist</code>.(Citation: xorrior emond Jan 2018)(Citation: magnusviri emond Apr 2016)(Citation: sentinelone macos persist Jun 2019)",
            insertText: 'T1519',
            range: range,
        }
        ,
        {
            label: 'Escape to Host',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may break out of a container to gain access to the underlying host. This can allow an adversary access to other containerized resources from the host level or to the host itself. In principle, containerized resources should provide a clear separation of application functionality and be isolated from the host environment.(Citation: Docker Overview)",
            insertText: 'T1611',
            range: range,
        }
        ,
        {
            label: 'Domain or Tenant Policy Modification',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify the configuration settings of a domain or identity tenant to evade defenses and/or escalate privileges in centrally managed environments. Such services provide a centralized means of managing identity resources such as devices and accounts, and often include configuration settings that may apply between domains or tenants such as trust relationships, identity syncing, or identity federation.",
            insertText: 'T1484',
            range: range,
        }
        ,
        {
            label: 'Group Policy Modification',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify Group Policy Objects (GPOs) to subvert the intended discretionary access controls for a domain, usually with the intention of escalating privileges on the domain. Group policy allows for centralized management of user and computer settings in Active Directory (AD). GPOs are containers for group policy settings made up of files stored within a predictable network path `\\<DOMAIN>\\SYSVOL\\<DOMAIN>\\Policies\\`.(Citation: TechNet Group Policy Basics)(Citation: ADSecurity GPO Persistence 2016)",
            insertText: 'T1484.001',
            range: range,
        }
        ,
        {
            label: 'Trust Modification',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may add new domain trusts, modify the properties of existing domain trusts, or otherwise change the configuration of trust relationships between domains and tenants to evade defenses and/or elevate privileges.Trust details, such as whether or not user identities are federated, allow authentication and authorization properties to apply between domains or tenants for the purpose of accessing shared resources.(Citation: Microsoft - Azure AD Federation) These trust objects may include accounts, credentials, and other authentication material applied to servers, tokens, and domains.",
            insertText: 'T1484.002',
            range: range,
        }
        ,
        {
            label: 'Boot or Logon Initialization Scripts',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use scripts automatically executed at boot or logon initialization to establish persistence.(Citation: Mandiant APT29 Eye Spy Email Nov 22)(Citation: Anomali Rocke March 2019) Initialization scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. These scripts can vary based on operating system and whether applied locally or remotely.",
            insertText: 'T1037',
            range: range,
        }
        ,
        {
            label: 'Logon Script (Windows)',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence. Windows allows logon scripts to be run whenever a specific user or group of users log into a system.(Citation: TechNet Logon Scripts) This is done via adding a path to a script to the <code>HKCU\\Environment\\UserInitMprLogonScript</code> Registry key.(Citation: Hexacorn Logon Scripts)",
            insertText: 'T1037.001',
            range: range,
        }
        ,
        {
            label: 'Login Hook',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use a Login Hook to establish persistence executed upon user logon. A login hook is a plist file that points to a specific script to execute with root privileges upon user logon. The plist file is located in the <code>/Library/Preferences/com.apple.loginwindow.plist</code> file and can be modified using the <code>defaults</code> command-line utility. This behavior is the same for logout hooks where a script can be executed upon user logout. All hooks require administrator permissions to modify or create hooks.(Citation: Login Scripts Apple Dev)(Citation: LoginWindowScripts Apple Dev)",
            insertText: 'T1037.002',
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
            label: 'RC Scripts',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may establish persistence by modifying RC scripts which are executed during a Unix-like system\u2019s startup. These files allow system administrators to map and start custom services at startup for different run levels. RC scripts require root privileges to modify.",
            insertText: 'T1037.004',
            range: range,
        }
        ,
        {
            label: 'Startup Items',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use startup items automatically executed at boot initialization to establish persistence. Startup items execute during the final phase of the boot process and contain shell scripts or other executable files along with configuration information used by the system to determine the execution order for all startup items.(Citation: Startup Items)",
            insertText: 'T1037.005',
            range: range,
        }
        ,
        {
            label: 'Access Token Manipulation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify access tokens to operate under a different user or system security context to perform actions and bypass access controls. Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it is the child of a different process or belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token.",
            insertText: 'T1134',
            range: range,
        }
        ,
        {
            label: 'Create Process with Token',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create a new process with an existing token to escalate privileges and bypass access controls. Processes can be created with the token and resulting security context of another user using features such as <code>CreateProcessWithTokenW</code> and <code>runas</code>.(Citation: Microsoft RunAs)",
            insertText: 'T1134.002',
            range: range,
        }
        ,
        {
            label: 'Make and Impersonate Token',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may make new tokens and impersonate users to escalate privileges and bypass access controls. For example, if an adversary has a username and password but the user is not logged onto the system the adversary can then create a logon session for the user using the `LogonUser` function.(Citation: LogonUserW function) The function will return a copy of the new session's access token and the adversary can use `SetThreadToken` to assign the token to a thread.",
            insertText: 'T1134.003',
            range: range,
        }
        ,
        {
            label: 'Parent PID Spoofing',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may spoof the parent process identifier (PPID) of a new process to evade process-monitoring defenses or to elevate privileges. New processes are typically spawned directly from their parent, or calling, process unless explicitly specified. One way of explicitly assigning the PPID of a new process is via the <code>CreateProcess</code> API call, which supports a parameter that defines the PPID to use.(Citation: DidierStevens SelectMyParent Nov 2009) This functionality is used by Windows features such as User Account Control (UAC) to correctly set the PPID after a requested elevated process is spawned by SYSTEM (typically via <code>svchost.exe</code> or <code>consent.exe</code>) rather than the current user context.(Citation: Microsoft UAC Nov 2018)",
            insertText: 'T1134.004',
            range: range,
        }
        ,
        {
            label: 'SID-History Injection',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use SID-History Injection to escalate privileges and bypass access controls. The Windows security identifier (SID) is a unique value that identifies a user or group account. SIDs are used by Windows security in both security descriptors and access tokens. (Citation: Microsoft SID) An account can hold additional SIDs in the SID-History Active Directory attribute (Citation: Microsoft SID-History Attribute), allowing inter-operable account migration between domains (e.g., all values in SID-History are included in access tokens).",
            insertText: 'T1134.005',
            range: range,
        }
        ,
        {
            label: 'Token Impersonation/Theft',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may duplicate then impersonate another user's existing token to escalate privileges and bypass access controls. For example, an adversary can duplicate an existing token using `DuplicateToken` or `DuplicateTokenEx`.(Citation: DuplicateToken function) The token can then be used with `ImpersonateLoggedOnUser` to allow the calling thread to impersonate a logged on user's security context, or with `SetThreadToken` to assign the impersonated token to a thread.",
            insertText: 'T1134.001',
            range: range,
        }
        ,
        {
            label: 'Create or Modify System Process',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create or modify system-level processes to repeatedly execute malicious payloads as part of persistence. When operating systems boot up, they can start processes that perform background system functions. On Windows and Linux, these system processes are referred to as services.(Citation: TechNet Services) On macOS, launchd processes known as [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) and [Launch Agent](https://attack.mitre.org/techniques/T1543/001) are run to finish system initialization and load user specific parameters.(Citation: AppleDocs Launch Agent Daemons)",
            insertText: 'T1543',
            range: range,
        }
        ,
        {
            label: 'Launch Agent',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create or modify launch agents to repeatedly execute malicious payloads as part of persistence. When a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the property list (.plist) file found in <code>/System/Library/LaunchAgents</code>, <code>/Library/LaunchAgents</code>, and <code>~/Library/LaunchAgents</code>.(Citation: AppleDocs Launch Agent Daemons)(Citation: OSX Keydnap malware) (Citation: Antiquated Mac Malware) Property list files use the <code>Label</code>, <code>ProgramArguments </code>, and <code>RunAtLoad</code> keys to identify the Launch Agent's name, executable location, and execution time.(Citation: OSX.Dok Malware) Launch Agents are often installed to perform updates to programs, launch user specified programs at login, or to conduct other developer tasks.",
            insertText: 'T1543.001',
            range: range,
        }
        ,
        {
            label: 'Systemd Service',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create or modify systemd services to repeatedly execute malicious payloads as part of persistence. Systemd is a system and service manager commonly used for managing background daemon processes (also known as services) and other system resources.(Citation: Linux man-pages: systemd January 2014) Systemd is the default initialization (init) system on many Linux distributions replacing legacy init systems, including SysVinit and Upstart, while remaining backwards compatible.",
            insertText: 'T1543.002',
            range: range,
        }
        ,
        {
            label: 'Windows Service',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions.(Citation: TechNet Services) Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Windows Registry.",
            insertText: 'T1543.003',
            range: range,
        }
        ,
        {
            label: 'Launch Daemon',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create or modify Launch Daemons to execute malicious payloads as part of persistence. Launch Daemons are plist files used to interact with Launchd, the service management framework used by macOS. Launch Daemons require elevated privileges to install, are executed for every user on a system prior to login, and run in the background without the need for user interaction. During the macOS initialization startup, the launchd process loads the parameters for launch-on-demand system-level daemons from plist files found in <code>/System/Library/LaunchDaemons/</code> and <code>/Library/LaunchDaemons/</code>. Required Launch Daemons parameters include a <code>Label</code> to identify the task, <code>Program</code> to provide a path to the executable, and <code>RunAtLoad</code> to specify when the task is run. Launch Daemons are often used to provide access to shared resources, updates to software, or conduct automation tasks.(Citation: AppleDocs Launch Agent Daemons)(Citation: Methods of Mac Malware Persistence)(Citation: launchd Keywords for plists)",
            insertText: 'T1543.004',
            range: range,
        }
        ,
        {
            label: 'Container Service',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create or modify container or container cluster management tools that run as daemons, agents, or services on individual hosts. These include software for creating and managing individual containers, such as Docker and Podman, as well as container cluster node-level agents such as kubelet. By modifying these services, an adversary may be able to achieve persistence or escalate their privileges on a host.",
            insertText: 'T1543.005',
            range: range,
        }
        ,
        {
            label: 'Abuse Elevation Control Mechanism',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions. Most modern systems contain native elevation control mechanisms that are intended to limit privileges that a user can perform on a machine. Authorization has to be granted to specific users in order to perform tasks that can be considered of higher risk.(Citation: TechNet How UAC Works)(Citation: sudo man page 2018) An adversary can perform several methods to take advantage of built-in control mechanisms in order to escalate privileges on a system.(Citation: OSX Keydnap malware)(Citation: Fortinet Fareit)",
            insertText: 'T1548',
            range: range,
        }
        ,
        {
            label: 'Setuid and Setgid',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may abuse configurations where an application has the setuid or setgid bits set in order to get code running in a different (and possibly more privileged) user\u2019s context. On Linux or macOS, when the setuid or setgid bits are set for an application binary, the application will run with the privileges of the owning user or group respectively.(Citation: setuid man page) Normally an application is run in the current user\u2019s context, regardless of which user or group owns the application. However, there are instances where programs need to be executed in an elevated context to function properly, but the user running them may not have the specific required privileges.",
            insertText: 'T1548.001',
            range: range,
        }
        ,
        {
            label: 'Bypass User Account Control',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may bypass UAC mechanisms to elevate process privileges on system. Windows User Account Control (UAC) allows a program to elevate its privileges (tracked as integrity levels ranging from low to high) to perform a task under administrator-level permissions, possibly by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action.(Citation: TechNet How UAC Works)",
            insertText: 'T1548.002',
            range: range,
        }
        ,
        {
            label: 'Sudo and Sudo Caching',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges. Adversaries may do this to execute commands as other users or spawn processes with higher privileges.",
            insertText: 'T1548.003',
            range: range,
        }
        ,
        {
            label: 'Elevated Execution with Prompt',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may leverage the <code>AuthorizationExecuteWithPrivileges</code> API to escalate privileges by prompting the user for credentials.(Citation: AppleDocs AuthorizationExecuteWithPrivileges) The purpose of this API is to give application developers an easy way to perform operations with root privileges, such as for application installation or updating. This API does not validate that the program requesting root privileges comes from a reputable source or has been maliciously modified.",
            insertText: 'T1548.004',
            range: range,
        }
        ,
        {
            label: 'Temporary Elevated Cloud Access',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse permission configurations that allow them to gain temporarily elevated access to cloud resources. Many cloud environments allow administrators to grant user or service accounts permission to request just-in-time access to roles, impersonate other accounts, pass roles onto resources and services, or otherwise gain short-term access to a set of privileges that may be distinct from their own.",
            insertText: 'T1548.005',
            range: range,
        }
        ,
        {
            label: 'TCC Manipulation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries can manipulate or abuse the Transparency, Consent, & Control (TCC) service or database to execute malicious applications with elevated permissions. TCC is a Privacy & Security macOS control mechanism used to determine if the running process has permission to access the data or services protected by TCC, such as screen sharing, camera, microphone, or Full Disk Access (FDA).",
            insertText: 'T1548.006',
            range: range,
        }
        ,
        {
            label: 'Process Injection',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process.",
            insertText: 'T1055',
            range: range,
        }
        ,
        {
            label: 'Dynamic-link Library Injection',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses as well as possibly elevate privileges. DLL injection is a method of executing arbitrary code in the address space of a separate live process.",
            insertText: 'T1055.001',
            range: range,
        }
        ,
        {
            label: 'Portable Executable Injection',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may inject portable executables (PE) into processes in order to evade process-based defenses as well as possibly elevate privileges. PE injection is a method of executing arbitrary code in the address space of a separate live process.",
            insertText: 'T1055.002',
            range: range,
        }
        ,
        {
            label: 'Thread Execution Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. Thread Execution Hijacking is a method of executing arbitrary code in the address space of a separate live process.",
            insertText: 'T1055.003',
            range: range,
        }
        ,
        {
            label: 'Asynchronous Procedure Call',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may inject malicious code into processes via the asynchronous procedure call (APC) queue in order to evade process-based defenses as well as possibly elevate privileges. APC injection is a method of executing arbitrary code in the address space of a separate live process.",
            insertText: 'T1055.004',
            range: range,
        }
        ,
        {
            label: 'Thread Local Storage',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may inject malicious code into processes via thread local storage (TLS) callbacks in order to evade process-based defenses as well as possibly elevate privileges. TLS callback injection is a method of executing arbitrary code in the address space of a separate live process.",
            insertText: 'T1055.005',
            range: range,
        }
        ,
        {
            label: 'Ptrace System Calls',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may inject malicious code into processes via ptrace (process trace) system calls in order to evade process-based defenses as well as possibly elevate privileges. Ptrace system call injection is a method of executing arbitrary code in the address space of a separate live process.",
            insertText: 'T1055.008',
            range: range,
        }
        ,
        {
            label: 'Proc Memory',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may inject malicious code into processes via the /proc filesystem in order to evade process-based defenses as well as possibly elevate privileges. Proc memory injection is a method of executing arbitrary code in the address space of a separate live process.",
            insertText: 'T1055.009',
            range: range,
        }
        ,
        {
            label: 'Extra Window Memory Injection',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may inject malicious code into process via Extra Window Memory (EWM) in order to evade process-based defenses as well as possibly elevate privileges. EWM injection is a method of executing arbitrary code in the address space of a separate live process.",
            insertText: 'T1055.011',
            range: range,
        }
        ,
        {
            label: 'Process Hollowing',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. Process hollowing is a method of executing arbitrary code in the address space of a separate live process.",
            insertText: 'T1055.012',
            range: range,
        }
        ,
        {
            label: 'Process Doppelgänging',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may inject malicious code into process via process doppelg\u00e4nging in order to evade process-based defenses as well as possibly elevate privileges. Process doppelg\u00e4nging is a method of executing arbitrary code in the address space of a separate live process.",
            insertText: 'T1055.013',
            range: range,
        }
        ,
        {
            label: 'VDSO Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may inject malicious code into processes via VDSO hijacking in order to evade process-based defenses as well as possibly elevate privileges. Virtual dynamic shared object (vdso) hijacking is a method of executing arbitrary code in the address space of a separate live process.",
            insertText: 'T1055.014',
            range: range,
        }
        ,
        {
            label: 'ListPlanting',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse list-view controls to inject malicious code into hijacked processes in order to evade process-based defenses as well as possibly elevate privileges. ListPlanting is a method of executing arbitrary code in the address space of a separate live process. Code executed via ListPlanting may also evade detection from security products since the execution is masked under a legitimate process.",
            insertText: 'T1055.015',
            range: range,
        }
        ,
        {
            label: 'Hijack Execution Flow',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may execute their own malicious payloads by hijacking the way operating systems run programs. Hijacking execution flow can be for the purposes of persistence, since this hijacked execution may reoccur over time. Adversaries may also use these mechanisms to elevate privileges or evade defenses, such as application control or other restrictions on execution.",
            insertText: 'T1574',
            range: range,
        }
        ,
        {
            label: 'DLL Search Order Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may execute their own malicious payloads by hijacking the search order used to load DLLs. Windows systems use a common method to look for required DLLs to load into a program. (Citation: Microsoft Dynamic Link Library Search Order)(Citation: FireEye Hijacking July 2010) Hijacking DLL loads may be for the purpose of establishing persistence as well as elevating privileges and/or evading restrictions on file execution.",
            insertText: 'T1574.001',
            range: range,
        }
        ,
        {
            label: 'DLL Side-Loading',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may execute their own malicious payloads by side-loading DLLs. Similar to [DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001), side-loading involves hijacking which DLL a program loads. But rather than just planting the DLL within the search order of a program then waiting for the victim application to be invoked, adversaries may directly side-load their payloads by planting then invoking a legitimate application that executes their payload(s).",
            insertText: 'T1574.002',
            range: range,
        }
        ,
        {
            label: 'Dylib Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may execute their own payloads by placing a malicious dynamic library (dylib) with an expected name in a path a victim application searches at runtime. The dynamic loader will try to find the dylibs based on the sequential order of the search paths. Paths to dylibs may be prefixed with <code>@rpath</code>, which allows developers to use relative paths to specify an array of search paths used at runtime based on the location of the executable.  Additionally, if weak linking is used, such as the <code>LC_LOAD_WEAK_DYLIB</code> function, an application will still execute even if an expected dylib is not present. Weak linking enables developers to run an application on multiple macOS versions as new APIs are added.",
            insertText: 'T1574.004',
            range: range,
        }
        ,
        {
            label: 'Executable Installer File Permissions Weakness',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may execute their own malicious payloads by hijacking the binaries used by an installer. These processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.",
            insertText: 'T1574.005',
            range: range,
        }
        ,
        {
            label: 'Dynamic Linker Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may execute their own malicious payloads by hijacking environment variables the dynamic linker uses to load shared libraries. During the execution preparation phase of a program, the dynamic linker loads specified absolute paths of shared libraries from environment variables and files, such as <code>LD_PRELOAD</code> on Linux or <code>DYLD_INSERT_LIBRARIES</code> on macOS. Libraries specified in environment variables are loaded first, taking precedence over system libraries with the same function name.(Citation: Man LD.SO)(Citation: TLDP Shared Libraries)(Citation: Apple Doco Archive Dynamic Libraries) These variables are often used by developers to debug binaries without needing to recompile, deconflict mapped symbols, and implement custom functions without changing the original library.(Citation: Baeldung LD_PRELOAD)",
            insertText: 'T1574.006',
            range: range,
        }
        ,
        {
            label: 'Path Interception by PATH Environment Variable',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may execute their own malicious payloads by hijacking environment variables used to load libraries. The PATH environment variable contains a list of directories (User and System) that the OS searches sequentially through in search of the binary that was called from a script or the command line.",
            insertText: 'T1574.007',
            range: range,
        }
        ,
        {
            label: 'Path Interception by Search Order Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may execute their own malicious payloads by hijacking the search order used to load other programs. Because some programs do not call other programs using the full path, adversaries may place their own file in the directory where the calling program is located, causing the operating system to launch their malicious software at the request of the calling program.",
            insertText: 'T1574.008',
            range: range,
        }
        ,
        {
            label: 'Path Interception by Unquoted Path',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may execute their own malicious payloads by hijacking vulnerable file path references. Adversaries can take advantage of paths that lack surrounding quotations by placing an executable in a higher level directory within the path, so that Windows will choose the adversary's executable to launch.",
            insertText: 'T1574.009',
            range: range,
        }
        ,
        {
            label: 'Services File Permissions Weakness',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may execute their own malicious payloads by hijacking the binaries used by services. Adversaries may use flaws in the permissions of Windows services to replace the binary that is executed upon service start. These service processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM.",
            insertText: 'T1574.010',
            range: range,
        }
        ,
        {
            label: 'Services Registry Permissions Weakness',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may execute their own malicious payloads by hijacking the Registry entries used by services. Adversaries may use flaws in the permissions for Registry keys related to services to redirect from the originally specified executable to one that they control, in order to launch their own code when a service starts. Windows stores local service configuration information in the Registry under <code>HKLM\\SYSTEM\\CurrentControlSet\\Services</code>. The information stored under a service's Registry keys can be manipulated to modify a service's execution parameters through tools such as the service controller, sc.exe,  [PowerShell](https://attack.mitre.org/techniques/T1059/001), or [Reg](https://attack.mitre.org/software/S0075). Access to Registry keys is controlled through access control lists and user permissions. (Citation: Registry Key Security)(Citation: malware_hides_service)",
            insertText: 'T1574.011',
            range: range,
        }
        ,
        {
            label: 'COR_PROFILER',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may leverage the COR_PROFILER environment variable to hijack the execution flow of programs that load the .NET CLR. The COR_PROFILER is a .NET Framework feature which allows developers to specify an unmanaged (or external of .NET) profiling DLL to be loaded into each .NET process that loads the Common Language Runtime (CLR). These profilers are designed to monitor, troubleshoot, and debug managed code executed by the .NET CLR.(Citation: Microsoft Profiling Mar 2017)(Citation: Microsoft COR_PROFILER Feb 2013)",
            insertText: 'T1574.012',
            range: range,
        }
        ,
        {
            label: 'KernelCallbackTable',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse the <code>KernelCallbackTable</code> of a process to hijack its execution flow in order to run their own payloads.(Citation: Lazarus APT January 2022)(Citation: FinFisher exposed ) The <code>KernelCallbackTable</code> can be found in the Process Environment Block (PEB) and is initialized to an array of graphic functions available to a GUI process once <code>user32.dll</code> is loaded.(Citation: Windows Process Injection KernelCallbackTable)",
            insertText: 'T1574.013',
            range: range,
        }
        ,
        {
            label: 'AppDomainManager',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may execute their own malicious payloads by hijacking how the .NET `AppDomainManager` loads assemblies. The .NET framework uses the `AppDomainManager` class to create and manage one or more isolated runtime environments (called application domains) inside a process to host the execution of .NET applications. Assemblies (`.exe` or `.dll` binaries compiled to run as .NET code) may be loaded into an application domain as executable code.(Citation: Microsoft App Domains)",
            insertText: 'T1574.014',
            range: range,
        }
        ,
        {
            label: 'Boot or Logon Autostart Execution',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may configure system settings to automatically execute a program during system boot or logon to maintain persistence or gain higher-level privileges on compromised systems. Operating systems may have mechanisms for automatically running a program on system boot or account logon.(Citation: Microsoft Run Key)(Citation: MSDN Authentication Packages)(Citation: Microsoft TimeProvider)(Citation: Cylance Reg Persistence Sept 2013)(Citation: Linux Kernel Programming) These mechanisms may include automatically executing programs that are placed in specially designated directories or are referenced by repositories that store configuration information, such as the Windows Registry. An adversary may achieve the same goal by modifying or extending features of the kernel.",
            insertText: 'T1547',
            range: range,
        }
        ,
        {
            label: 'Registry Run Keys / Startup Folder',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the \"run keys\" in the Registry or startup folder will cause the program referenced to be executed when a user logs in.(Citation: Microsoft Run Key) These programs will be executed under the context of the user and will have the account's associated permissions level.",
            insertText: 'T1547.001',
            range: range,
        }
        ,
        {
            label: 'Authentication Package',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse authentication packages to execute DLLs when the system boots. Windows authentication package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system.(Citation: MSDN Authentication Packages)",
            insertText: 'T1547.002',
            range: range,
        }
        ,
        {
            label: 'Time Providers',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse time providers to execute DLLs when the system boots. The Windows Time service (W32Time) enables time synchronization across and within domains.(Citation: Microsoft W32Time Feb 2018) W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients.(Citation: Microsoft TimeProvider)",
            insertText: 'T1547.003',
            range: range,
        }
        ,
        {
            label: 'Winlogon Helper DLL',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in. Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in <code>HKLM\\Software[\\\\Wow6432Node\\\\]\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\</code> and <code>HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\</code> are used to manage additional helper programs and functionalities that support Winlogon.(Citation: Cylance Reg Persistence Sept 2013)",
            insertText: 'T1547.004',
            range: range,
        }
        ,
        {
            label: 'Security Support Provider',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse security support providers (SSPs) to execute DLLs when the system boots. Windows SSP DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs.",
            insertText: 'T1547.005',
            range: range,
        }
        ,
        {
            label: 'Kernel Modules and Extensions',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify the kernel to automatically execute programs on system boot. Loadable Kernel Modules (LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. For example, one type of module is the device driver, which allows the kernel to access hardware connected to the system.(Citation: Linux Kernel Programming)\u00a0",
            insertText: 'T1547.006',
            range: range,
        }
        ,
        {
            label: 'Re-opened Applications',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify plist files to automatically run an application when a user logs in. When a user logs out or restarts via the macOS Graphical User Interface (GUI), a prompt is provided to the user with a checkbox to \"Reopen windows when logging back in\".(Citation: Re-Open windows on Mac) When selected, all applications currently open are added to a property list file named <code>com.apple.loginwindow.[UUID].plist</code> within the <code>~/Library/Preferences/ByHost</code> directory.(Citation: Methods of Mac Malware Persistence)(Citation: Wardle Persistence Chapter) Applications listed in this file are automatically reopened upon the user\u2019s next logon.",
            insertText: 'T1547.007',
            range: range,
        }
        ,
        {
            label: 'LSASS Driver',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify or add LSASS drivers to obtain persistence on compromised systems. The Windows security subsystem is a set of components that manage and enforce the security policy for a computer or domain. The Local Security Authority (LSA) is the main component responsible for local security policy and user authentication. The LSA includes multiple dynamic link libraries (DLLs) associated with various other security functions, all of which run in the context of the LSA Subsystem Service (LSASS) lsass.exe process.(Citation: Microsoft Security Subsystem)",
            insertText: 'T1547.008',
            range: range,
        }
        ,
        {
            label: 'Shortcut Modification',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create or modify shortcuts that can execute a program during system boot or user login. Shortcuts or symbolic links are used to reference other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process.",
            insertText: 'T1547.009',
            range: range,
        }
        ,
        {
            label: 'Port Monitors',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use port monitors to run an adversary supplied DLL during system boot for persistence or privilege escalation. A port monitor can be set through the <code>AddMonitor</code> API call to set a DLL to be loaded at startup.(Citation: AddMonitor) This DLL can be located in <code>C:\\Windows\\System32</code> and will be loaded and run by the print spooler service, `spoolsv.exe`, under SYSTEM level permissions on boot.(Citation: Bloxham)",
            insertText: 'T1547.010',
            range: range,
        }
        ,
        {
            label: 'Plist Modification',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries can modify property list files (plist files) to execute their code as part of establishing persistence. Plist files are used by macOS applications to store properties and configuration settings for applications and services. Applications use information plist files, <code>Info.plist</code>, to tell the operating system how to handle the application at runtime using structured metadata in the form of keys and values. Plist files are formatted in XML and based on Apple's Core Foundation DTD and can be saved in text or binary format.(Citation: fileinfo plist file description)",
            insertText: 'T1547.011',
            range: range,
        }
        ,
        {
            label: 'Print Processors',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse print processors to run malicious DLLs during system boot for persistence and/or privilege escalation. Print processors are DLLs that are loaded by the print spooler service, `spoolsv.exe`, during boot.(Citation: Microsoft Intro Print Processors)",
            insertText: 'T1547.012',
            range: range,
        }
        ,
        {
            label: 'XDG Autostart Entries',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may add or modify XDG Autostart Entries to execute malicious programs or commands when a user\u2019s desktop environment is loaded at login. XDG Autostart entries are available for any XDG-compliant Linux system. XDG Autostart entries use Desktop Entry files (`.desktop`) to configure the user\u2019s desktop environment upon user login. These configuration files determine what applications launch upon user login, define associated applications to open specific file types, and define applications used to open removable media.(Citation: Free Desktop Application Autostart Feb 2006)(Citation: Free Desktop Entry Keys)",
            insertText: 'T1547.013',
            range: range,
        }
        ,
        {
            label: 'Active Setup',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may achieve persistence by adding a Registry key to the Active Setup of the local machine. Active Setup is a Windows mechanism that is used to execute programs when a user logs in. The value stored in the Registry key will be executed after a user logs into the computer.(Citation: Klein Active Setup 2010) These programs will be executed under the context of the user and will have the account's associated permissions level.",
            insertText: 'T1547.014',
            range: range,
        }
        ,
        {
            label: 'Login Items',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may add login items to execute upon user login to gain persistence or escalate privileges. Login items are applications, documents, folders, or server connections that are automatically launched when a user logs in.(Citation: Open Login Items Apple) Login items can be added via a shared file list or Service Management Framework.(Citation: Adding Login Items) Shared file list login items can be set using scripting languages such as [AppleScript](https://attack.mitre.org/techniques/T1059/002), whereas the Service Management Framework uses the API call <code>SMLoginItemSetEnabled</code>.",
            insertText: 'T1547.015',
            range: range,
        }
        ,
        {
            label: 'Event Triggered Execution',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may establish persistence and/or elevate privileges using system mechanisms that trigger execution based on specific events. Various operating systems have means to monitor and subscribe to events such as logons or other user activity such as running specific applications/binaries. Cloud environments may also support various functions and services that monitor and can be invoked in response to specific cloud events.(Citation: Backdooring an AWS account)(Citation: Varonis Power Automate Data Exfiltration)(Citation: Microsoft DART Case Report 001)",
            insertText: 'T1546',
            range: range,
        }
        ,
        {
            label: 'Change Default File Association',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may establish persistence by executing malicious content triggered by a file type association. When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access or by administrators using the built-in assoc utility.(Citation: Microsoft Change Default Programs)(Citation: Microsoft File Handlers)(Citation: Microsoft Assoc Oct 2017) Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.",
            insertText: 'T1546.001',
            range: range,
        }
        ,
        {
            label: 'Screensaver',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may establish persistence by executing malicious content triggered by user inactivity. Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension.(Citation: Wikipedia Screensaver) The Windows screensaver application scrnsave.scr is located in <code>C:\\Windows\\System32\\</code>, and <code>C:\\Windows\\sysWOW64\\</code>  on 64-bit Windows systems, along with screensavers included with base Windows installations.",
            insertText: 'T1546.002',
            range: range,
        }
        ,
        {
            label: 'Windows Management Instrumentation Event Subscription',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may establish persistence and elevate privileges by executing malicious content triggered by a Windows Management Instrumentation (WMI) event subscription. WMI can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Examples of events that may be subscribed to are the wall clock time, user login, or the computer's uptime.(Citation: Mandiant M-Trends 2015)",
            insertText: 'T1546.003',
            range: range,
        }
        ,
        {
            label: 'Unix Shell Configuration Modification',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may establish persistence through executing malicious commands triggered by a user\u2019s shell. User [Unix Shell](https://attack.mitre.org/techniques/T1059/004)s execute several configuration scripts at different points throughout the session based on events. For example, when a user opens a command-line interface or remotely logs in (such as via SSH) a login shell is initiated. The login shell executes scripts from the system (<code>/etc</code>) and the user\u2019s home directory (<code>~/</code>) to configure the environment. All login shells on a system use /etc/profile when initiated. These configuration scripts run at the permission level of their directory and are often used to set environment variables, create aliases, and customize the user\u2019s environment. When the shell exits or terminates, additional shell scripts are executed to ensure the shell exits appropriately.",
            insertText: 'T1546.004',
            range: range,
        }
        ,
        {
            label: 'Trap',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may establish persistence by executing malicious content triggered by an interrupt signal. The <code>trap</code> command allows programs and shells to specify commands that will be executed upon receiving interrupt signals. A common situation is a script allowing for graceful termination and handling of common keyboard interrupts like <code>ctrl+c</code> and <code>ctrl+d</code>.",
            insertText: 'T1546.005',
            range: range,
        }
        ,
        {
            label: 'LC_LOAD_DYLIB Addition',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may establish persistence by executing malicious content triggered by the execution of tainted binaries. Mach-O binaries have a series of headers that are used to perform certain operations when a binary is loaded. The LC_LOAD_DYLIB header in a Mach-O binary tells macOS and OS X which dynamic libraries (dylibs) to load during execution time. These can be added ad-hoc to the compiled binary as long as adjustments are made to the rest of the fields and dependencies.(Citation: Writing Bad Malware for OSX) There are tools available to perform these changes.",
            insertText: 'T1546.006',
            range: range,
        }
        ,
        {
            label: 'Netsh Helper DLL',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may establish persistence by executing malicious content triggered by Netsh Helper DLLs. Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility.(Citation: TechNet Netsh) The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at <code>HKLM\\SOFTWARE\\Microsoft\\Netsh</code>.",
            insertText: 'T1546.007',
            range: range,
        }
        ,
        {
            label: 'Accessibility Features',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by accessibility features. Windows contains accessibility features that may be launched with a key combination before a user has logged in (ex: when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system.",
            insertText: 'T1546.008',
            range: range,
        }
        ,
        {
            label: 'AppCert DLLs',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppCert DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the <code>AppCertDLLs</code> Registry key under <code>HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\</code> are loaded into every process that calls the ubiquitously used application programming interface (API) functions <code>CreateProcess</code>, <code>CreateProcessAsUser</code>, <code>CreateProcessWithLoginW</code>, <code>CreateProcessWithTokenW</code>, or <code>WinExec</code>. (Citation: Elastic Process Injection July 2017)",
            insertText: 'T1546.009',
            range: range,
        }
        ,
        {
            label: 'AppInit DLLs',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by AppInit DLLs loaded into processes. Dynamic-link libraries (DLLs) that are specified in the <code>AppInit_DLLs</code> value in the Registry keys <code>HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows</code> or <code>HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows</code> are loaded by user32.dll into every process that loads user32.dll. In practice this is nearly every program, since user32.dll is a very common library. (Citation: Elastic Process Injection July 2017)",
            insertText: 'T1546.010',
            range: range,
        }
        ,
        {
            label: 'Application Shimming',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by application shims. The Microsoft Windows Application Compatibility Infrastructure/Framework (Application Shim) was created to allow for backward compatibility of software as the operating system codebase changes over time. For example, the application shimming feature allows developers to apply fixes to applications (without rewriting code) that were created for Windows XP so that it will work with Windows 10. (Citation: Elastic Process Injection July 2017)",
            insertText: 'T1546.011',
            range: range,
        }
        ,
        {
            label: 'Image File Execution Options Injection',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may establish persistence and/or elevate privileges by executing malicious content triggered by Image File Execution Options (IFEO) debuggers. IFEOs enable a developer to attach a debugger to an application. When a process is created, a debugger present in an application\u2019s IFEO will be prepended to the application\u2019s name, effectively launching the new process under the debugger (e.g., <code>C:\\dbg\\ntsd.exe -g  notepad.exe</code>). (Citation: Microsoft Dev Blog IFEO Mar 2010)",
            insertText: 'T1546.012',
            range: range,
        }
        ,
        {
            label: 'PowerShell Profile',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gain persistence and elevate privileges by executing malicious content triggered by PowerShell profiles. A PowerShell profile  (<code>profile.ps1</code>) is a script that runs when [PowerShell](https://attack.mitre.org/techniques/T1059/001) starts and can be used as a logon script to customize user environments.",
            insertText: 'T1546.013',
            range: range,
        }
        ,
        {
            label: 'Emond',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may gain persistence and elevate privileges by executing malicious content triggered by the Event Monitor Daemon (emond). Emond is a [Launch Daemon](https://attack.mitre.org/techniques/T1543/004) that accepts events from various services, runs them through a simple rules engine, and takes action. The emond binary at <code>/sbin/emond</code> will load any rules from the <code>/etc/emond.d/rules/</code> directory and take action once an explicitly defined event takes place.",
            insertText: 'T1546.014',
            range: range,
        }
        ,
        {
            label: 'Component Object Model Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may establish persistence by executing malicious content triggered by hijacked references to Component Object Model (COM) objects. COM is a system within Windows to enable interaction between software components through the operating system.(Citation: Microsoft Component Object Model)  References to various COM objects are stored in the Registry.",
            insertText: 'T1546.015',
            range: range,
        }
        ,
        {
            label: 'Installer Packages',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may establish persistence and elevate privileges by using an installer to trigger the execution of malicious content. Installer packages are OS specific and contain the resources an operating system needs to install applications on a system. Installer packages can include scripts that run prior to installation as well as after installation is complete. Installer scripts may inherit elevated permissions when executed. Developers often use these scripts to prepare the environment for installation, check requirements, download dependencies, and remove files after installation.(Citation: Installer Package Scripting Rich Trouton)",
            insertText: 'T1546.016',
            range: range,
        }
        ,
        {
            label: 'Udev Rules',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may maintain persistence through executing malicious content triggered using udev rules. Udev is the Linux kernel device manager that dynamically manages device nodes, handles access to pseudo-device files in the `/dev` directory, and responds to hardware events, such as when external devices like hard drives or keyboards are plugged in or removed. Udev uses rule files with `match keys` to specify the conditions a hardware event must meet and `action keys` to define the actions that should follow. Root permissions are required to create, modify, or delete rule files located in `/etc/udev/rules.d/`, `/run/udev/rules.d/`, `/usr/lib/udev/rules.d/`, `/usr/local/lib/udev/rules.d/`, and `/lib/udev/rules.d/`. Rule priority is determined by both directory and by the digit prefix in the rule filename.(Citation: Ignacio Udev research 2024)(Citation: Elastic Linux Persistence 2024)",
            insertText: 'T1546.017',
            range: range,
        }
        ,
        {
            label: 'Winlogon Helper DLL',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Winlogon.exe is a Windows component responsible for actions at logon/logoff as well as the secure attention sequence (SAS) triggered by Ctrl-Alt-Delete. Registry entries in <code>HKLM\\Software\\[Wow6432Node\\]Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\</code> and <code>HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\</code> are used to manage additional helper programs and functionalities that support Winlogon. (Citation: Cylance Reg Persistence Sept 2013)",
            insertText: 'T1004',
            range: range,
        }
        ,
        {
            label: 'System Firmware',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "The BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) or Extensible Firmware Interface (EFI) are examples of system firmware that operate as the software interface between the operating system and hardware of a computer. (Citation: Wikipedia BIOS) (Citation: Wikipedia UEFI) (Citation: About UEFI)",
            insertText: 'T1019',
            range: range,
        }
        ,
        {
            label: 'Shortcut Modification',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Shortcuts or symbolic links are ways of referencing other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process. Adversaries could use shortcuts to execute their tools for persistence. They may create a new shortcut as a means of indirection that may use [Masquerading](https://attack.mitre.org/techniques/T1036) to look like a legitimate program. Adversaries could also edit the target path or entirely replace an existing shortcut so their tools will be executed instead of the intended legitimate program.",
            insertText: 'T1023',
            range: range,
        }
        ,
        {
            label: 'Modify Existing Service',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Windows service configuration information, including the file path to the service's executable or recovery programs/commands, is stored in the Registry. Service configurations can be modified using utilities such as sc.exe and [Reg](https://attack.mitre.org/software/S0075).",
            insertText: 'T1031',
            range: range,
        }
        ,
        {
            label: 'Change Default File Association',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "When a file is opened, the default program used to open the file (also called the file association or handler) is checked. File association selections are stored in the Windows Registry and can be edited by users, administrators, or programs that have Registry access (Citation: Microsoft Change Default Programs) (Citation: Microsoft File Handlers) or by administrators using the built-in assoc utility. (Citation: Microsoft Assoc Oct 2017) Applications can modify the file association for a given file extension to call an arbitrary program when a file with the given extension is opened.",
            insertText: 'T1042',
            range: range,
        }
        ,
        {
            label: 'Registry Run Keys / Startup Folder',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the \"run keys\" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. (Citation: Microsoft Run Key) These programs will be executed under the context of the user and will have the account's associated permissions level.",
            insertText: 'T1060',
            range: range,
        }
        ,
        {
            label: 'Hypervisor',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "**This technique has been deprecated and should no longer be used.**",
            insertText: 'T1062',
            range: range,
        }
        ,
        {
            label: 'Bootkit',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "A bootkit is a malware variant that modifies the boot sectors of a hard drive, including the Master Boot Record (MBR) and Volume Boot Record (VBR). (Citation: MTrends 2016)",
            insertText: 'T1067',
            range: range,
        }
        ,
        {
            label: 'Windows Management Instrumentation Event Subscription',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Windows Management Instrumentation (WMI) can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system. Adversaries may attempt to evade detection of this technique by compiling WMI scripts into Windows Management Object (MOF) files (.mof extension). (Citation: Dell WMI Persistence) Examples of events that may be subscribed to are the wall clock time or the computer's uptime. (Citation: Kazanciyan 2014) Several threat groups have reportedly used this technique to maintain persistence. (Citation: Mandiant M-Trends 2015)",
            insertText: 'T1084',
            range: range,
        }
        ,
        {
            label: 'Security Support Provider',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Windows Security Support Provider (SSP) DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: <code>HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages</code> and <code>HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security Packages</code>. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.",
            insertText: 'T1101',
            range: range,
        }
        ,
        {
            label: 'Redundant Access',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "**This technique has been deprecated. Please use [Create Account](https://attack.mitre.org/techniques/T1136), [Web Shell](https://attack.mitre.org/techniques/T1505/003), and [External Remote Services](https://attack.mitre.org/techniques/T1133) where appropriate.**",
            insertText: 'T1108',
            range: range,
        }
        ,
        {
            label: 'Component Firmware',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Some adversaries may employ sophisticated means to compromise computer components and install malicious firmware that will execute adversary code outside of the operating system and main system firmware or BIOS. This technique may be similar to [System Firmware](https://attack.mitre.org/techniques/T1019) but conducted upon other system components that may not have the same capability or level of integrity checking. Malicious device firmware could provide both a persistent level of access to systems despite potential typical failures to maintain access and hard disk re-images, as well as a way to evade host software-based defenses and integrity checks.",
            insertText: 'T1109',
            range: range,
        }
        ,
        {
            label: 'Component Object Model Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "The Component Object Model (COM) is a system within Windows to enable interaction between software components through the operating system. (Citation: Microsoft Component Object Model) Adversaries can use this system to insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships as a means for persistence. Hijacking a COM object requires a change in the Windows Registry to replace a reference to a legitimate system component which may cause that component to not work when executed. When that system component is executed through normal system operation the adversary's code will be executed instead. (Citation: GDATA COM Hijacking) An adversary is likely to hijack objects that are used frequently enough to maintain a consistent level of persistence, but are unlikely to break noticeable functionality within the system as to avoid system instability that could lead to detection.",
            insertText: 'T1122',
            range: range,
        }
        ,
        {
            label: 'Netsh Helper DLL',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Netsh.exe (also referred to as Netshell) is a command-line scripting utility used to interact with the network configuration of a system. It contains functionality to add helper DLLs for extending functionality of the utility. (Citation: TechNet Netsh) The paths to registered netsh.exe helper DLLs are entered into the Windows Registry at <code>HKLM\\SOFTWARE\\Microsoft\\Netsh</code>.",
            insertText: 'T1128',
            range: range,
        }
        ,
        {
            label: 'Authentication Package',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Windows Authentication Package DLLs are loaded by the Local Security Authority (LSA) process at system start. They provide support for multiple logon processes and multiple security protocols to the operating system. (Citation: MSDN Authentication Packages)",
            insertText: 'T1131',
            range: range,
        }
        ,
        {
            label: 'Malicious Shell Modification',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may establish persistence through executing malicious commands triggered by a user\u2019s shell. User shells execute several configuration scripts at different points throughout the session based on events. For example, when a user opens a command line interface or remotely logs in (such as SSH) a login shell is initiated. The login shell executes scripts from the system (/etc) and the user\u2019s home directory (~/) to configure the environment. All login shells on a system use <code>/etc/profile</code> when initiated. These configuration scripts run at the permission level of their directory and are often used to set environment variables, create aliases, and customize the user\u2019s environment. When the shell exits or terminates, additional shell scripts are executed to ensure the shell exits appropriately.",
            insertText: 'T1156',
            range: range,
        }
        ,
        {
            label: 'Hidden Files and Directories',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a \u2018hidden\u2019 file. These files don\u2019t show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files either via a series of Graphical User Interface (GUI) prompts or with command line switches (<code>dir /a</code> for Windows and <code>ls \u2013a</code> for Linux and macOS).",
            insertText: 'T1158',
            range: range,
        }
        ,
        {
            label: 'Launch Agent',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Per Apple\u2019s developer documentation, when a user logs in, a per-user launchd process is started which loads the parameters for each launch-on-demand user agent from the property list (plist) files found in <code>/System/Library/LaunchAgents</code>, <code>/Library/LaunchAgents</code>, and <code>$HOME/Library/LaunchAgents</code> (Citation: AppleDocs Launch Agent Daemons) (Citation: OSX Keydnap malware) (Citation: Antiquated Mac Malware). These launch agents have property list files which point to the executables that will be launched (Citation: OSX.Dok Malware).",
            insertText: 'T1159',
            range: range,
        }
        ,
        {
            label: 'LC_LOAD_DYLIB Addition',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Mach-O binaries have a series of headers that are used to perform certain operations when a binary is loaded. The LC_LOAD_DYLIB header in a Mach-O binary tells macOS and OS X which dynamic libraries (dylibs) to load during execution time. These can be added ad-hoc to the compiled binary as long adjustments are made to the rest of the fields and dependencies (Citation: Writing Bad Malware for OSX). There are tools available to perform these changes. Any changes will invalidate digital signatures on binaries because the binary is being modified. Adversaries can remediate this issue by simply removing the LC_CODE_SIGNATURE command from the binary so that the signature isn\u2019t checked at load time (Citation: Malware Persistence on OS X).",
            insertText: 'T1161',
            range: range,
        }
        ,
        {
            label: 'Login Item',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "MacOS provides the option to list specific applications to run when a user logs in. These applications run under the logged in user's context, and will be started every time the user logs in. Login items installed using the Service Management Framework are not visible in the System Preferences and can only be removed by the application that created them (Citation: Adding Login Items). Users have direct control over login items installed using a shared file list which are also visible in System Preferences (Citation: Adding Login Items). These login items are stored in the user's <code>~/Library/Preferences/</code> directory in a plist file called <code>com.apple.loginitems.plist</code> (Citation: Methods of Mac Malware Persistence). Some of these applications can open visible dialogs to the user, but they don\u2019t all have to since there is an option to \u2018Hide\u2019 the window. If an adversary can register their own login item or modified an existing one, then they can use it to execute their code for a persistence mechanism each time the user logs in (Citation: Malware Persistence on OS X) (Citation: OSX.Dok Malware). The API method <code> SMLoginItemSetEnabled </code> can be used to set Login Items, but scripting languages like [AppleScript](https://attack.mitre.org/techniques/T1155) can do this as well  (Citation: Adding Login Items).",
            insertText: 'T1162',
            range: range,
        }
        ,
        {
            label: 'Rc.common',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "During the boot process, macOS executes <code>source /etc/rc.common</code>, which is a shell script containing various utility functions. This file also defines routines for processing command-line arguments and for gathering system settings, and is thus recommended to include in the start of Startup Item Scripts (Citation: Startup Items). In macOS and OS X, this is now a deprecated technique in favor of launch agents and launch daemons, but is currently still used.",
            insertText: 'T1163',
            range: range,
        }
        ,
        {
            label: 'Re-opened Applications',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Starting in Mac OS X 10.7 (Lion), users can specify certain applications to be re-opened when a user reboots their machine. While this is usually done via a Graphical User Interface (GUI) on an app-by-app basis, there are property list files (plist) that contain this information as well located at <code>~/Library/Preferences/com.apple.loginwindow.plist</code> and <code>~/Library/Preferences/ByHost/com.apple.loginwindow.* .plist</code>.",
            insertText: 'T1164',
            range: range,
        }
        ,
        {
            label: 'Browser Extensions',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse Internet browser extensions to establish persistent access to victim systems. Browser extensions or plugins are small programs that can add functionality and customize aspects of Internet browsers. They can be installed directly or through a browser's app store and generally have access and permissions to everything that the browser can access.(Citation: Wikipedia Browser Extension)(Citation: Chrome Extensions Definition)",
            insertText: 'T1176',
            range: range,
        }
        ,
        {
            label: 'Screensaver',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension.(Citation: Wikipedia Screensaver) The Windows screensaver application scrnsave.scr is located in <code>C:\\Windows\\System32\\</code>, and <code>C:\\Windows\\sysWOW64\\</code> on 64-bit Windows systems, along with screensavers included with base Windows installations.",
            insertText: 'T1180',
            range: range,
        }
        ,
        {
            label: 'BITS Jobs',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse BITS jobs to persistently execute code and perform various background tasks. Windows Background Intelligent Transfer Service (BITS) is a low-bandwidth, asynchronous file transfer mechanism exposed through [Component Object Model](https://attack.mitre.org/techniques/T1559/001) (COM).(Citation: Microsoft COM)(Citation: Microsoft BITS) BITS is commonly used by updaters, messengers, and other applications preferred to operate in the background (using available idle bandwidth) without interrupting other networked applications. File transfer tasks are implemented as BITS jobs, which contain a queue of one or more file operations.",
            insertText: 'T1197',
            range: range,
        }
        ,
        {
            label: 'SIP and Trust Provider Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "In user mode, Windows Authenticode (Citation: Microsoft Authenticode) digital signatures are used to verify a file's origin and integrity, variables that may be used to establish trust in signed code (ex: a driver with a valid Microsoft signature may be handled as safe). The signature validation process is handled via the WinVerifyTrust application programming interface (API) function,  (Citation: Microsoft WinVerifyTrust) which accepts an inquiry and coordinates with the appropriate trust provider, which is responsible for validating parameters of a signature. (Citation: SpectorOps Subverting Trust Sept 2017)",
            insertText: 'T1198',
            range: range,
        }
        ,
        {
            label: 'Time Providers',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "The Windows Time service (W32Time) enables time synchronization across and within domains. (Citation: Microsoft W32Time Feb 2018) W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients. (Citation: Microsoft TimeProvider)",
            insertText: 'T1209',
            range: range,
        }
        ,
        {
            label: 'Kernel Modules and Extensions',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Loadable Kernel Modules (or LKMs) are pieces of code that can be loaded and unloaded into the kernel upon demand. They extend the functionality of the kernel without the need to reboot the system. For example, one type of module is the device driver, which allows the kernel to access hardware connected to the system. (Citation: Linux Kernel Programming)\u00a0When used maliciously, Loadable Kernel Modules (LKMs) can be a type of kernel-mode [Rootkit](https://attack.mitre.org/techniques/T1014) that run with the highest operating system privilege (Ring 0). (Citation: Linux Kernel Module Programming Guide)\u00a0Adversaries can use loadable kernel modules to covertly persist on a system and evade defenses. Examples have been found in the wild and there are some open source projects. (Citation: Volatility Phalanx2) (Citation: CrowdStrike Linux Rootkit) (Citation: GitHub Reptile) (Citation: GitHub Diamorphine)",
            insertText: 'T1215',
            range: range,
        }
        ,
        {
            label: 'Systemd Service',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Systemd services can be used to establish persistence on a Linux system. The systemd service manager is commonly used for managing background daemon processes (also known as services) and other system resources.(Citation: Linux man-pages: systemd January 2014)(Citation: Freedesktop.org Linux systemd 29SEP2018) Systemd is the default initialization (init) system on many Linux distributions starting with Debian 8, Ubuntu 15.04, CentOS 7, RHEL 7, Fedora 15, and replaces legacy init systems including SysVinit and Upstart while remaining backwards compatible with the aforementioned init systems.",
            insertText: 'T1501',
            range: range,
        }
        ,
        {
            label: 'Implant Internal Image',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may implant cloud or container images with malicious code to establish persistence after gaining access to an environment. Amazon Web Services (AWS) Amazon Machine Images (AMIs), Google Cloud Platform (GCP) Images, and Azure Images as well as popular container runtimes such as Docker can be implanted or backdoored. Unlike [Upload Malware](https://attack.mitre.org/techniques/T1608/001), this technique focuses on adversaries implanting an image in a registry within a victim\u2019s environment. Depending on how the infrastructure is provisioned, this could provide persistent access if the infrastructure provisioning tool is instructed to always use the latest image.(Citation: Rhino Labs Cloud Image Backdoor Technique Sept 2019)",
            insertText: 'T1525',
            range: range,
        }
        ,
        {
            label: 'Power Settings',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may impair a system's ability to hibernate, reboot, or shut down in order to extend access to infected machines. When a computer enters a dormant state, some or all software and hardware may cease to operate which can disrupt malicious activity.(Citation: Sleep, shut down, hibernate)",
            insertText: 'T1653',
            range: range,
        }
        ,
        {
            label: 'Compromise Host Software Binary',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify host software binaries to establish persistent access to systems. Software binaries/executables provide a wide range of system commands or services, programs, and libraries. Common software binaries are SSH clients, FTP clients, email clients, web browsers, and many other user or server applications.",
            insertText: 'T1554',
            range: range,
        }
        ,
        {
            label: 'Create Account',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create an account to maintain access to victim systems.(Citation: Symantec WastedLocker June 2020) With a sufficient level of access, creating such accounts may be used to establish secondary credentialed access that do not require persistent remote access tools to be deployed on the system.",
            insertText: 'T1136',
            range: range,
        }
        ,
        {
            label: 'Local Account',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create a local account to maintain access to victim systems. Local accounts are those configured by an organization for use by users, remote support, services, or for administration on a single system or service.",
            insertText: 'T1136.001',
            range: range,
        }
        ,
        {
            label: 'Domain Account',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create a domain account to maintain access to victim systems. Domain accounts are those managed by Active Directory Domain Services where access and permissions are configured across systems and services that are part of that domain. Domain accounts can cover user, administrator, and service accounts. With a sufficient level of access, the <code>net user /add /domain</code> command can be used to create a domain account.(Citation: Savill 1999)",
            insertText: 'T1136.002',
            range: range,
        }
        ,
        {
            label: 'Cloud Account',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create a cloud account to maintain access to victim systems. With a sufficient level of access, such accounts may be used to establish secondary credentialed access that does not require persistent remote access tools to be deployed on the system.(Citation: Microsoft O365 Admin Roles)(Citation: Microsoft Support O365 Add Another Admin, October 2019)(Citation: AWS Create IAM User)(Citation: GCP Create Cloud Identity Users)(Citation: Microsoft Azure AD Users)",
            insertText: 'T1136.003',
            range: range,
        }
        ,
        {
            label: 'Server Software Component',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse legitimate extensible development features of servers to establish persistent access to systems. Enterprise server applications may include features that allow developers to write and install software or scripts to extend the functionality of the main application. Adversaries may install malicious components to extend and abuse server applications.(Citation: volexity_0day_sophos_FW)",
            insertText: 'T1505',
            range: range,
        }
        ,
        {
            label: 'SQL Stored Procedures',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse SQL stored procedures to establish persistent access to systems. SQL Stored Procedures are code that can be saved and reused so that database users do not waste time rewriting frequently used SQL queries. Stored procedures can be invoked via SQL statements to the database using the procedure name or via defined events (e.g. when a SQL server application is started/restarted).",
            insertText: 'T1505.001',
            range: range,
        }
        ,
        {
            label: 'Transport Agent',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse Microsoft transport agents to establish persistent access to systems. Microsoft Exchange transport agents can operate on email messages passing through the transport pipeline to perform various tasks such as filtering spam, filtering malicious attachments, journaling, or adding a corporate signature to the end of all outgoing emails.(Citation: Microsoft TransportAgent Jun 2016)(Citation: ESET LightNeuron May 2019) Transport agents can be written by application developers and then compiled to .NET assemblies that are subsequently registered with the Exchange server. Transport agents will be invoked during a specified stage of email processing and carry out developer defined tasks.",
            insertText: 'T1505.002',
            range: range,
        }
        ,
        {
            label: 'Web Shell',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may backdoor web servers with web shells to establish persistent access to systems. A Web shell is a Web script that is placed on an openly accessible Web server to allow an adversary to access the Web server as a gateway into a network. A Web shell may provide a set of functions to execute or a command-line interface on the system that hosts the Web server.(Citation: volexity_0day_sophos_FW)",
            insertText: 'T1505.003',
            range: range,
        }
        ,
        {
            label: 'IIS Components',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may install malicious components that run on Internet Information Services (IIS) web servers to establish persistence. IIS provides several mechanisms to extend the functionality of the web servers. For example, Internet Server Application Programming Interface (ISAPI) extensions and filters can be installed to examine and/or modify incoming and outgoing IIS web requests. Extensions and filters are deployed as DLL files that export three functions: <code>Get{Extension/Filter}Version</code>, <code>Http{Extension/Filter}Proc</code>, and (optionally) <code>Terminate{Extension/Filter}</code>. IIS modules may also be installed to extend IIS web servers.(Citation: Microsoft ISAPI Extension Overview 2017)(Citation: Microsoft ISAPI Filter Overview 2017)(Citation: IIS Backdoor 2011)(Citation: Trustwave IIS Module 2013)",
            insertText: 'T1505.004',
            range: range,
        }
        ,
        {
            label: 'Terminal Services DLL',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse components of Terminal Services to enable persistent access to systems. Microsoft Terminal Services, renamed to Remote Desktop Services in some Windows Server OSs as of 2022, enable remote terminal connections to hosts. Terminal Services allows servers to transmit a full, interactive, graphical user interface to clients via RDP.(Citation: Microsoft Remote Desktop Services)",
            insertText: 'T1505.005',
            range: range,
        }
        ,
        {
            label: 'Pre-OS Boot',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse Pre-OS Boot mechanisms as a way to establish persistence on a system. During the booting process of a computer, firmware and various startup services are loaded before the operating system. These programs control flow of execution before the operating system takes control.(Citation: Wikipedia Booting)",
            insertText: 'T1542',
            range: range,
        }
        ,
        {
            label: 'System Firmware',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify system firmware to persist on systems.The BIOS (Basic Input/Output System) and The Unified Extensible Firmware Interface (UEFI) or Extensible Firmware Interface (EFI) are examples of system firmware that operate as the software interface between the operating system and hardware of a computer.(Citation: Wikipedia BIOS)(Citation: Wikipedia UEFI)(Citation: About UEFI)",
            insertText: 'T1542.001',
            range: range,
        }
        ,
        {
            label: 'Component Firmware',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify component firmware to persist on systems. Some adversaries may employ sophisticated means to compromise computer components and install malicious firmware that will execute adversary code outside of the operating system and main system firmware or BIOS. This technique may be similar to [System Firmware](https://attack.mitre.org/techniques/T1542/001) but conducted upon other system components/devices that may not have the same capability or level of integrity checking.",
            insertText: 'T1542.002',
            range: range,
        }
        ,
        {
            label: 'Bootkit',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use bootkits to persist on systems. Bootkits reside at a layer below the operating system and may make it difficult to perform full remediation unless an organization suspects one was used and can act accordingly.",
            insertText: 'T1542.003',
            range: range,
        }
        ,
        {
            label: 'ROMMONkit',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse the ROM Monitor (ROMMON) by loading an unauthorized firmware with adversary code to provide persistent access and manipulate device behavior that is difficult to detect. (Citation: Cisco Synful Knock Evolution)(Citation: Cisco Blog Legacy Device Attacks)",
            insertText: 'T1542.004',
            range: range,
        }
        ,
        {
            label: 'TFTP Boot',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse netbooting to load an unauthorized network device operating system from a Trivial File Transfer Protocol (TFTP) server. TFTP boot (netbooting) is commonly used by network administrators to load configuration-controlled network device images from a centralized management server. Netbooting is one option in the boot sequence and can be used to centralize, manage, and control device images.",
            insertText: 'T1542.005',
            range: range,
        }
        ,
        {
            label: 'Office Application Startup',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may leverage Microsoft Office-based applications for persistence between startups. Microsoft Office is a fairly common application suite on Windows-based operating systems within an enterprise network. There are multiple mechanisms that can be used with Office for persistence when an Office-based application is started; this can include the use of Office Template Macros and add-ins.",
            insertText: 'T1137',
            range: range,
        }
        ,
        {
            label: 'Office Template Macros',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse Microsoft Office templates to obtain persistence on a compromised system. Microsoft Office contains templates that are part of common Office applications and are used to customize styles. The base templates within the application are used each time an application starts. (Citation: Microsoft Change Normal Template)",
            insertText: 'T1137.001',
            range: range,
        }
        ,
        {
            label: 'Office Test',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse the Microsoft Office \"Office Test\" Registry key to obtain persistence on a compromised system. An Office Test Registry location exists that allows a user to specify an arbitrary DLL that will be executed every time an Office application is started. This Registry key is thought to be used by Microsoft to load DLLs for testing and debugging purposes while developing Office applications. This Registry key is not created by default during an Office installation.(Citation: Hexacorn Office Test)(Citation: Palo Alto Office Test Sofacy)",
            insertText: 'T1137.002',
            range: range,
        }
        ,
        {
            label: 'Outlook Forms',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse Microsoft Outlook forms to obtain persistence on a compromised system. Outlook forms are used as templates for presentation and functionality in Outlook messages. Custom Outlook forms can be created that will execute code when a specifically crafted email is sent by an adversary utilizing the same custom Outlook form.(Citation: SensePost Outlook Forms)",
            insertText: 'T1137.003',
            range: range,
        }
        ,
        {
            label: 'Outlook Home Page',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse Microsoft Outlook's Home Page feature to obtain persistence on a compromised system. Outlook Home Page is a legacy feature used to customize the presentation of Outlook folders. This feature allows for an internal or external URL to be loaded and presented whenever a folder is opened. A malicious HTML page can be crafted that will execute code when loaded by Outlook Home Page.(Citation: SensePost Outlook Home Page)",
            insertText: 'T1137.004',
            range: range,
        }
        ,
        {
            label: 'Outlook Rules',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse Microsoft Outlook rules to obtain persistence on a compromised system. Outlook rules allow a user to define automated behavior to manage email messages. A benign rule might, for example, automatically move an email to a particular folder in Outlook if it contains specific words from a specific sender. Malicious Outlook rules can be created that can trigger code execution when an adversary sends a specifically crafted email to that user.(Citation: SilentBreak Outlook Rules)",
            insertText: 'T1137.005',
            range: range,
        }
        ,
        {
            label: 'Add-ins',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse Microsoft Office add-ins to obtain persistence on a compromised system. Office add-ins can be used to add functionality to Office programs. (Citation: Microsoft Office Add-ins) There are different types of add-ins that can be used by the various Office products; including Word/Excel add-in Libraries (WLL/XLL), VBA add-ins, Office Component Object Model (COM) add-ins, automation add-ins, VBA Editor (VBE), Visual Studio Tools for Office (VSTO) add-ins, and Outlook add-ins. (Citation: MRWLabs Office Persistence Add-ins)(Citation: FireEye Mail CDS 2018)",
            insertText: 'T1137.006',
            range: range,
        }
        ,
        {
            label: 'Account Manipulation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may manipulate accounts to maintain and/or elevate access to victim systems. Account manipulation may consist of any action that preserves or modifies adversary access to a compromised account, such as modifying credentials or permission groups.(Citation: FireEye SMOKEDHAM June 2021) These actions could also include account activity designed to subvert security policies, such as performing iterative password updates to bypass password duration policies and preserve the life of compromised credentials.",
            insertText: 'T1098',
            range: range,
        }
        ,
        {
            label: 'Additional Cloud Credentials',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may add adversary-controlled credentials to a cloud account to maintain persistent access to victim accounts and instances within the environment.",
            insertText: 'T1098.001',
            range: range,
        }
        ,
        {
            label: 'Additional Email Delegate Permissions',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may grant additional permission levels to maintain persistent access to an adversary-controlled email account.",
            insertText: 'T1098.002',
            range: range,
        }
        ,
        {
            label: 'Additional Cloud Roles',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may add additional roles or permissions to an adversary-controlled cloud account to maintain persistent access to a tenant. For example, adversaries may update IAM policies in cloud-based environments or add a new global administrator in Office 365 environments.(Citation: AWS IAM Policies and Permissions)(Citation: Google Cloud IAM Policies)(Citation: Microsoft Support O365 Add Another Admin, October 2019)(Citation: Microsoft O365 Admin Roles) With sufficient permissions, a compromised account can gain almost unlimited access to data and settings (including the ability to reset the passwords of other admins).(Citation: Expel AWS Attacker)",
            insertText: 'T1098.003',
            range: range,
        }
        ,
        {
            label: 'SSH Authorized Keys',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify the SSH <code>authorized_keys</code> file to maintain persistence on a victim host. Linux distributions and macOS commonly use key-based authentication to secure the authentication process of SSH sessions for remote management. The <code>authorized_keys</code> file in SSH specifies the SSH keys that can be used for logging into the user account for which the file is configured. This file is usually found in the user's home directory under <code>&lt;user-home&gt;/.ssh/authorized_keys</code>.(Citation: SSH Authorized Keys) Users may edit the system\u2019s SSH config file to modify the directives PubkeyAuthentication and RSAAuthentication to the value \u201cyes\u201d to ensure public key and RSA authentication are enabled. The SSH config file is usually located under <code>/etc/ssh/sshd_config</code>.",
            insertText: 'T1098.004',
            range: range,
        }
        ,
        {
            label: 'Device Registration',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may register a device to an adversary-controlled account. Devices may be registered in a multifactor authentication (MFA) system, which handles authentication to the network, or in a device management system, which handles device access and compliance.",
            insertText: 'T1098.005',
            range: range,
        }
        ,
        {
            label: 'Additional Container Cluster Roles',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may add additional roles or permissions to an adversary-controlled user or service account to maintain persistent access to a container orchestration system. For example, an adversary with sufficient permissions may create a RoleBinding or a ClusterRoleBinding to bind a Role or ClusterRole to a Kubernetes account.(Citation: Kubernetes RBAC)(Citation: Aquasec Kubernetes Attack 2023) Where attribute-based access control (ABAC) is in use, an adversary with sufficient permissions may modify a Kubernetes ABAC policy to give the target account additional permissions.(Citation: Kuberentes ABAC)",
            insertText: 'T1098.006',
            range: range,
        }
        ,
        {
            label: 'Additional Local or Domain Groups',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may add additional local or domain groups to an adversary-controlled account to maintain persistent access to a system or domain.",
            insertText: 'T1098.007',
            range: range,
        }
        ,
        {
            label: 'Direct Volume Access',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may directly access a volume to bypass file access controls and file system monitoring. Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write files directly from the drive by analyzing file system data structures. This technique may bypass Windows file access controls as well as file system monitoring tools. (Citation: Hakobyan 2009)",
            insertText: 'T1006',
            range: range,
        }
        ,
        {
            label: 'Binary Padding',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries can use binary padding to add junk data and change the on-disk representation of malware without affecting the functionality or behavior of the binary. This will often increase the size of the binary beyond what some security tools are capable of handling due to file size limitations.",
            insertText: 'T1009',
            range: range,
        }
        ,
        {
            label: 'Rootkit',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use rootkits to hide the presence of programs, files, network connections, services, drivers, and other system components. Rootkits are programs that hide the existence of malware by intercepting/hooking and modifying operating system API calls that supply system information. (Citation: Symantec Windows Rootkits)",
            insertText: 'T1014',
            range: range,
        }
        ,
        {
            label: 'Software Packing',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Software packing is a method of compressing or encrypting an executable. Packing an executable changes the file signature in an attempt to avoid signature-based detection. Most decompression techniques decompress the executable code in memory.",
            insertText: 'T1045',
            range: range,
        }
        ,
        {
            label: 'Indicator Blocking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may attempt to block indicators or events typically captured by sensors from being gathered and analyzed. This could include maliciously redirecting (Citation: Microsoft Lamin Sept 2017) or even disabling host-based sensors, such as Event Tracing for Windows (ETW),(Citation: Microsoft About Event Tracing 2018) by tampering settings that control the collection and flow of event telemetry. (Citation: Medium Event Tracing Tampering 2018) These settings may be stored on the system in configuration files and/or in the Registry as well as being accessible via administrative utilities such as [PowerShell](https://attack.mitre.org/techniques/T1086) or [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047).",
            insertText: 'T1054',
            range: range,
        }
        ,
        {
            label: 'Indicator Removal from Tools',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "If a malicious tool is detected and quarantined or otherwise curtailed, an adversary may be able to determine why the malicious tool was detected (the indicator), modify the tool by removing the indicator, and use the updated version that is no longer detected by the target's defensive systems or subsequent targets that may use similar systems.",
            insertText: 'T1066',
            range: range,
        }
        ,
        {
            label: 'DLL Side-Loading',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Programs may specify DLLs that are loaded at runtime. Programs that improperly or vaguely specify a required DLL may be open to a vulnerability in which an unintended DLL is loaded. Side-loading vulnerabilities specifically occur when Windows Side-by-Side (WinSxS) manifests (Citation: MSDN Manifests) are not explicit enough about characteristics of the DLL to be loaded. Adversaries may take advantage of a legitimate program that is vulnerable to side-loading to load a malicious DLL. (Citation: Stewart 2014)",
            insertText: 'T1073',
            range: range,
        }
        ,
        {
            label: 'Disabling Security Tools',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may disable security tools to avoid possible detection of their tools and activities. This can take the form of killing security software or event logging processes, deleting Registry keys so that tools do not start at run time, or other methods to interfere with security scanning or event reporting.",
            insertText: 'T1089',
            range: range,
        }
        ,
        {
            label: 'Process Hollowing',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Process hollowing occurs when a process is created in a suspended state then its memory is unmapped and replaced with malicious code. Similar to [Process Injection](https://attack.mitre.org/techniques/T1055), execution of the malicious code is masked under a legitimate process and may evade defenses and detection analysis. (Citation: Leitch Hollowing) (Citation: Elastic Process Injection July 2017)",
            insertText: 'T1093',
            range: range,
        }
        ,
        {
            label: 'NTFS File Attributes',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Every New Technology File System (NTFS) formatted partition contains a Master File Table (MFT) that maintains a record for every file/directory on the partition. (Citation: SpectorOps Host-Based Jul 2017) Within MFT entries are file attributes, (Citation: Microsoft NTFS File Attributes Aug 2010) such as Extended Attributes (EA) and Data [known as Alternate Data Streams (ADSs) when more than one Data attribute is present], that can be used to store arbitrary data (and even complete files). (Citation: SpectorOps Host-Based Jul 2017) (Citation: Microsoft File Streams) (Citation: MalwareBytes ADS July 2015) (Citation: Microsoft ADS Mar 2014)",
            insertText: 'T1096',
            range: range,
        }
        ,
        {
            label: 'Timestomp',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may take actions to hide the deployment of new, or modification of existing files to obfuscate their activities. Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times), often to mimic files that are in the same folder. This is done, for example, on files that have been modified or created by the adversary so that they do not appear conspicuous to forensic investigators or file analysis tools. Timestomping may be used along with file name [Masquerading](https://attack.mitre.org/techniques/T1036) to hide malware and tools. (Citation: WindowsIR Anti-Forensic Techniques)",
            insertText: 'T1099',
            range: range,
        }
        ,
        {
            label: 'File Deletion',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may delete files left behind by the actions of their intrusion activity. Malware, tools, or other non-native files dropped or created on a system by an adversary may leave traces to indicate to what was done within a network and how. Removal of these files can occur during an intrusion, or as part of a post-intrusion process to minimize the adversary's footprint.",
            insertText: 'T1107',
            range: range,
        }
        ,
        {
            label: 'Modify Registry',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in persistence and execution.",
            insertText: 'T1112',
            range: range,
        }
        ,
        {
            label: 'Code Signing',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with. (Citation: Wikipedia Code Signing) However, adversaries are known to use code signing certificates to masquerade malware and tools as legitimate binaries (Citation: Janicab). The certificates used during an operation may be created, forged, or stolen by the adversary. (Citation: Securelist Digital Certificates) (Citation: Symantec Digital Certificates)",
            insertText: 'T1116',
            range: range,
        }
        ,
        {
            label: 'Network Share Connection Removal',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation. Windows shared drive and [Windows Admin Shares](https://attack.mitre.org/techniques/T1077) connections can be removed when no longer needed. [Net](https://attack.mitre.org/software/S0039) is an example utility that can be used to remove network share connections with the <code>net use \\\\system\\share /delete</code> command. (Citation: Technet Net Use)",
            insertText: 'T1126',
            range: range,
        }
        ,
        {
            label: 'Install Root Certificate',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Root certificates are used in public key cryptography to identify a root certificate authority (CA). When a root certificate is installed, the system or application will trust certificates in the root's chain of trust that have been signed by the root certificate. (Citation: Wikipedia Root Certificate) Certificates are commonly used for establishing secure TLS/SSL communications within a web browser. When a user attempts to browse a website that presents a certificate that is not trusted an error message will be displayed to warn the user of the security risk. Depending on the security settings, the browser may not allow the user to establish a connection to the website.",
            insertText: 'T1130',
            range: range,
        }
        ,
        {
            label: 'Deobfuscate/Decode Files or Information',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027) to hide artifacts of an intrusion from analysis. They may require separate mechanisms to decode or deobfuscate that information depending on how they intend to use it. Methods for doing that include built-in functionality of malware or by using utilities present on the system.",
            insertText: 'T1140',
            range: range,
        }
        ,
        {
            label: 'Hidden Window',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may implement hidden windows to conceal malicious activity from the plain sight of users. In some cases, windows that would typically be displayed when an application carries out an operation can be hidden. This may be utilized by system administrators to avoid disrupting user work environments when carrying out administrative tasks. Adversaries may abuse operating system functionality to hide otherwise visible windows from users so as not to alert the user to adversary activity on the system.",
            insertText: 'T1143',
            range: range,
        }
        ,
        {
            label: 'Gatekeeper Bypass',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "In macOS and OS X, when applications or programs are downloaded from the internet, there is a special attribute set on the file called <code>com.apple.quarantine</code>. This attribute is read by Apple's Gatekeeper defense program at execution time and provides a prompt to the user to allow or deny execution.",
            insertText: 'T1144',
            range: range,
        }
        ,
        {
            label: 'Clear Command History',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "In addition to clearing system logs, an adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion. macOS and Linux both keep track of the commands users type in their terminal so that users can retrace what they've done. These logs can be accessed in a few different ways. While logged in, this command history is tracked in a file pointed to by the environment variable <code>HISTFILE</code>. When a user logs off a system, this information is flushed to a file in the user's home directory called <code>~/.bash_history</code>. The benefit of this is that it allows users to go back to commands they've used before in different sessions. Since everything typed on the command-line is saved, passwords passed in on the command line are also saved. Adversaries can abuse this by searching these files for cleartext passwords. Additionally, adversaries can use a variety of methods to prevent their own commands from appear in these logs such as <code>unset HISTFILE</code>, <code>export HISTFILESIZE=0</code>, <code>history -c</code>, <code>rm ~/.bash_history</code>.",
            insertText: 'T1146',
            range: range,
        }
        ,
        {
            label: 'Hidden Users',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Every user account in macOS has a userID associated with it. When creating a user, you can specify the userID for that account. There is a property value in <code>/Library/Preferences/com.apple.loginwindow</code> called <code>Hide500Users</code> that prevents users with userIDs 500 and lower from appearing at the login screen. By using the [Create Account](https://attack.mitre.org/techniques/T1136) technique with a userID under 500 and enabling this property (setting it to Yes), an adversary can hide their user accounts much more easily: <code>sudo dscl . -create /Users/username UniqueID 401</code> (Citation: Cybereason OSX Pirrit).",
            insertText: 'T1147',
            range: range,
        }
        ,
        {
            label: 'HISTCONTROL',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "The <code>HISTCONTROL</code> environment variable keeps track of what should be saved by the <code>history</code> command and eventually into the <code>~/.bash_history</code> file when a user logs out. This setting can be configured to ignore commands that start with a space by simply setting it to \"ignorespace\". <code>HISTCONTROL</code> can also be set to ignore duplicate commands by setting it to \"ignoredups\". In some Linux systems, this is set by default to \"ignoreboth\" which covers both of the previous examples. This means that \u201c ls\u201d will not be saved, but \u201cls\u201d would be saved by history. <code>HISTCONTROL</code> does not exist by default on macOS, but can be set by the user and will be respected. Adversaries can use this to operate without leaving traces by simply prepending a space to all of their terminal commands.",
            insertText: 'T1148',
            range: range,
        }
        ,
        {
            label: 'LC_MAIN Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "**This technique has been deprecated and should no longer be used.**",
            insertText: 'T1149',
            range: range,
        }
        ,
        {
            label: 'Process Doppelgänging',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Windows Transactional NTFS (TxF) was introduced in Vista as a method to perform safe file operations. (Citation: Microsoft TxF) To ensure data integrity, TxF enables only one transacted handle to write to a file at a given time. Until the write handle transaction is terminated, all other handles are isolated from the writer and may only read the committed version of the file that existed at the time the handle was opened. (Citation: Microsoft Basic TxF Concepts) To avoid corruption, TxF performs an automatic rollback if the system or application fails during a write transaction. (Citation: Microsoft Where to use TxF)",
            insertText: 'T1186',
            range: range,
        }
        ,
        {
            label: 'Indirect Command Execution',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse utilities that allow for command execution to bypass security restrictions that limit the use of command-line interpreters. Various Windows utilities may be used to execute commands, possibly without invoking [cmd](https://attack.mitre.org/software/S0106). For example, [Forfiles](https://attack.mitre.org/software/S0193), the Program Compatibility Assistant (pcalua.exe), components of the Windows Subsystem for Linux (WSL), as well as other utilities may invoke the execution of programs and commands from a [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059), Run window, or via scripts. (Citation: VectorSec ForFiles Aug 2017) (Citation: Evi1cg Forfiles Nov 2017)",
            insertText: 'T1202',
            range: range,
        }
        ,
        {
            label: 'Rogue Domain Controller',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may register a rogue Domain Controller to enable manipulation of Active Directory data. DCShadow may be used to create a rogue Domain Controller (DC). DCShadow is a method of manipulating Active Directory (AD) data, including objects and schemas, by registering (or reusing an inactive registration) and simulating the behavior of a DC. (Citation: DCShadow Blog) Once registered, a rogue DC may be able to inject and replicate changes into AD infrastructure for any domain object, including credentials and keys.",
            insertText: 'T1207',
            range: range,
        }
        ,
        {
            label: 'Exploitation for Defense Evasion',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may exploit a system or application vulnerability to bypass security features. Exploitation of a vulnerability occurs when an adversary takes advantage of a programming error in a program, service, or within the operating system software or kernel itself to execute adversary-controlled code.\u00a0Vulnerabilities may exist in defensive security software that can be used to disable or circumvent them.",
            insertText: 'T1211',
            range: range,
        }
        ,
        {
            label: 'XSL Script Processing',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may bypass application control and obscure execution of code by embedding scripts inside XSL files. Extensible Stylesheet Language (XSL) files are commonly used to describe the processing and rendering of data within XML files. To support complex operations, the XSL standard includes support for embedded scripting in various languages. (Citation: Microsoft XSLT Script Mar 2017)",
            insertText: 'T1220',
            range: range,
        }
        ,
        {
            label: 'Template Injection',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create or modify references in user document templates to conceal malicious code or force authentication attempts. For example, Microsoft\u2019s Office Open XML (OOXML) specification defines an XML-based format for Office documents (.docx, xlsx, .pptx) to replace older binary formats (.doc, .xls, .ppt). OOXML files are packed together ZIP archives compromised of various XML files, referred to as parts, containing properties that collectively define how a document is rendered.(Citation: Microsoft Open XML July 2017)",
            insertText: 'T1221',
            range: range,
        }
        ,
        {
            label: 'Compile After Delivery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code. Similar to [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027), text-based source code files may subvert analysis and scrutiny from protections targeting executables/binaries. These payloads will need to be compiled before execution; typically via native utilities such as csc.exe or GCC/MinGW.(Citation: ClearSky MuddyWater Nov 2018)",
            insertText: 'T1500',
            range: range,
        }
        ,
        {
            label: 'Unused/Unsupported Cloud Regions',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create cloud instances in unused geographic service regions in order to evade detection. Access is usually obtained through compromising accounts used to manage cloud infrastructure.",
            insertText: 'T1535',
            range: range,
        }
        ,
        {
            label: 'Revert Cloud Instance',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may revert changes made to a cloud instance after they have performed malicious activities in attempt to evade detection and remove evidence of their presence. In highly virtualized environments, such as cloud-based infrastructure, this may be accomplished by restoring virtual machine (VM) or data storage snapshots through the cloud management dashboard or cloud APIs.",
            insertText: 'T1536',
            range: range,
        }
        ,
        {
            label: 'Build Image on Host',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may build a container image directly on a host to bypass defenses that monitor for the retrieval of malicious images from a public registry. A remote <code>build</code> request may be sent to the Docker API that includes a Dockerfile that pulls a vanilla base image, such as alpine, from a public or local registry and then builds a custom image upon it.(Citation: Docker Build Image)",
            insertText: 'T1612',
            range: range,
        }
        ,
        {
            label: 'Reflective Code Loading',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may reflectively load code into a process in order to conceal the execution of malicious payloads. Reflective loading involves allocating then executing payloads directly within the memory of the process, vice creating a thread or process backed by a file path on disk (e.g., [Shared Modules](https://attack.mitre.org/techniques/T1129)).",
            insertText: 'T1620',
            range: range,
        }
        ,
        {
            label: 'Plist File Modification',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify property list files (plist files) to enable other malicious activity, while also potentially evading and bypassing system defenses. macOS applications use plist files, such as the <code>info.plist</code> file, to store properties and configuration settings that inform the operating system how to handle the application at runtime. Plist files are structured metadata in key-value pairs formatted in XML based on Apple's Core Foundation DTD. Plist files can be saved in text or binary format.(Citation: fileinfo plist file description)",
            insertText: 'T1647',
            range: range,
        }
        ,
        {
            label: 'Impersonation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may impersonate a trusted person or organization in order to persuade and trick a target into performing some action on their behalf. For example, adversaries may communicate with victims (via [Phishing for Information](https://attack.mitre.org/techniques/T1598), [Phishing](https://attack.mitre.org/techniques/T1566), or [Internal Spearphishing](https://attack.mitre.org/techniques/T1534)) while impersonating a known sender such as an executive, colleague, or third-party vendor. Established trust can then be leveraged to accomplish an adversary\u2019s ultimate goals, possibly against multiple victims.",
            insertText: 'T1656',
            range: range,
        }
        ,
        {
            label: 'Modify Cloud Resource Hierarchy',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to modify hierarchical structures in infrastructure-as-a-service (IaaS) environments in order to evade defenses.",
            insertText: 'T1666',
            range: range,
        }
        ,
        {
            label: 'Network Boundary Bridging',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may bridge network boundaries by compromising perimeter network devices or internal devices responsible for network segmentation. Breaching these devices may enable an adversary to bypass restrictions on traffic routing that otherwise separate trusted and untrusted networks.",
            insertText: 'T1599',
            range: range,
        }
        ,
        {
            label: 'Network Address Translation Traversal',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may bridge network boundaries by modifying a network device\u2019s Network Address Translation (NAT) configuration. Malicious modifications to NAT may enable an adversary to bypass restrictions on traffic routing that otherwise separate trusted and untrusted networks.",
            insertText: 'T1599.001',
            range: range,
        }
        ,
        {
            label: 'Trusted Developer Utilities Proxy Execution',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may take advantage of trusted developer utilities to proxy execution of malicious payloads. There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering.(Citation: engima0x3 DNX Bypass)(Citation: engima0x3 RCSI Bypass)(Citation: Exploit Monday WinDbg)(Citation: LOLBAS Tracker) These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application control solutions.",
            insertText: 'T1127',
            range: range,
        }
        ,
        {
            label: 'MSBuild',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use MSBuild to proxy execution of code through a trusted Windows utility. MSBuild.exe (Microsoft Build Engine) is a software build platform used by Visual Studio. It handles XML formatted project files that define requirements for loading and building various platforms and configurations.(Citation: MSDN MSBuild)",
            insertText: 'T1127.001',
            range: range,
        }
        ,
        {
            label: 'ClickOnce',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use ClickOnce applications (.appref-ms and .application files) to proxy execution of code through a trusted Windows utility.(Citation: Burke/CISA ClickOnce BlackHat) ClickOnce is a deployment that enables a user to create self-updating Windows-based .NET applications (i.e, .XBAP, .EXE, or .DLL) that install and run from a file share or web page with minimal user interaction. The application launches as a child process of DFSVC.EXE, which is responsible for installing, launching, and updating the application.(Citation: SpectorOps Medium ClickOnce)",
            insertText: 'T1127.002',
            range: range,
        }
        ,
        {
            label: 'File and Directory Permissions Modification',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files.(Citation: Hybrid Analysis Icacls1 June 2018)(Citation: Hybrid Analysis Icacls2 May 2018) File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).",
            insertText: 'T1222',
            range: range,
        }
        ,
        {
            label: 'Windows File and Directory Permissions Modification',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files.(Citation: Hybrid Analysis Icacls1 June 2018)(Citation: Hybrid Analysis Icacls2 May 2018) File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).",
            insertText: 'T1222.001',
            range: range,
        }
        ,
        {
            label: 'Linux and Mac File and Directory Permissions Modification',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files.(Citation: Hybrid Analysis Icacls1 June 2018)(Citation: Hybrid Analysis Icacls2 May 2018) File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).",
            insertText: 'T1222.002',
            range: range,
        }
        ,
        {
            label: 'Execution Guardrails',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use execution guardrails to constrain execution or actions based on adversary supplied and environment specific conditions that are expected to be present on the target. Guardrails ensure that a payload only executes against an intended target and reduces collateral damage from an adversary\u2019s campaign.(Citation: FireEye Kevin Mandia Guardrails) Values an adversary can provide about a target system or environment to use as guardrails may include specific network share names, attached physical devices, files, joined Active Directory (AD) domains, and local/external IP addresses.(Citation: FireEye Outlook Dec 2019)",
            insertText: 'T1480',
            range: range,
        }
        ,
        {
            label: 'Environmental Keying',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may environmentally key payloads or other features of malware to evade defenses and constraint execution to a specific target environment. Environmental keying uses cryptography to constrain execution or actions based on adversary supplied environment specific conditions that are expected to be present on the target. Environmental keying is an implementation of [Execution Guardrails](https://attack.mitre.org/techniques/T1480) that utilizes cryptographic techniques for deriving encryption/decryption keys from specific types of values in a given computing environment.(Citation: EK Clueless Agents)",
            insertText: 'T1480.001',
            range: range,
        }
        ,
        {
            label: 'Mutual Exclusion',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may constrain execution or actions based on the presence of a mutex associated with malware. A mutex is a locking mechanism used to synchronize access to a resource. Only one thread or process can acquire a mutex at a given time.(Citation: Microsoft Mutexes)",
            insertText: 'T1480.002',
            range: range,
        }
        ,
        {
            label: 'Weaken Encryption',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may compromise a network device\u2019s encryption capability in order to bypass encryption that would otherwise protect data communications. (Citation: Cisco Synful Knock Evolution)",
            insertText: 'T1600',
            range: range,
        }
        ,
        {
            label: 'Reduce Key Space',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may reduce the level of effort required to decrypt data transmitted over the network by reducing the cipher strength of encrypted communications.(Citation: Cisco Synful Knock Evolution)",
            insertText: 'T1600.001',
            range: range,
        }
        ,
        {
            label: 'Disable Crypto Hardware',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries disable a network device\u2019s dedicated hardware encryption, which may enable them to leverage weaknesses in software encryption in order to reduce the effort involved in collecting, manipulating, and exfiltrating transmitted data.",
            insertText: 'T1600.002',
            range: range,
        }
        ,
        {
            label: 'Modify System Image',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may make changes to the operating system of embedded network devices to weaken defenses and provide new capabilities for themselves.  On such devices, the operating systems are typically monolithic and most of the device functionality and capabilities are contained within a single file.",
            insertText: 'T1601',
            range: range,
        }
        ,
        {
            label: 'Patch System Image',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify the operating system of a network device to introduce new capabilities or weaken existing defenses.(Citation: Killing the myth of Cisco IOS rootkits) (Citation: Killing IOS diversity myth) (Citation: Cisco IOS Shellcode) (Citation: Cisco IOS Forensics Developments) (Citation: Juniper Netscreen of the Dead) Some network devices are built with a monolithic architecture, where the entire operating system and most of the functionality of the device is contained within a single file.  Adversaries may change this file in storage, to be loaded in a future boot, or in memory during runtime.",
            insertText: 'T1601.001',
            range: range,
        }
        ,
        {
            label: 'Downgrade System Image',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may install an older version of the operating system of a network device to weaken security.  Older operating system versions on network devices often have weaker encryption ciphers and, in general, fewer/less updated defensive features. (Citation: Cisco Synful Knock Evolution)",
            insertText: 'T1601.002',
            range: range,
        }
        ,
        {
            label: 'Virtualization/Sandbox Evasion',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may employ various means to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) during automated discovery to shape follow-on behaviors.(Citation: Deloitte Environment Awareness)",
            insertText: 'T1497',
            range: range,
        }
        ,
        {
            label: 'System Checks',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may employ various system checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) during automated discovery to shape follow-on behaviors.(Citation: Deloitte Environment Awareness)",
            insertText: 'T1497.001',
            range: range,
        }
        ,
        {
            label: 'User Activity Based Checks',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may employ various user activity checks to detect and avoid virtualization and analysis environments. This may include changing behaviors based on the results of checks for the presence of artifacts indicative of a virtual machine environment (VME) or sandbox. If the adversary detects a VME, they may alter their malware to disengage from the victim or conceal the core functions of the implant. They may also search for VME artifacts before dropping secondary or additional payloads. Adversaries may use the information learned from [Virtualization/Sandbox Evasion](https://attack.mitre.org/techniques/T1497) during automated discovery to shape follow-on behaviors.(Citation: Deloitte Environment Awareness)",
            insertText: 'T1497.002',
            range: range,
        }
        ,
        {
            label: 'Time Based Evasion',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may employ various time-based methods to detect and avoid virtualization and analysis environments. This may include enumerating time-based properties, such as uptime or the system clock, as well as the use of timers or other triggers to avoid a virtual machine environment (VME) or sandbox, specifically those that are automated or only operate for a limited amount of time.",
            insertText: 'T1497.003',
            range: range,
        }
        ,
        {
            label: 'Modify Cloud Compute Infrastructure',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may attempt to modify a cloud account's compute service infrastructure to evade defenses. A modification to the compute service infrastructure can include the creation, deletion, or modification of one or more components such as compute instances, virtual machines, and snapshots.",
            insertText: 'T1578',
            range: range,
        }
        ,
        {
            label: 'Create Snapshot',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may create a snapshot or data backup within a cloud account to evade defenses. A snapshot is a point-in-time copy of an existing cloud compute component such as a virtual machine (VM), virtual hard drive, or volume. An adversary may leverage permissions to create a snapshot in order to bypass restrictions that prevent access to existing compute service infrastructure, unlike in [Revert Cloud Instance](https://attack.mitre.org/techniques/T1578/004) where an adversary may revert to a snapshot to evade detection and remove evidence of their presence.",
            insertText: 'T1578.001',
            range: range,
        }
        ,
        {
            label: 'Create Cloud Instance',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may create a new instance or virtual machine (VM) within the compute service of a cloud account to evade defenses. Creating a new instance may allow an adversary to bypass firewall rules and permissions that exist on instances currently residing within an account. An adversary may [Create Snapshot](https://attack.mitre.org/techniques/T1578/001) of one or more volumes in an account, create a new instance, mount the snapshots, and then apply a less restrictive security policy to collect [Data from Local System](https://attack.mitre.org/techniques/T1005) or for [Remote Data Staging](https://attack.mitre.org/techniques/T1074/002).(Citation: Mandiant M-Trends 2020)",
            insertText: 'T1578.002',
            range: range,
        }
        ,
        {
            label: 'Delete Cloud Instance',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may delete a cloud instance after they have performed malicious activities in an attempt to evade detection and remove evidence of their presence.  Deleting an instance or virtual machine can remove valuable forensic artifacts and other evidence of suspicious behavior if the instance is not recoverable.",
            insertText: 'T1578.003',
            range: range,
        }
        ,
        {
            label: 'Revert Cloud Instance',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may revert changes made to a cloud instance after they have performed malicious activities in attempt to evade detection and remove evidence of their presence. In highly virtualized environments, such as cloud-based infrastructure, this may be accomplished by restoring virtual machine (VM) or data storage snapshots through the cloud management dashboard or cloud APIs.",
            insertText: 'T1578.004',
            range: range,
        }
        ,
        {
            label: 'Modify Cloud Compute Configurations',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify settings that directly affect the size, locations, and resources available to cloud compute infrastructure in order to evade defenses. These settings may include service quotas, subscription associations, tenant-wide policies, or other configurations that impact available compute. Such modifications may allow adversaries to abuse the victim\u2019s compute resources to achieve their goals, potentially without affecting the execution of running instances and/or revealing their activities to the victim.",
            insertText: 'T1578.005',
            range: range,
        }
        ,
        {
            label: 'Subvert Trust Controls',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may undermine security controls that will either warn users of untrusted activity or prevent execution of untrusted programs. Operating systems and security products may contain mechanisms to identify programs or websites as possessing some level of trust. Examples of such features would include a program being allowed to run because it is signed by a valid code signing certificate, a program prompting the user with a warning because it has an attribute set from being downloaded from the Internet, or getting an indication that you are about to connect to an untrusted site.",
            insertText: 'T1553',
            range: range,
        }
        ,
        {
            label: 'Gatekeeper Bypass',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify file attributes and subvert Gatekeeper functionality to evade user prompts and execute untrusted programs. Gatekeeper is a set of technologies that act as layer of Apple\u2019s security model to ensure only trusted applications are executed on a host. Gatekeeper was built on top of File Quarantine in Snow Leopard (10.6, 2009) and has grown to include Code Signing, security policy compliance, Notarization, and more. Gatekeeper also treats applications running for the first time differently than reopened applications.(Citation: TheEclecticLightCompany Quarantine and the flag)(Citation: TheEclecticLightCompany apple notarization )",
            insertText: 'T1553.001',
            range: range,
        }
        ,
        {
            label: 'Code Signing',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may create, acquire, or steal code signing materials to sign their malware or tools. Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with. (Citation: Wikipedia Code Signing) The certificates used during an operation may be created, acquired, or stolen by the adversary. (Citation: Securelist Digital Certificates) (Citation: Symantec Digital Certificates) Unlike [Invalid Code Signature](https://attack.mitre.org/techniques/T1036/001), this activity will result in a valid signature.",
            insertText: 'T1553.002',
            range: range,
        }
        ,
        {
            label: 'SIP and Trust Provider Hijacking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may tamper with SIP and trust provider components to mislead the operating system and application control tools when conducting signature validation checks. In user mode, Windows Authenticode (Citation: Microsoft Authenticode) digital signatures are used to verify a file's origin and integrity, variables that may be used to establish trust in signed code (ex: a driver with a valid Microsoft signature may be handled as safe). The signature validation process is handled via the WinVerifyTrust application programming interface (API) function,  (Citation: Microsoft WinVerifyTrust) which accepts an inquiry and coordinates with the appropriate trust provider, which is responsible for validating parameters of a signature. (Citation: SpectorOps Subverting Trust Sept 2017)",
            insertText: 'T1553.003',
            range: range,
        }
        ,
        {
            label: 'Install Root Certificate',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may install a root certificate on a compromised system to avoid warnings when connecting to adversary controlled web servers. Root certificates are used in public key cryptography to identify a root certificate authority (CA). When a root certificate is installed, the system or application will trust certificates in the root's chain of trust that have been signed by the root certificate.(Citation: Wikipedia Root Certificate) Certificates are commonly used for establishing secure TLS/SSL communications within a web browser. When a user attempts to browse a website that presents a certificate that is not trusted an error message will be displayed to warn the user of the security risk. Depending on the security settings, the browser may not allow the user to establish a connection to the website.",
            insertText: 'T1553.004',
            range: range,
        }
        ,
        {
            label: 'Mark-of-the-Web Bypass',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse specific file formats to subvert Mark-of-the-Web (MOTW) controls. In Windows, when files are downloaded from the Internet, they are tagged with a hidden NTFS Alternate Data Stream (ADS) named <code>Zone.Identifier</code> with a specific value known as the MOTW.(Citation: Microsoft Zone.Identifier 2020) Files that are tagged with MOTW are protected and cannot perform certain actions. For example, starting in MS Office 10, if a MS Office file has the MOTW, it will open in Protected View. Executables tagged with the MOTW will be processed by Windows Defender SmartScreen that compares files with an allowlist of well-known executables. If the file is not known/trusted, SmartScreen will prevent the execution and warn the user not to run it.(Citation: Beek Use of VHD Dec 2020)(Citation: Outflank MotW 2020)(Citation: Intezer Russian APT Dec 2020)",
            insertText: 'T1553.005',
            range: range,
        }
        ,
        {
            label: 'Code Signing Policy Modification',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify code signing policies to enable execution of unsigned or self-signed code. Code signing provides a level of authenticity on a program from a developer and a guarantee that the program has not been tampered with. Security controls can include enforcement mechanisms to ensure that only valid, signed code can be run on an operating system.",
            insertText: 'T1553.006',
            range: range,
        }
        ,
        {
            label: 'Masquerading',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign to users and/or security tools. Masquerading occurs when the name or location of an object, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. This may include manipulating file metadata, tricking users into misidentifying the file type, and giving legitimate task or service names.",
            insertText: 'T1036',
            range: range,
        }
        ,
        {
            label: 'Invalid Code Signature',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to mimic features of valid code signatures to increase the chance of deceiving a user, analyst, or tool. Code signing provides a level of authenticity on a binary from the developer and a guarantee that the binary has not been tampered with. Adversaries can copy the metadata and signature information from a signed program, then use it as a template for an unsigned program. Files with invalid code signatures will fail digital signature validation checks, but they may appear more legitimate to users and security tools may improperly handle these files.(Citation: Threatexpress MetaTwin 2017)",
            insertText: 'T1036.001',
            range: range,
        }
        ,
        {
            label: 'Right-to-Left Override',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse the right-to-left override (RTLO or RLO) character (U+202E) to disguise a string and/or file name to make it appear benign. RTLO is a non-printing Unicode character that causes the text that follows it to be displayed in reverse. For example, a Windows screensaver executable named <code>March 25 \\u202Excod.scr</code> will display as <code>March 25 rcs.docx</code>. A JavaScript file named <code>photo_high_re\\u202Egnp.js</code> will be displayed as <code>photo_high_resj.png</code>.(Citation: Infosecinstitute RTLO Technique)",
            insertText: 'T1036.002',
            range: range,
        }
        ,
        {
            label: 'Rename System Utilities',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may rename legitimate system utilities to try to evade security mechanisms concerning the usage of those utilities. Security monitoring and control mechanisms may be in place for system utilities adversaries are capable of abusing. (Citation: LOLBAS Main Site) It may be possible to bypass those security mechanisms by renaming the utility prior to utilization (ex: rename <code>rundll32.exe</code>). (Citation: Elastic Masquerade Ball) An alternative case occurs when a legitimate utility is copied or moved to a different directory and renamed to avoid detections based on system utilities executing from non-standard paths. (Citation: F-Secure CozyDuke)",
            insertText: 'T1036.003',
            range: range,
        }
        ,
        {
            label: 'Masquerade Task or Service',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to manipulate the name of a task or service to make it appear legitimate or benign. Tasks/services executed by the Task Scheduler or systemd will typically be given a name and/or description.(Citation: TechNet Schtasks)(Citation: Systemd Service Units) Windows services will have a service name as well as a display name. Many benign tasks and services exist that have commonly associated names. Adversaries may give tasks or services names that are similar or identical to those of legitimate ones.",
            insertText: 'T1036.004',
            range: range,
        }
        ,
        {
            label: 'Match Legitimate Name or Location',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may match or approximate the name or location of legitimate files or resources when naming/placing them. This is done for the sake of evading defenses and observation. This may be done by placing an executable in a commonly trusted directory (ex: under System32) or giving it the name of a legitimate, trusted program (ex: svchost.exe). In containerized environments, this may also be done by creating a resource in a namespace that matches the naming convention of a container pod or cluster. Alternatively, a file or container image name given may be a close approximation to legitimate programs/images or something innocuous.",
            insertText: 'T1036.005',
            range: range,
        }
        ,
        {
            label: 'Space after Filename',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries can hide a program's true filetype by changing the extension of a file. With certain file types (specifically this does not work with .app extensions), appending a space to the end of a filename will change how the file is processed by the operating system.",
            insertText: 'T1036.006',
            range: range,
        }
        ,
        {
            label: 'Double File Extension',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse a double extension in the filename as a means of masquerading the true file type. A file name may include a secondary file type extension that may cause only the first extension to be displayed (ex: <code>File.txt.exe</code> may render in some views as just <code>File.txt</code>). However, the second extension is the true file type that determines how the file is opened and executed. The real file extension may be hidden by the operating system in the file browser (ex: explorer.exe), as well as in any software configured using or similar to the system\u2019s policies.(Citation: PCMag DoubleExtension)(Citation: SOCPrime DoubleExtension)",
            insertText: 'T1036.007',
            range: range,
        }
        ,
        {
            label: 'Masquerade File Type',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may masquerade malicious payloads as legitimate files through changes to the payload's formatting, including the file\u2019s signature, extension, and contents. Various file types have a typical standard format, including how they are encoded and organized. For example, a file\u2019s signature (also known as header or magic bytes) is the beginning bytes of a file and is often used to identify the file\u2019s type. For example, the header of a JPEG file,  is <code> 0xFF 0xD8</code> and the file extension is either `.JPE`, `.JPEG` or `.JPG`.",
            insertText: 'T1036.008',
            range: range,
        }
        ,
        {
            label: 'Break Process Trees',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may attempt to evade process tree-based analysis by modifying executed malware's parent process ID (PPID). If endpoint protection software leverages the \u201cparent-child\" relationship for detection, breaking this relationship could result in the adversary\u2019s behavior not being associated with previous process tree activity. On Unix-based systems breaking this process tree is common practice for administrators to execute software using scripts and programs.(Citation: 3OHA double-fork 2022)",
            insertText: 'T1036.009',
            range: range,
        }
        ,
        {
            label: 'Masquerade Account Name',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may match or approximate the names of legitimate accounts to make newly created ones appear benign. This will typically occur during [Create Account](https://attack.mitre.org/techniques/T1136), although accounts may also be renamed at a later date. This may also coincide with [Account Access Removal](https://attack.mitre.org/techniques/T1531) if the actor first deletes an account before re-creating one with the same name.(Citation: Huntress MOVEit 2023)",
            insertText: 'T1036.010',
            range: range,
        }
        ,
        {
            label: 'Indicator Removal',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may delete or modify artifacts generated within systems to remove evidence of their presence or hinder defenses. Various artifacts may be created by an adversary or something that can be attributed to an adversary\u2019s actions. Typically these artifacts are used as defensive indicators related to monitored events, such as strings from downloaded files, logs that are generated from user actions, and other data analyzed by defenders. Location, format, and type of artifact (such as command or login history) are often specific to each platform.",
            insertText: 'T1070',
            range: range,
        }
        ,
        {
            label: 'Clear Windows Event Logs',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may clear Windows Event Logs to hide the activity of an intrusion. Windows Event Logs are a record of a computer's alerts and notifications. There are three system-defined sources of events: System, Application, and Security, with five event types: Error, Warning, Information, Success Audit, and Failure Audit.",
            insertText: 'T1070.001',
            range: range,
        }
        ,
        {
            label: 'Clear Linux or Mac System Logs',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may clear system logs to hide evidence of an intrusion. macOS and Linux both keep track of system or user-initiated actions via system logs. The majority of native system logging is stored under the <code>/var/log/</code> directory. Subfolders in this directory categorize logs by their related functions, such as:(Citation: Linux Logs)",
            insertText: 'T1070.002',
            range: range,
        }
        ,
        {
            label: 'Clear Command History',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "In addition to clearing system logs, an adversary may clear the command history of a compromised account to conceal the actions undertaken during an intrusion. Various command interpreters keep track of the commands users type in their terminal so that users can retrace what they've done.",
            insertText: 'T1070.003',
            range: range,
        }
        ,
        {
            label: 'File Deletion',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may delete files left behind by the actions of their intrusion activity. Malware, tools, or other non-native files dropped or created on a system by an adversary (ex: [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)) may leave traces to indicate to what was done within a network and how. Removal of these files can occur during an intrusion, or as part of a post-intrusion process to minimize the adversary's footprint.",
            insertText: 'T1070.004',
            range: range,
        }
        ,
        {
            label: 'Network Share Connection Removal',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may remove share connections that are no longer useful in order to clean up traces of their operation. Windows shared drive and [SMB/Windows Admin Shares](https://attack.mitre.org/techniques/T1021/002) connections can be removed when no longer needed. [Net](https://attack.mitre.org/software/S0039) is an example utility that can be used to remove network share connections with the <code>net use \\\\system\\share /delete</code> command. (Citation: Technet Net Use)",
            insertText: 'T1070.005',
            range: range,
        }
        ,
        {
            label: 'Timestomp',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify file time attributes to hide new or changes to existing files. Timestomping is a technique that modifies the timestamps of a file (the modify, access, create, and change times), often to mimic files that are in the same folder. This is done, for example, on files that have been modified or created by the adversary so that they do not appear conspicuous to forensic investigators or file analysis tools.",
            insertText: 'T1070.006',
            range: range,
        }
        ,
        {
            label: 'Clear Network Connection History and Configurations',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may clear or remove evidence of malicious network connections in order to clean up traces of their operations. Configuration settings as well as various artifacts that highlight connection history may be created on a system and/or in application logs from behaviors that require network connections, such as [Remote Services](https://attack.mitre.org/techniques/T1021) or [External Remote Services](https://attack.mitre.org/techniques/T1133). Defenders may use these artifacts to monitor or otherwise analyze network connections created by adversaries.",
            insertText: 'T1070.007',
            range: range,
        }
        ,
        {
            label: 'Clear Mailbox Data',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify mail and mail application data to remove evidence of their activity. Email applications allow users and other programs to export and delete mailbox data via command line tools or use of APIs. Mail application data can be emails, email metadata, or logs generated by the application or operating system, such as export requests.",
            insertText: 'T1070.008',
            range: range,
        }
        ,
        {
            label: 'Clear Persistence',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may clear artifacts associated with previously established persistence on a host system to remove evidence of their activity. This may involve various actions, such as removing services, deleting executables, [Modify Registry](https://attack.mitre.org/techniques/T1112), [Plist File Modification](https://attack.mitre.org/techniques/T1647), or other methods of cleanup to prevent defenders from collecting evidence of their persistent presence.(Citation: Cylance Dust Storm) Adversaries may also delete accounts previously created to maintain persistence (i.e. [Create Account](https://attack.mitre.org/techniques/T1136)).(Citation: Talos - Cisco Attack 2022)",
            insertText: 'T1070.009',
            range: range,
        }
        ,
        {
            label: 'Relocate Malware',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Once a payload is delivered, adversaries may reproduce copies of the same malware on the victim system to remove evidence of their presence and/or avoid defenses. Copying malware payloads to new locations may also be combined with [File Deletion](https://attack.mitre.org/techniques/T1070/004) to cleanup older artifacts.",
            insertText: 'T1070.010',
            range: range,
        }
        ,
        {
            label: 'Impair Defenses',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may maliciously modify components of a victim environment in order to hinder or disable defensive mechanisms. This not only involves impairing preventative defenses, such as firewalls and anti-virus, but also detection capabilities that defenders can use to audit activity and identify malicious behavior. This may also span both native defenses as well as supplemental capabilities installed by users and administrators.",
            insertText: 'T1562',
            range: range,
        }
        ,
        {
            label: 'Disable or Modify Tools',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may modify and/or disable security tools to avoid possible detection of their malware/tools and activities. This may take many forms, such as killing security software processes or services, modifying / deleting Registry keys or configuration files so that tools do not operate properly, or other methods to interfere with security tools scanning or reporting information. Adversaries may also disable updates to prevent the latest security patches from reaching tools on victim systems.(Citation: SCADAfence_ransomware)",
            insertText: 'T1562.001',
            range: range,
        }
        ,
        {
            label: 'Disable Windows Event Logging',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may disable Windows event logging to limit data that can be leveraged for detections and audits. Windows event logs record user and system activity such as login attempts, process creation, and much more.(Citation: Windows Log Events) This data is used by security tools and analysts to generate detections.",
            insertText: 'T1562.002',
            range: range,
        }
        ,
        {
            label: 'Impair Command History Logging',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may impair command history logging to hide commands they run on a compromised system. Various command interpreters keep track of the commands users type in their terminal so that users can retrace what they've done.",
            insertText: 'T1562.003',
            range: range,
        }
        ,
        {
            label: 'Disable or Modify System Firewall',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage. Changes could be disabling the entire mechanism as well as adding, deleting, or modifying particular rules. This can be done numerous ways depending on the operating system, including via command-line, editing Windows Registry keys, and Windows Control Panel.",
            insertText: 'T1562.004',
            range: range,
        }
        ,
        {
            label: 'Indicator Blocking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may attempt to block indicators or events typically captured by sensors from being gathered and analyzed. This could include maliciously redirecting(Citation: Microsoft Lamin Sept 2017) or even disabling host-based sensors, such as Event Tracing for Windows (ETW)(Citation: Microsoft About Event Tracing 2018), by tampering settings that control the collection and flow of event telemetry.(Citation: Medium Event Tracing Tampering 2018) These settings may be stored on the system in configuration files and/or in the Registry as well as being accessible via administrative utilities such as [PowerShell](https://attack.mitre.org/techniques/T1059/001) or [Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047).",
            insertText: 'T1562.006',
            range: range,
        }
        ,
        {
            label: 'Disable or Modify Cloud Firewall',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may disable or modify a firewall within a cloud environment to bypass controls that limit access to cloud resources. Cloud firewalls are separate from system firewalls that are described in [Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1562/004).",
            insertText: 'T1562.007',
            range: range,
        }
        ,
        {
            label: 'Disable or Modify Cloud Logs',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "An adversary may disable or modify cloud logging capabilities and integrations to limit what data is collected on their activities and avoid detection. Cloud environments allow for collection and analysis of audit and application logs that provide insight into what activities a user does within the environment. If an adversary has sufficient permissions, they can disable or modify logging to avoid detection of their activities.",
            insertText: 'T1562.008',
            range: range,
        }
        ,
        {
            label: 'Safe Mode Boot',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse Windows safe mode to disable endpoint defenses. Safe mode starts up the Windows operating system with a limited set of drivers and services. Third-party security software such as endpoint detection and response (EDR) tools may not start after booting Windows in safe mode. There are two versions of safe mode: Safe Mode and Safe Mode with Networking. It is possible to start additional services after a safe mode boot.(Citation: Microsoft Safe Mode)(Citation: Sophos Snatch Ransomware 2019)",
            insertText: 'T1562.009',
            range: range,
        }
        ,
        {
            label: 'Downgrade Attack',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may downgrade or use a version of system features that may be outdated, vulnerable, and/or does not support updated security controls. Downgrade attacks typically take advantage of a system\u2019s backward compatibility to force it into less secure modes of operation.",
            insertText: 'T1562.010',
            range: range,
        }
        ,
        {
            label: 'Spoof Security Alerting',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may spoof security alerting from tools, presenting false evidence to impair defenders\u2019 awareness of malicious activity.(Citation: BlackBasta) Messages produced by defensive tools contain information about potential security events as well as the functioning status of security software and the system. Security reporting messages are important for monitoring the normal operation of a system and identifying important events that can signal a security incident.",
            insertText: 'T1562.011',
            range: range,
        }
        ,
        {
            label: 'Disable or Modify Linux Audit System',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may disable or modify the Linux audit system to hide malicious activity and avoid detection. Linux admins use the Linux Audit system to track security-relevant information on a system. The Linux Audit system operates at the kernel-level and maintains event logs on application and system activity such as process, network, file, and login events based on pre-configured rules.",
            insertText: 'T1562.012',
            range: range,
        }
        ,
        {
            label: 'Hide Artifacts',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to hide artifacts associated with their behaviors to evade detection. Operating systems may have features to hide various artifacts, such as important system files and administrative task execution, to avoid disrupting user work environments and prevent users from changing files or features on the system. Adversaries may abuse these features to hide artifacts such as files, directories, user accounts, or other system activity to evade detection.(Citation: Sofacy Komplex Trojan)(Citation: Cybereason OSX Pirrit)(Citation: MalwareBytes ADS July 2015)",
            insertText: 'T1564',
            range: range,
        }
        ,
        {
            label: 'Hidden Files and Directories',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may set files and directories to be hidden to evade detection mechanisms. To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a \u2018hidden\u2019 file. These files don\u2019t show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files either via a series of Graphical User Interface (GUI) prompts or with command line switches (<code>dir /a</code> for Windows and <code>ls \u2013a</code> for Linux and macOS).",
            insertText: 'T1564.001',
            range: range,
        }
        ,
        {
            label: 'Hidden Users',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use hidden users to hide the presence of user accounts they create or modify. Administrators may want to hide users when there are many user accounts on a given system or if they want to hide their administrative or other management accounts from other users.",
            insertText: 'T1564.002',
            range: range,
        }
        ,
        {
            label: 'Hidden Window',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use hidden windows to conceal malicious activity from the plain sight of users. In some cases, windows that would typically be displayed when an application carries out an operation can be hidden. This may be utilized by system administrators to avoid disrupting user work environments when carrying out administrative tasks.",
            insertText: 'T1564.003',
            range: range,
        }
        ,
        {
            label: 'NTFS File Attributes',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection. Every New Technology File System (NTFS) formatted partition contains a Master File Table (MFT) that maintains a record for every file/directory on the partition. (Citation: SpectorOps Host-Based Jul 2017) Within MFT entries are file attributes, (Citation: Microsoft NTFS File Attributes Aug 2010) such as Extended Attributes (EA) and Data [known as Alternate Data Streams (ADSs) when more than one Data attribute is present], that can be used to store arbitrary data (and even complete files). (Citation: SpectorOps Host-Based Jul 2017) (Citation: Microsoft File Streams) (Citation: MalwareBytes ADS July 2015) (Citation: Microsoft ADS Mar 2014)",
            insertText: 'T1564.004',
            range: range,
        }
        ,
        {
            label: 'Hidden File System',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use a hidden file system to conceal malicious activity from users and security tools. File systems provide a structure to store and access data from physical storage. Typically, a user engages with a file system through applications that allow them to access files and directories, which are an abstraction from their physical location (ex: disk sector). Standard file systems include FAT, NTFS, ext4, and APFS. File systems can also contain other structures, such as the Volume Boot Record (VBR) and Master File Table (MFT) in NTFS.(Citation: MalwareTech VFS Nov 2014)",
            insertText: 'T1564.005',
            range: range,
        }
        ,
        {
            label: 'Run Virtual Instance',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may carry out malicious operations using a virtual instance to avoid detection. A wide variety of virtualization technologies exist that allow for the emulation of a computer or computing environment. By running malicious code inside of a virtual instance, adversaries can hide artifacts associated with their behavior from security tools that are unable to monitor activity inside the virtual instance. Additionally, depending on the virtual networking implementation (ex: bridged adapter), network traffic generated by the virtual instance can be difficult to trace back to the compromised host as the IP address and hostname might not match known values.(Citation: SingHealth Breach Jan 2019)",
            insertText: 'T1564.006',
            range: range,
        }
        ,
        {
            label: 'VBA Stomping',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may hide malicious Visual Basic for Applications (VBA) payloads embedded within MS Office documents by replacing the VBA source code with benign data.(Citation: FireEye VBA stomp Feb 2020)",
            insertText: 'T1564.007',
            range: range,
        }
        ,
        {
            label: 'Email Hiding Rules',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use email rules to hide inbound emails in a compromised user's mailbox. Many email clients allow users to create inbox rules for various email functions, including moving emails to other folders, marking emails as read, or deleting emails. Rules may be created or modified within email clients or through external features such as the <code>New-InboxRule</code> or <code>Set-InboxRule</code> [PowerShell](https://attack.mitre.org/techniques/T1059/001) cmdlets on Windows systems.(Citation: Microsoft Inbox Rules)(Citation: MacOS Email Rules)(Citation: Microsoft New-InboxRule)(Citation: Microsoft Set-InboxRule)",
            insertText: 'T1564.008',
            range: range,
        }
        ,
        {
            label: 'Resource Forking',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may abuse resource forks to hide malicious code or executables to evade detection and bypass security applications. A resource fork provides applications a structured way to store resources such as thumbnail images, menu definitions, icons, dialog boxes, and code.(Citation: macOS Hierarchical File System Overview) Usage of a resource fork is identifiable when displaying a file\u2019s extended attributes, using <code>ls -l@</code> or <code>xattr -l</code> commands. Resource forks have been deprecated and replaced with the application bundle structure. Non-localized resources are placed at the top level directory of an application bundle, while localized resources are placed in the <code>/Resources</code> folder.(Citation: Resource and Data Forks)(Citation: ELC Extended Attributes)",
            insertText: 'T1564.009',
            range: range,
        }
        ,
        {
            label: 'Process Argument Spoofing',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to hide process command-line arguments by overwriting process memory. Process command-line arguments are stored in the process environment block (PEB), a data structure used by Windows to store various information about/used by a process. The PEB includes the process command-line arguments that are referenced when executing the process. When a process is created, defensive tools/sensors that monitor process creations may retrieve the process arguments from the PEB.(Citation: Microsoft PEB 2021)(Citation: Xpn Argue Like Cobalt 2019)",
            insertText: 'T1564.010',
            range: range,
        }
        ,
        {
            label: 'Ignore Process Interrupts',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may evade defensive mechanisms by executing commands that hide from process interrupt signals. Many operating systems use signals to deliver messages to control process behavior. Command interpreters often include specific commands/flags that ignore errors and other hangups, such as when the user of the active session logs off.(Citation: Linux Signal Man)  These interrupt signals may also be used by defensive tools and/or analysts to pause or terminate specified running processes.",
            insertText: 'T1564.011',
            range: range,
        }
        ,
        {
            label: 'File/Path Exclusions',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to hide their file-based artifacts by writing them to specific folders or file names excluded from antivirus (AV) scanning and other defensive capabilities. AV and other file-based scanners often include exclusions to optimize performance as well as ease installation and legitimate use of applications. These exclusions may be contextual (e.g., scans are only initiated in response to specific triggering events/alerts), but are also often hardcoded strings referencing specific folders and/or files assumed to be trusted and legitimate.(Citation: Microsoft File Folder Exclusions)",
            insertText: 'T1564.012',
            range: range,
        }
        ,
        {
            label: 'Obfuscated Files or Information',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.",
            insertText: 'T1027',
            range: range,
        }
        ,
        {
            label: 'Binary Padding',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use binary padding to add junk data and change the on-disk representation of malware. This can be done without affecting the functionality or behavior of a binary, but can increase the size of the binary beyond what some security tools are capable of handling due to file size limitations.",
            insertText: 'T1027.001',
            range: range,
        }
        ,
        {
            label: 'Software Packing',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may perform software packing or virtual machine software protection to conceal their code. Software packing is a method of compressing or encrypting an executable. Packing an executable changes the file signature in an attempt to avoid signature-based detection. Most decompression techniques decompress the executable code in memory. Virtual machine software protection translates an executable's original code into a special format that only a special virtual machine can run. A virtual machine is then called to run this code.(Citation: ESET FinFisher Jan 2018)",
            insertText: 'T1027.002',
            range: range,
        }
        ,
        {
            label: 'Steganography',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may use steganography techniques in order to prevent the detection of hidden information. Steganographic techniques can be used to hide data in digital media such as images, audio tracks, video clips, or text files.",
            insertText: 'T1027.003',
            range: range,
        }
        ,
        {
            label: 'Compile After Delivery',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to make payloads difficult to discover and analyze by delivering files to victims as uncompiled code. Text-based source code files may subvert analysis and scrutiny from protections targeting executables/binaries. These payloads will need to be compiled before execution; typically via native utilities such as csc.exe or GCC/MinGW.(Citation: ClearSky MuddyWater Nov 2018)",
            insertText: 'T1027.004',
            range: range,
        }
        ,
        {
            label: 'Indicator Removal from Tools',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may remove indicators from tools if they believe their malicious tool was detected, quarantined, or otherwise curtailed. They can modify the tool by removing the indicator and using the updated version that is no longer detected by the target's defensive systems or subsequent targets that may use similar systems.",
            insertText: 'T1027.005',
            range: range,
        }
        ,
        {
            label: 'HTML Smuggling',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may smuggle data and files past content filters by hiding malicious payloads inside of seemingly benign HTML files. HTML documents can store large binary objects known as JavaScript Blobs (immutable data that represents raw bytes) that can later be constructed into file-like objects. Data may also be stored in Data URLs, which enable embedding media type or MIME files inline of HTML documents. HTML5 also introduced a download attribute that may be used to initiate file downloads.(Citation: HTML Smuggling Menlo Security 2020)(Citation: Outlflank HTML Smuggling 2018)",
            insertText: 'T1027.006',
            range: range,
        }
        ,
        {
            label: 'Dynamic API Resolution',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may obfuscate then dynamically resolve API functions called by their malware in order to conceal malicious functionalities and impair defensive analysis. Malware commonly uses various [Native API](https://attack.mitre.org/techniques/T1106) functions provided by the OS to perform various tasks such as those involving processes, files, and other system artifacts.",
            insertText: 'T1027.007',
            range: range,
        }
        ,
        {
            label: 'Stripped Payloads',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may attempt to make a payload difficult to analyze by removing symbols, strings, and other human readable information. Scripts and executables may contain variables names and other strings that help developers document code functionality. Symbols are often created by an operating system\u2019s `linker` when executable payloads are compiled. Reverse engineers use these symbols and strings to analyze code and to identify functionality in payloads.(Citation: Mandiant golang stripped binaries explanation)(Citation: intezer stripped binaries elf files 2018)",
            insertText: 'T1027.008',
            range: range,
        }
        ,
        {
            label: 'Embedded Payloads',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may embed payloads within other files to conceal malicious content from defenses. Otherwise seemingly benign files (such as scripts and executables) may be abused to carry and obfuscate malicious payloads and content. In some cases, embedded payloads may also enable adversaries to [Subvert Trust Controls](https://attack.mitre.org/techniques/T1553) by not impacting execution controls such as digital signatures and notarization tickets.(Citation: Sentinel Labs)",
            insertText: 'T1027.009',
            range: range,
        }
        ,
        {
            label: 'Command Obfuscation',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may obfuscate content during command execution to impede detection. Command-line obfuscation is a method of making strings and patterns within commands and scripts more difficult to signature and analyze. This type of obfuscation can be included within commands executed by delivered payloads (e.g., [Phishing](https://attack.mitre.org/techniques/T1566) and [Drive-by Compromise](https://attack.mitre.org/techniques/T1189)) or interactively via [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059).(Citation: Akamai JS)(Citation: Malware Monday VBE)",
            insertText: 'T1027.010',
            range: range,
        }
        ,
        {
            label: 'Fileless Storage',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may store data in \"fileless\" formats to conceal malicious activity from defenses. Fileless storage can be broadly defined as any format other than a file. Common examples of non-volatile fileless storage include the Windows Registry, event logs, or WMI repository.(Citation: Microsoft Fileless)(Citation: SecureList Fileless)",
            insertText: 'T1027.011',
            range: range,
        }
        ,
        {
            label: 'LNK Icon Smuggling',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may smuggle commands to download malicious payloads past content filters by hiding them within otherwise seemingly benign windows shortcut files. Windows shortcut files (.LNK) include many metadata fields, including an icon location field (also known as the `IconEnvironmentDataBlock`) designed to specify the path to an icon file that is to be displayed for the LNK file within a host directory.",
            insertText: 'T1027.012',
            range: range,
        }
        ,
        {
            label: 'Encrypted/Encoded File',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may encrypt or encode files to obfuscate strings, bytes, and other specific patterns to impede detection. Encrypting and/or encoding file content aims to conceal malicious artifacts within a file used in an intrusion. Many other techniques, such as [Software Packing](https://attack.mitre.org/techniques/T1027/002), [Steganography](https://attack.mitre.org/techniques/T1027/003), and [Embedded Payloads](https://attack.mitre.org/techniques/T1027/009), share this same broad objective. Encrypting and/or encoding files could lead to a lapse in detection of static signatures, only for this malicious content to be revealed (i.e., [Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)) at the time of execution/use.",
            insertText: 'T1027.013',
            range: range,
        }
        ,
        {
            label: 'Polymorphic Code',
            kind: monaco.languages.CompletionItemKind.Event,
            documentation: "Adversaries may utilize polymorphic code (also known as metamorphic or mutating code) to evade detection. Polymorphic code is a type of software capable of changing its runtime footprint during code execution.(Citation: polymorphic-blackberry) With each execution of the software, the code is mutated into a different version of itself that achieves the same purpose or objective as the original. This functionality enables the malware to evade traditional signature-based defenses, such as antivirus and antimalware tools.(Citation: polymorphic-sentinelone)",
            insertText: 'T1027.014',
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
            label: 'Digital Identity',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The unique representation of a subject engaged in an online transaction. A digital identity is always unique in the context of a digital service, but does not necessarily need to uniquely identify the subject in all contexts. In other words, accessing a digital service may not mean that the subject's real-life identity is known.  Note: There is no single, widely accepted definition for this term and context is important. This definition is specific to online transactions.",
            insertText: 'DigitalIdentity',
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
            label: 'Domain Registration',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A domain registration, or domain name registration data, is the relevant registration data from Internet resources such as domain names, IP addresses, and autonomous system numbers. Registration data is typically retrieved by means of either the Registration Data Access Protocol (RDAP) or its predecessor, the WHOIS protocol.",
            insertText: 'DomainRegistration',
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
            label: 'Pointer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computer science, a pointer is a programming language object, whose value refers to (or \"points to\") another value stored elsewhere in the computer memory using its memory address. A pointer references a location in memory, and obtaining the value stored at that location is known as dereferencing the pointer. As an analogy, a page number in a book's index could be considered a pointer to the corresponding page; dereferencing such a pointer would be done by flipping to the page with the given page number.",
            insertText: 'Pointer',
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
            label: 'MAC Address',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A media access control address (MAC address) is a unique identifier assigned to a network interface controller (NIC) for use as a network address in communications within a network segment.",
            insertText: 'MACAddress',
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
            label: 'OS API System Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Indirect System calls are made through an OS-specific library (like glibc in Linux) that provides a higher-level API for the system calls.",
            insertText: 'OSAPISystemFunction',
            range: range,
        }
        ,
        {
            label: 'Linux Ptrace Argument PTRACE_ATTACH',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Attach to the process specified in pid, making it a tracee of the calling process.",
            insertText: 'LinuxPtraceArgumentPTRACEATTACH',
            range: range,
        }
        ,
        {
            label: 'Linux Init Module',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Loads an ELF image into kernel space, performs any necessary symbol relocations, initializes module parameters to values provided by the caller, and then runs the module's init function.",
            insertText: 'LinuxInitModule',
            range: range,
        }
        ,
        {
            label: 'Linux Ptrace Argument PTRACE_PEEKTEXT',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Read a word at the address addr in the tracee's memory, returning the word as the result of the ptrace() call.",
            insertText: 'LinuxPtraceArgumentPTRACEPEEKTEXT',
            range: range,
        }
        ,
        {
            label: 'Linux Ptrace Argument PTRACE_GETREGS',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Copy the tracee's general-purpose or floating-point registers, respectively, to the address data in the tracer.",
            insertText: 'LinuxPtraceArgumentPTRACEGETREGS',
            range: range,
        }
        ,
        {
            label: 'Linux Ptrace Argument PTRACE_SETREGS',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Modify the tracee's general-purpose or floating-point registers, respectively, from the address data in the tracer.",
            insertText: 'LinuxPtraceArgumentPTRACESETREGS',
            range: range,
        }
        ,
        {
            label: 'Linux Delete Module',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Attempts to remove the unused loadable module entry identified by name. If the module has an exit function, then that function is executed before unloading the module.",
            insertText: 'LinuxDeleteModule',
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
            label: 'Windows DuplicateToken',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The DuplicateToken function creates a new access token that duplicates one already in existence.",
            insertText: 'WindowsDuplicateToken',
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
            label: 'Windows GetThreadContext',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Retrieves the context of the specified thread.",
            insertText: 'WindowsGetThreadContext',
            range: range,
        }
        ,
        {
            label: 'Linux Ptrace Argument PTRACE_CONT',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Restart the stopped tracee process.",
            insertText: 'LinuxPtraceArgumentPTRACECONT',
            range: range,
        }
        ,
        {
            label: 'Linux Ptrace Argument PTRACE_DETACH',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Restart the stopped tracee as for PTRACE_CONT, but first detach from it.",
            insertText: 'LinuxPtraceArgumentPTRACE_DETACH',
            range: range,
        }
        ,
        {
            label: 'Windows ResumeThread',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Decrements a thread's suspend count. When the suspend count is decremented to zero, the execution of the thread is resumed.",
            insertText: 'WindowsResumeThread',
            range: range,
        }
        ,
        {
            label: 'Windows SetThreadContext',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Sets the context for the specified thread.",
            insertText: 'WindowsSetThreadContext',
            range: range,
        }
        ,
        {
            label: 'Windows OpenThread',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Opens an existing thread object.",
            insertText: 'WindowsOpenThread',
            range: range,
        }
        ,
        {
            label: 'Windows NtOpenThread',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Opens a handle to a thread object with the access specified.",
            insertText: 'WindowsNtOpenThread',
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
            label: 'Windows VirtualFree',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Releases, decommits, or releases and decommits a region of pages within the virtual address space of the calling process.",
            insertText: 'WindowsVirtualFree',
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
            label: 'Windows QueryPerformanceCounter',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Retrieves the current value of the performance counter, which is a high resolution (<1us) time stamp that can be used for time-interval measurements.",
            insertText: 'WindowsQueryPerformanceCounter',
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
            label: 'Linux Pause Thread',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Causes the calling thread to sleep until a signal is delivered that either terminates the thread or causes the invocation of a signal-catching function.",
            insertText: 'LinuxPauseThread',
            range: range,
        }
        ,
        {
            label: 'Windows SuspendThread',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Suspends the specified thread.",
            insertText: 'WindowsSuspendThread',
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
            label: 'Windows OpenProcess',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Opens an existing local process object.",
            insertText: 'WindowsOpenProcess',
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
            label: 'Windows TerminateProcess',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Terminates the specified process and all of its threads.",
            insertText: 'WindowsTerminateProcess',
            range: range,
        }
        ,
        {
            label: 'Linux Ptrace Argument PTRACE_POKETEXT',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Copy the word data to the address addr in the tracee's memory.",
            insertText: 'LinuxPtraceArgumentPTRACEPOKETEXT',
            range: range,
        }
        ,
        {
            label: 'Windows WriteProcessMemory',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails.",
            insertText: 'WindowsWriteProcessMemory',
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
            label: 'Windows DeleteFile',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Deletes an existing file.",
            insertText: 'WindowsDeleteFile',
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
            label: 'Windows NtDeleteFile',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Deletes the specified file.",
            insertText: 'WindowsNtDeleteFile',
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
            label: 'Windows ReadFile',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Reads data from the specified file or input/output (I/O) device. Reads occur at the position specified by the file pointer if supported by the device.",
            insertText: 'WindowsReadFile',
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
            label: 'Windows WriteFile',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Writes data to the specified file or input/output (I/O) device.",
            insertText: 'WindowsWriteFile',
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
            label: 'Windows CreateThread',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Creates a thread to execute within the virtual address space of the calling process.",
            insertText: 'WindowsCreateThread',
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
            label: 'Windows OpenFile',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Creates, opens, reopens, or deletes a file.",
            insertText: 'WindowOpenFile',
            range: range,
        }
        ,
        {
            label: 'Windows CreateFileA',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Creates or opens a file or I/O device. The most commonly used I/O devices are as follows: file, file stream, directory, physical disk, volume, console buffer, tape drive, communications resource, mailslot, and pipe. The function returns a handle that can be used to access the file or device for various types of I/O depending on the file or device and the flags and attributes specified.",
            insertText: 'WindowsCreateFileA',
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
            label: 'Windows VirtualAllocEx',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified process. The function initializes the memory it allocates to zero.",
            insertText: 'WindowsVirtualAllocEx',
            range: range,
        }
        ,
        {
            label: 'Windows VirtualProtectEx',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Changes the protection on a region of committed pages in the virtual address space of a specified process.",
            insertText: 'WindowsVirtualProtectEx',
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
            label: 'Windows CreateProcessA',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Creates a new process and its primary thread. The new process runs in the security context of the calling process.",
            insertText: 'WindowsCreateProcessA',
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
            label: 'Network Agent',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A network agent is software installed on a network node or device that transmits information back to a collector agent or management system.  Kinds of network agents include SNMP Agent, IPMI agents, WBEM agents, and many proprietary agents capturing network monitoring and management information.",
            insertText: 'CollectorAgent',
            range: range,
        }
        ,
        {
            label: 'Asset Inventory Agent',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An asset inventory agent is a software tool which captures and transmits information about the devices on a network, including their hostnames, MAC addresses, software they may be running, etc.",
            insertText: 'AssetInventoryAgent',
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
            label: 'Office Application',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An office application is one that is part of an application suite (e.g., Microsoft Office, Open Office).",
            insertText: 'OfficeApplication',
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
            label: 'Mathematical Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Computes mathematical expressions.",
            insertText: 'MathematicalFunction',
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
            label: 'Pointer Dereferencing Function',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A function which has an operation which dereferences a pointer.",
            insertText: 'PointerDereferencingFunction',
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
            label: 'Enclave',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Network enclaves consist of standalone assets that do not interact with other information systems or networks. A major difference between a DMZ or demilitarized zone and a network enclave is a DMZ allows inbound and outbound traffic access, where firewall boundaries are traversed. In an enclave, firewall boundaries are not traversed. Enclave protection tools can be used to provide protection within specific security domains. These mechanisms are installed as part of an Intranet to connect networks that have similar security requirements.",
            insertText: 'Enclave',
            range: range,
        }
        ,
        {
            label: 'Internet Persona',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A social identity that an Internet user establishes in online communities and websites. It may also be an actively constructed presentation of oneself.",
            insertText: 'InternetPersona',
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
            label: 'User Profile',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A user profile is a collection of settings and information associated with a user. It contains critical information that is used to identify an individual, such as their name, age, portrait photograph and individual characteristics such as knowledge or expertise.",
            insertText: 'UserProfile',
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
            label: 'Computing Snapshot',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computer systems, a snapshot is the state of a system at a particular point in time.",
            insertText: 'ComputingSnapshot',
            range: range,
        }
        ,
        {
            label: 'Storage Snapshot',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A storage snapshot is a copy of a storage medium or system environment at a point in time.",
            insertText: 'StorageSnapshot',
            range: range,
        }
        ,
        {
            label: 'Volume Snapshot',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A volume snapshot is a point-in-time copy of a storage volume.",
            insertText: 'VolumeSnapshot',
            range: range,
        }
        ,
        {
            label: 'Differential Volume Snapshot',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A differential volume snapshot is a point-in-time capture of the files and directories that were changed since the last full snapshot.",
            insertText: 'DifferentialVolumeSnapshot',
            range: range,
        }
        ,
        {
            label: 'Full Volume Snapshot',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A full volume snapshot is a point-in-time copy of the complete contents of a volume.",
            insertText: 'FullVolumeSnapshot',
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
            label: 'Repository',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A centralized digital storage location where code, files, and related resources are systematically organized, managed, and maintained.",
            insertText: 'Repository',
            range: range,
        }
        ,
        {
            label: 'Software Repository',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A software repository, or repo for short, is a storage location for software packages. Often a table of contents is also stored, along with metadata. A software repository is typically managed by source or version control, or repository managers. Package managers allow automatically installing and updating repositories, sometimes called 'packages'.",
            insertText: 'SoftwareRepository',
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
            label: 'Stack Segment',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The stack segment contains the program stack, a last-in-first-out structure, typically allocated in the higher parts of memory for the process.",
            insertText: 'StackSegment',
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
            label: 'Computer Platform',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Platform includes the hardware and OS. The term computing platform can refer to different abstraction levels, including a certain hardware architecture, an operating system (OS), and runtime libraries. In total it can be said to be the stage on which computer programs can run.",
            insertText: 'ComputerPlatform',
            range: range,
        }
        ,
        {
            label: 'Computer Network Node',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A network node running on a computer platform.",
            insertText: 'ComputerNetworkNode',
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
            label: 'OT Embedded Computer',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A ruggedized computational device, embedded in industrial control systems, designed to handle real-time tasks and environmental stressors common in OT.",
            insertText: 'OTEmbeddedComputer',
            range: range,
        }
        ,
        {
            label: 'OT Controller',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An OT Controller is an industrial control device that automatically regulates one or more controlled variables in response to command inputs and real-time feedback signals.",
            insertText: 'OTController',
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
            label: 'File Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "The term server highlights the role of the machine in the traditional client-server scheme, where the clients are the workstations using the storage. A file server does not normally perform computational tasks or run programs on behalf of its client workstations. File servers are commonly found in schools and offices, where users use a local area network to connect their client computers.",
            insertText: 'FileServer',
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
            label: 'Network Time Server',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A network time server is a server computer that reads the actual time from a reference clock and distributes this information to its clients using a computer network. The time server may be a local network time server or an internet time server. The time server may also be a stand-alone hardware device. It can use NTP (RFC5905) or other protocols.",
            insertText: 'NetworkTimeServer',
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
            label: 'Interprocess Communication',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computer science, inter-process communication or inter-process communication (IPC) refers specifically to the mechanisms an operating system provides to allow processes it manages to share data. Typically, applications can use IPC categorized as clients and servers, where the client requests data and the server responds to client requests. Many applications are both clients and servers, as commonly seen in distributed computing. Methods for achieving IPC are divided into categories which vary based on software requirements, such as performance and modularity requirements, and system circumstances, such as network bandwidth and latency.",
            insertText: 'InterprocessCommunication',
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
            label: 'Network Packet',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A network packet is a formatted unit of data carried by a packet-switched network. Computer communications links that do not support packets, such as traditional point-to-point telecommunications links, simply transmit data as a bit stream. When data is formatted into packets, packet switching is possible and the bandwidth of the communication medium can be better shared among users than with circuit switching.",
            insertText: 'NetworkPackets',
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
            label: 'Computing Image',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A computing image captures the full state or contents of a computing entity, such as a process or volume.",
            insertText: 'ComputingImage',
            range: range,
        }
        ,
        {
            label: 'Storage Image',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A storage image is a complete, encapsulated representation of a storage medium or system environment. It contains all the data, files, and configurations necessary to replicate or deploy a specific system state or software setup.",
            insertText: 'StorageImage',
            range: range,
        }
        ,
        {
            label: 'Disk Image',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A disk image is a snapshot of a storage device's structure and data typically stored in one or more computer files on another storage device.",
            insertText: 'DiskImage',
            range: range,
        }
        ,
        {
            label: 'Optical Disc Image',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An optical disc image (or ISO image, from the ISO 9660 file system used with CD-ROM media) is a disk image that contains everything that would be written to an optical disc, disk sector by disc sector, including the optical disc file system.",
            insertText: 'OpticalDiscImage',
            range: range,
        }
        ,
        {
            label: 'Virtual Machine Image',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A Virtual Machine Image (VMI) is a file that encapsulates the entire state of a virtual machine at a given point in time. This includes the operating system, applications, data, and configurations. VMIs are used to create and replicate virtual machines, ensuring consistency and reliability across different environments.",
            insertText: 'VMImage',
            range: range,
        }
        ,
        {
            label: 'System State Image',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a system image is a serialized copy of the entire state of a computer system stored in some non-volatile form, such as a binary executable file.",
            insertText: 'SystemStateImage',
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
            label: 'Container Image',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A container is a standard unit of software that packages up code and all its dependencies so the application runs quickly and reliably from one computing environment to another. A Docker container image is a lightweight, standalone, executable package of software that includes everything needed to run an application: code, runtime, system tools, system libraries and settings.\n\n:S\n\nContainer images become containers at runtime and in the case of Docker containers - images become containers when they run on Docker Engine. Available for both Linux and Windows-based applications, containerized software will always run the same, regardless of the infrastructure. Containers isolate software from its environment and ensure that it works uniformly despite differences for instance between development and staging.",
            insertText: 'ContainerImage',
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
            label: 'Operating System',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An operating system (OS) is system software that manages computer hardware and software resources and provides common services for computer programs. All computer programs, excluding firmware, require an operating system to function. Time-sharing operating systems schedule tasks for efficient use of the system and may also include accounting software for cost allocation of processor time, mass storage, printing, and other resources.",
            insertText: 'OperatingSystem',
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
            label: 'Sensor',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In the broadest definition, a sensor is a device, module, machine, or subsystem that detects events or changes in its environment and sends the information to other electronics, frequently a computer.",
            insertText: 'Sensor',
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
            label: 'Network Scanner',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A network scanner is a computer program used to retrieve usernames and info on groups, shares, and services of networked computers. This type of program scans networks for vulnerabilities in the security of that network. If there is a vulnerability with the security of the network, it will send a report back to a hacker who may use this info to exploit that network glitch to gain entry to the network or for other malicious activities. Ethical hackers often also use the information to remove the glitches and strengthen their network.",
            insertText: 'NetworkScanner',
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
            label: 'OT Sensor',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An OT Sensor is an industrial-grade sensing device engineered for operational technology (OT) environments (e.g. SCADA, ICS). It measures physical variables\u2014such as pressure, temperature, or flow\u2014under demanding conditions, converting them into reliable signals for real-time monitoring and process control loops.",
            insertText: 'OTSensor',
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
            label: 'User',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A user is a person [or agent] who uses a computer or network service. Users generally use a system or a software product without the technical expertise required to fully understand it. Power users use advanced features of programs, though they are not necessarily capable of computer programming and system administration. A user often has a user account and is identified to the system by a username (or user name). Other terms for username include login name, screenname (or screen name), nickname (or nick) and handle, which is derived from the identical Citizen's Band radio term. Some software products provide services to other systems and have no direct end users.",
            insertText: 'User',
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
            documentation: "In computing, a login session is the period of activity between a user logging in and logging out of a (multi-user) system. This includes local login sessions, where a user has direct physical access to a computer, as well as domain login sessions, where a user logs into a computer that is part of a network domain.",
            insertText: 'LoginSession',
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
            label: 'Remote Login Session',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A remote login session is a login session where a client has logged in from their local host machine to a server via a network.",
            insertText: 'RemoteLoginSession',
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
            label: 'Volume',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In the context of computer operating systems, a volume or logical drive is a single accessible storage area with a single file system, typically (though not necessarily) resident on a single partition of a hard disk. Although a volume might be different from a physical disk drive, it can still be accessed with an operating system's logical interface. However, a volume differs from a partition.",
            insertText: 'Volume',
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
            label: 'Packet Log',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A log of all the network packet data captured from a network by a network sensor (i.e., packet analyzer),",
            insertText: 'PacketLog',
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
            label: 'Authorization Log',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A log of authorization events.",
            insertText: 'AuthorizationLog',
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
            label: 'Authentication Log',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A log of authentication events.",
            insertText: 'AuthenticationLog',
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
            label: 'System Utilization Record',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A system utilization record is a record for the tracking of resource utilization e.g. CPU, Disk, Network, Memory Bandwidth, GPU, or other resources for a given time period.",
            insertText: 'SystemUtilizationRecord',
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
            label: 'Digital Event Record',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A digital event record is a structured representation of a digital event, encapsulating all relevant details about the occurrence for storage, analysis, and response. These records serve as the primary artifacts for cybersecurity operations, enabling threat detection, forensic investigations, and compliance reporting. Digital event records include metadata such as timestamps, origin, context, and associated resources, ensuring traceability and actionable intelligence in digital ecosystems.",
            insertText: 'DigitalEventRecord',
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
            label: 'Partition Table',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A partition is a fixed-size subset of a storage device which is treated as a unit by the operating system. A partition table is a table maintained on the storage device by the operating system describing the partitions on that device. The terms partition table and partition map are most commonly associated with the MBR partition table of a Master Boot Record (MBR) in IBM PC compatibles, but it may be used generically to refer to other \"formats\" that divide a disk drive into partitions, such as: GUID Partition Table (GPT), Apple partition map (APM), or BSD disklabel.",
            insertText: 'PartitionTable',
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
            label: 'Anonymous Pipe',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computer science, an anonymous pipe is a simplex FIFO communication channel that may be used for one-way interprocess communication (IPC). An implementation is often integrated into the operating system's file IO subsystem. Typically a parent program opens anonymous pipes, and creates a new process that inherits the other ends of the pipes, or creates several new processes and arranges them in a pipeline.",
            insertText: 'AnonymousPipe',
            range: range,
        }
        ,
        {
            label: 'Named Pipe',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computing, a named pipe (also known as a FIFO for its behavior) is an extension to the traditional pipe concept on Unix and Unix-like systems, and is one of the methods of inter-process communication (IPC). The concept is also found in OS/2 and Microsoft Windows, although the semantics differ substantially. A traditional pipe is 'unnamed' and lasts only as long as the process. A named pipe, however, can last as long as the system is up, beyond the life of the process. It can be deleted if no longer used. Usually a named pipe appears as a file, and generally processes attach to it for IPC.",
            insertText: 'NamedPipe',
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
            label: 'Processor Cache Memory',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Cache memory is temporary storage that is more readily available to the processor than the computer's main memory source, located between the main memory and the processor.  It is typically either integrated directly into the CPU chip (level 1 cache) or placed on a separate chip with a bus interconnect with the CPU (level 2 cache).",
            insertText: 'CacheMemory',
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
            label: 'Certificate',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In cryptography, a public key certificate, also known as a digital certificate or identity certificate, is an electronic document used to prove the ownership of a public key. The certificate includes information about the key, information about the identity of its owner (called the subject), and the digital signature of an entity that has verified the certificate's contents (called the issuer). If the signature is valid, and the software examining the certificate trusts the issuer, then it can use that key to communicate securely with the certificate's subject. In email encryption, code signing, and e-signature systems, a certificate's subject is typically a person or organization. However, in Transport Layer Security (TLS) a certificate's subject is typically a computer or other device.",
            insertText: 'Certificate',
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
            label: 'Intranet Network',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An intranet is a private network accessible only to an organization's staff or delegates. Generally a wide range of information and services from the organization's internal IT systems are available that would not be available to the public from the Internet. A company-wide intranet can constitute an important focal point of internal communication and collaboration, and provide a single starting point to access internal and external resources. In its simplest form an intranet is established with the technologies for local area networks (LANs) and wide area networks (WANs).",
            insertText: 'IntranetNetwork',
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
            documentation: "Information used to configure the services, parameters, and initial settings for a virtual server instance running in a cloud service.",
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
            label: 'Hardware Device',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Hardware devices are the physical artifacts that constitute a network or computer system. Hardware devices are the physical parts or components of a computer, such as the monitor, keyboard, computer data storage, hard disk drive (HDD), graphic cards, sound cards, memory (RAM), motherboard, and so on, all of which are tangible physical objects. By contrast, software is instructions that can be stored and run by hardware. Hardware is directed by the software to execute any command or instruction. A combination of hardware and software forms a usable computing system.",
            insertText: 'HardwareDevice',
            range: range,
        }
        ,
        {
            label: 'I/O Module',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An I/O Module is a hardware device that translates signals between external sensors or actuators and control systems. It typically handles analog-to-digital (and vice versa) conversion, serving as the data interface that allows physical processes to be monitored and controlled by digital controllers.",
            insertText: 'IOModule',
            range: range,
        }
        ,
        {
            label: 'OT I/O Module',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An OT I/O Module is an industrial-grade interface designed for harsh Operational Technology (OT) environments. It reliably connects sensors and actuators to industrial control systems, ensuring precise, real-time data exchange in applications such as SCADA or ICS. Engineered for ruggedness and consistent performance, it can manage analog, digital, or other specialized signal types while enduring demanding conditions.",
            insertText: 'OTIOModule',
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
            label: 'Power Supply',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A power supply is an electrical device or module that converts and regulates energy from a source (e.g., the power grid or batteries) to an appropriate voltage, current, and frequency for one or more loads. It may stand alone or be integrated into its host appliance, often providing overcurrent protection, voltage regulation, or power conditioning for safe, stable operation.",
            insertText: 'PowerSupply',
            range: range,
        }
        ,
        {
            label: 'OT Power Supply',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An OT power supply is a power supply whose control amplifier is optimized for signal-processing tasks rather than supplying mere steady-state power to a load. It is a self-contained combination of operational amplifiers, power amplifiers, and integral power circuits designed for higher-level operations in industrial or OT contexts.",
            insertText: 'OTPowerSupply',
            range: range,
        }
        ,
        {
            label: 'Network Interface Card',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A network interface card (NIC, also known as a network interface controller, network adapter, LAN adapter or physical network interface, and by similar terms) is a computer hardware component that connects a computer to a computer network.",
            insertText: 'NetworkInterfaceCard',
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
            label: 'Output Device',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An output device is any piece of computer hardware equipment which converts information into human-readable form. It can be text, graphics, tactile, audio, and video. Some of the output devices are Visual Display Units (VDU) i.e. a Monitor, Printer, Graphic Output devices, Plotters, Speakers etc. A new type of Output device is been developed these days, known as Speech synthesizer, a mechanism attached to the computer which produces verbal output sounding almost like human speeches.",
            insertText: 'OutputDevice',
            range: range,
        }
        ,
        {
            label: 'Actuator',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An actuator is a mechanical or electromechanical device that, upon receiving a relatively low-energy control signal (e.g., electrical voltage, fluid pressure, or human force), translates its primary energy source (electric, hydraulic, or pneumatic) into targeted mechanical motion or adjustment. It typically works in conjunction with a control device (like a valve or logic driver) and is central to automation, enabling machines or systems to move, open, close, or otherwise manipulate their components or environment. By amplifying or redirecting energy from one form to another, the actuator executes control commands, thereby automating processes in industrial, automotive, aerospace, and other domains where precise mechanical action is essential.",
            insertText: 'Actuator',
            range: range,
        }
        ,
        {
            label: 'OT Actuator',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An OT actuator is an industrial-grade actuator optimized for operational technology (OT) environments, such as SCADA or process-control systems. It tolerates harsher conditions, meets stricter safety and reliability standards, and integrates seamlessly with ICS protocols to enable real-time mechanical motion or adjustments in production lines and critical infrastructure.",
            insertText: 'OTActuator',
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
            label: 'Removable Media Device',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A removable media device is a hardware device used for computer storage and that is designed to be inserted and removed from the system.  It is distinct from other removable media in that all the hardware required to read the data are built into the device.  So USB flash drives and external hard drives are removable media devices, whereas tapes and disks are not, as they require additional hardware to perform read/write operations.",
            insertText: 'RemovableMediaDevice',
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
            label: 'Web Identity Token',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "An ID token is an artifact that proves that the user has been authenticated.",
            insertText: 'WebIdentityToken',
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
            label: 'Session Token',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "In computer science, a session identifier, session ID or session token is a piece of data that is used in network communications (often over HTTPS) to identify a session, a series of related message exchanges.",
            insertText: 'SessionToken',
            range: range,
        }
        ,
        {
            label: 'Web Access Token',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A web access token is a credential that allows a web client application to access a specific resource to perform specific actions on behalf of the user.",
            insertText: 'WebAccessToken',
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
            label: 'Service Account',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A service account is a type of account used by an application or service to interact with the operating system.",
            insertText: 'ServiceAccount',
            range: range,
        }
        ,
        {
            label: 'Kerberos Ticket Granting Ticket Account',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "KRBTGT is an account used by Key Distribution Center (KDC) service to issue Ticket Granting Tickets (TGTs) as part of the Kerberos authentication protocol.",
            insertText: 'KerberosTicketGrantingTicketAccount',
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
            label: 'TFTP Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "TFTP Network Traffic is network traffic typically used to automatically transfer configuration or boot files between machines.",
            insertText: 'TFTPNetworkTraffic',
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
            label: 'Outbound Internet File Transfer Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "Outbound internet file transfer traffic is file transfer traffic that is: (a) on an outgoing connection initiated from a host within a network to a host outside the network, and (b) using a standard file transfer protocol.",
            insertText: 'OutboundInternetFileTransferTraffic',
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
            label: 'File Transfer Network Traffic',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "File transfer network traffic is network traffic related to file transfers between network nodes. This includes only network traffic conforming to standard file transfer protocols, not custom transfer protocols.",
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
            label: 'Load Module',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A system call that loads a driver or extension into the kernel.",
            insertText: 'LoadModule',
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
            label: 'Unload Module',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "A system call that unloads a driver or extension from the kernel.",
            insertText: 'UnloadModule',
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
            label: 'Open File',
            kind: monaco.languages.CompletionItemKind.Class,
            documentation: "For most file systems, a program initializes access to a file in a file system using the open system call. This allocates resources associated to the file (the file descriptor), and returns a handle that the process will use to refer to that file. In some cases the open is performed by the first access. During the open, the filesystem may allocate memory for buffers, or it may wait until the first operation. Various other errors which may occur during the open include directory update failures, un-permitted multiple connections, media failures, communication link failures and device failures.",
            insertText: 'OpenFile',
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
            label: 'obfuscates',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x obfuscates y: The technique x makes the digital artifact y unclear or obscure.  Typically obfuscation is a way to hide a digital artifact from discovery, use, or both.",
            insertText: 'obfuscates',
            range: range,
        }
        ,
        {
            label: 'unloads',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x unloads y: The technique or artifact performs the action of unloading some artifact (applications, kernel modules, or hardware drivers, etc.) from a computer's memory.",
            insertText: 'unloads',
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
            label: 'terminates',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x terminates y: The technique x brings to an end or halt to some activity y.",
            insertText: 'terminates',
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
            label: 'updates',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x updates y: The technique x updates the software for component y.",
            insertText: 'updates',
            range: range,
        }
        ,
        {
            label: 'validated-by',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x validated-by y: The digital artifact x has its authenticity and correctness confirmed or verified by the technique, operation, or agent y.",
            insertText: 'validated-by',
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
            label: 'regenerates',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x regenerates y: The entity x discards the current digital artifact y and creates a new version that serves the same function.",
            insertText: 'regenerates',
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
            label: 'authenticates',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x authenticates y: The subject x establishes the authenticity of some y. This relation indicates an authentication event has occurred.",
            insertText: 'authenticates',
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
            documentation: "x may-be-tactically-associated-with y: the defensive action x may be a tactic that counters offensive action y.",
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
            label: 'produces',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x produces y: The subject entity x or process produces a data object y, which may be discrete digital object or a stream (e.g., a stream such as network traffic.)",
            insertText: 'produces',
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
            documentation: "x enumerates y: The subject x takes the action of reading from a digital source y to acquire data and create a list of its contents.",
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
            label: 'controlled-by',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x controlled-by y: x's operation or behavior is directed or regulated by y.",
            insertText: 'controlled-by',
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
            label: 'causes',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x causes y: The event or action x brings about event or action y as a consequence.",
            insertText: 'causes',
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
            label: 'depends-on',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x depends-on y: The entity x is contingent on y being available; x relies on y.",
            insertText: 'dependsOn',
            range: range,
        }
        ,
        {
            label: 'powered-by',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x powered-by y: x obtains its essential energy or force from y to perform its function or remain active.",
            insertText: 'powered-by',
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
            documentation: "x instructed-by y: A subject x takes machine instructions from object y.",
            insertText: 'instructed-by',
            range: range,
        }
        ,
        {
            label: 'instructs',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x instructs y: A subject x delivers machine instructions to object y.",
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
            label: 'participates-in',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x participates-in y: The object x takes part in the event y, signifying that x contributes to or is affected by the event\u2019s occurrence in some way.",
            insertText: 'participates-in',
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
            label: 'controls',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x controls y: x directs or regulates y's operational state, behavior, or function.",
            insertText: 'controls',
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
            label: 'powers',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x powers y: x furnishes y with the energy or force required for y's functionality or operation.",
            insertText: 'powers',
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
            label: 'preceded-by',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x preceded-by y: The event or action x occurs after event or action y in time.",
            insertText: 'preceded-by',
            range: range,
        }
        ,
        {
            label: 'precedes',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x precedes y: The event or action x occurs before event or action y in time.",
            insertText: 'precedes',
            range: range,
        }
        ,
        {
            label: 'resumes',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "The agent or technique x continues a previous action on entity y. Usually occurs after suspension on y.",
            insertText: 'resumes',
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
            label: 'caused-by',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x caused-by y: The event or action x occurs as a consequence of event or action y.",
            insertText: 'caused-by',
            range: range,
        }
        ,
        {
            label: 'communicates-with',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x communicates-with y: x and y exchange signals or data bidirectionally, enabling mutual awareness, coordination, or interaction.",
            insertText: 'communicates-with',
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
            label: 'related',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x related y: x has a symmetric associative relation to y.",
            insertText: 'related',
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
            label: 'enables',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x enables y: A top level technique x enables a tactic y, that is, the property indicates that a technique x is used to put a particular tactic y into action. In other words, x renders y capable or able for some task.",
            insertText: 'enables',
            range: range,
        }
        ,
        {
            label: 'has-participant',
            kind: monaco.languages.CompletionItemKind.Property,
            documentation: "x has-participant y: The event x involves an object y as a participant, indicating that y plays some role in the event, whether actively, passively, or otherwise.",
            insertText: 'has-participant',
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
