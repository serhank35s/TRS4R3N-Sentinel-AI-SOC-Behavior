TRS4R3N Sentinel AI | Advanced Endpoint Behavioral Analytics (EBA)

Sentinel AI v3.9 is a high-performance, event-driven monitoring solution designed to bridge the gap between raw Windows telemetry and actionable security intelligence. By implementing a multi-threaded correlation engine, it provides real-time visibility into sophisticated adversary tactics.

Core Capabilities

1. MITRE ATT&CK® Correlation Engine
The engine performs deep packet and log inspection to map telemetry to the MITRE ATT&CK Matrix. It covers critical vectors including:
Credential Access: (T1003) LSASS dumping and SAM database access.
Lateral Movement: (T1021) Remote service creation and share enumeration.
Persistence: (T1543) Unauthorized service and scheduled task manipulation.



2. Heuristic Chain Analysis (HCA)
Unlike static thresholding, Sentinel AI utilizes an HCA algorithm to detect sequential malicious behaviors. If an entity triggers a chain of high-risk events, the system applies an exponential risk multiplier, identifying complex attack patterns like Ransomware staging or Advanced Persistent Threats (APTs).

3. Real-Time Network Telemetry & Geo-Intelligence
The engine integrates with the Windows IP Helper API to provide a live mapping of process-to-network traffic. Each external connection is cross-referenced with Geo-IP intelligence to detect anomalous data exfiltration or Command & Control (C2) beacons.

4. High-Performance Concurrency Model
Built on a zero-dependency C++ core, the system utilizes a multi-threaded architecture:
Log Ingestion Thread: Subscribes to the Windows Event Subsystem (WES).
Network Intelligence Thread: Scans and correlates TCP states.
UI Rendering Thread: Optimized ANSI-based dashboard for real-time visualization.

Architecture Detail

| Component | Technology | Role |
| :--- | :--- | :--- |
| Telemetry Ingestion | Win32 Evt Subsystem | Low-level event subscription |
| Logic Engine | STL Unordered Maps / Mutex | High-speed pattern matching |
| Network | Winsock2 / IPHelper | Socket state analysis |
| Security Layer | MITRE DB v14 Integration | Standardized threat labeling |

Deployment

1. Sysmon Installation: Ensure Microsoft Sysmon is active for deep process visibility.
2. Privilege Escalation: Execute the binary with `SeDebugPrivilege` (Run as Administrator).
3. ANSI Terminal: Use Windows Terminal or enable `Virtual Terminal Processing` for the enhanced UI.

Screenshoots

1.Detected Foreign IP Addresses.
<img width="2559" height="1224" alt="1" src="https://github.com/user-attachments/assets/ae7f5eb7-2683-4095-9888-29d5d7ce2b6b" />

2.Detect Added Privileged User (ADMİN,SYSTEM group)
<img width="2554" height="1221" alt="2" src="https://github.com/user-attachments/assets/c65b7df5-50b4-4bb7-ae3f-c4fe1a4b3466" />

3.Detect Clenaned Security Logs
<img width="2559" height="1210" alt="3" src="https://github.com/user-attachments/assets/c7e6bf1f-949f-4ded-9a79-6560c2d87cc5" />

License & Legal Notice

This project is licensed under the **Apache License 2.0**.

Apache 2.0 Summary:
Permissions: You can use, modify, and distribute this software for personal or commercial purposes.
Conditions: You must give appropriate credit (attribution), provide a link to the license, and indicate if changes were made.
Limitations: This software is provided "as is", without warranties of any kind.

Unauthorized Use & Ethics Warning
TRS4R3N Sentinel AI is developed strictly for educational, defensive research, and authorized security auditing purposes. 

1.  Attribution Required:** Any redistribution or reuse of this source code (in whole or in part) must include original authorship credit to TRS4R3N.
2.  No Malicious Intent: Use of this tool for unauthorized monitoring or illegal activities is strictly prohibited. The developer is not responsible for any misuse or damage caused by this software.
3.  Strictly Professional: Selling this software as a standalone commercial product without explicit permission from the original author is a violation of the community's ethical standards.

True power is used to protect, not to exploit.
