# CICIoT2023 — Dataset Inspection Report (Phase 1)

Generated: 2026-10-07T01:02:28.469442+00:00  ·  data dir: `/Users/nitish/Code/KG_SIEM/project/data/raw`  ·  elapsed: 1.82 s

> Every number below was measured from the listed files in streaming mode (chunksize 100,000). No external dataset descriptions were used.

## 1. Files

- Files: **1**  ·  total size: **67.1 MB**  ·  split across multiple files: **False**  ·  schema consistent: **True**

| File | Size | Physical data lines | Parsed rows | Malformed skipped | Labels in file | Header OK | Time (s) |
|---|---:|---:|---:|---:|---:|:-:|---:|
| `part-00000-363d1ba3-8ab5-4f96-bc25-4d5862db7cb9-c000.csv` | 67.1 MB | 238,687 | 238,687 | 0 | 34 | yes | 1.8 |

## 2. Rows

- Parsed rows: **238,687**
- Physical data lines (newline count minus headers): **238,687**
- Malformed lines (field count != header) dropped: **0**  ·  blank lines: 0  ·  files parsed in strict mode: 0
- Parsed-vs-scanned row discrepancy: **0** (0 = every physical data line accounted for)

## 3. Columns

- Columns: **47** (46 features + target)
- Target column: **`label`** (detected via `exact`; equals expected `label`: **True**)
- Binary indicator columns (only 0/1 observed): 21 → `fin_flag_number`, `syn_flag_number`, `rst_flag_number`, `psh_flag_number`, `ack_flag_number`, `ece_flag_number`, `cwr_flag_number`, `HTTP`, `HTTPS`, `DNS`, `Telnet`, `SMTP`, `SSH`, `IRC`, `TCP`, `UDP`, `DHCP`, `ARP`, `ICMP`, `IPv`, `LLC`
- Constant columns: ['ece_flag_number', 'cwr_flag_number', 'Telnet', 'SMTP', 'IRC', 'DHCP']
- Feature columns parsed as non-numeric in ≥1 chunk: none

Column names (stripped): `flow_duration`, `Header_Length`, `Protocol Type`, `Duration`, `Rate`, `Srate`, `Drate`, `fin_flag_number`, `syn_flag_number`, `rst_flag_number`, `psh_flag_number`, `ack_flag_number`, `ece_flag_number`, `cwr_flag_number`, `ack_count`, `syn_count`, `fin_count`, `urg_count`, `rst_count`, `HTTP`, `HTTPS`, `DNS`, `Telnet`, `SMTP`, `SSH`, `IRC`, `TCP`, `UDP`, `DHCP`, `ARP`, `ICMP`, `IPv`, `LLC`, `Tot sum`, `Min`, `Max`, `AVG`, `Std`, `Tot size`, `IAT`, `Number`, `Magnitue`, `Radius`, `Covariance`, `Variance`, `Weight`, `label`

## 4. Missing / non-finite values

- NaN cells: **0**  ·  ±inf cells: **0**  ·  non-numeric cells coerced: **0**  ·  rows with missing label: **0**

## 5. Duplicates

- Method: 64-bit row hash (features as float32 + label), exact match across all files
- Rows hashed: 238,687  ·  unique rows: 229,928  ·  **duplicate rows: 8,759 (3.67 %)**  ·  max multiplicity: 83

## 6. Labels and class distribution

- Unique labels observed: **34**  ·  labels per file: min 34, max 34

| Raw label | Rows | % | Files | Status | Attack type | Category | Match |
|---|---:|---:|---:|---|---|---|---|
| `DDoS-ICMP_Flood` | 36,554 | 15.315 | 1 | in_scope | DDoS ICMP Flood | DDoS | exact |
| `DDoS-UDP_Flood` | 27,626 | 11.574 | 1 | in_scope | DDoS UDP Flood | DDoS | exact |
| `DDoS-TCP_Flood` | 23,149 | 9.698 | 1 | in_scope | DDoS TCP Flood | DDoS | exact |
| `DDoS-PSHACK_Flood` | 21,210 | 8.886 | 1 | excluded (not_in_project_scope) | DDoS PSH-ACK Flood | DDoS | exact |
| `DDoS-SYN_Flood` | 20,739 | 8.689 | 1 | in_scope | DDoS SYN Flood | DDoS | exact |
| `DDoS-RSTFINFlood` | 20,669 | 8.659 | 1 | excluded (not_in_project_scope) | DDoS RST-FIN Flood | DDoS | exact |
| `DDoS-SynonymousIP_Flood` | 18,189 | 7.620 | 1 | excluded (not_in_project_scope) | DDoS Synonymous IP Flood | DDoS | exact |
| `DoS-UDP_Flood` | 16,957 | 7.104 | 1 | in_scope | DoS UDP Flood | DoS | exact |
| `DoS-TCP_Flood` | 13,630 | 5.710 | 1 | in_scope | DoS TCP Flood | DoS | exact |
| `DoS-SYN_Flood` | 10,275 | 4.305 | 1 | in_scope | DoS SYN Flood | DoS | exact |
| `BenignTraffic` | 5,600 | 2.346 | 1 | in_scope | Benign | Benign | exact |
| `Mirai-greeth_flood` | 5,016 | 2.101 | 1 | excluded (mirai_excluded) | Mirai GRE-ETH Flood | Mirai | exact |
| `Mirai-udpplain` | 4,661 | 1.953 | 1 | excluded (mirai_excluded) | Mirai UDP Plain | Mirai | exact |
| `Mirai-greip_flood` | 3,758 | 1.574 | 1 | excluded (mirai_excluded) | Mirai GRE-IP Flood | Mirai | exact |
| `DDoS-ICMP_Fragmentation` | 2,377 | 0.996 | 1 | excluded (not_in_project_scope) | DDoS ICMP Fragmentation | DDoS | exact |
| `MITM-ArpSpoofing` | 1,614 | 0.676 | 1 | in_scope | ARP Spoofing | Spoofing | exact |
| `DDoS-ACK_Fragmentation` | 1,505 | 0.631 | 1 | excluded (not_in_project_scope) | DDoS ACK Fragmentation | DDoS | exact |
| `DDoS-UDP_Fragmentation` | 1,484 | 0.622 | 1 | excluded (not_in_project_scope) | DDoS UDP Fragmentation | DDoS | exact |
| `DNS_Spoofing` | 925 | 0.388 | 1 | in_scope | DNS Spoofing | Spoofing | exact |
| `Recon-HostDiscovery` | 697 | 0.292 | 1 | in_scope | Host Discovery | Reconnaissance | exact |
| `Recon-OSScan` | 517 | 0.217 | 1 | in_scope | OS Scan | Reconnaissance | exact |
| `Recon-PortScan` | 430 | 0.180 | 1 | in_scope | Port Scan | Reconnaissance | exact |
| `DoS-HTTP_Flood` | 414 | 0.173 | 1 | in_scope | DoS HTTP Flood | DoS | exact |
| `VulnerabilityScan` | 210 | 0.088 | 1 | in_scope | Vulnerability Scan | Reconnaissance | exact |
| `DDoS-HTTP_Flood` | 169 | 0.071 | 1 | in_scope | DDoS HTTP Flood | DDoS | exact |
| `DDoS-SlowLoris` | 106 | 0.044 | 1 | excluded (not_in_project_scope) | DDoS SlowLoris | DDoS | exact |
| `DictionaryBruteForce` | 63 | 0.026 | 1 | in_scope | Dictionary Brute Force | Brute Force | exact |
| `SqlInjection` | 31 | 0.013 | 1 | in_scope | SQL Injection | Web-Based | exact |
| `BrowserHijacking` | 30 | 0.013 | 1 | excluded (optional_excluded_decision_D5) | Browser Hijacking | Web-Based | exact |
| `CommandInjection` | 28 | 0.012 | 1 | in_scope | Command Injection | Web-Based | exact |
| `Backdoor_Malware` | 22 | 0.009 | 1 | in_scope | Backdoor Malware | Web-Based | exact |
| `XSS` | 18 | 0.008 | 1 | in_scope | XSS | Web-Based | exact |
| `Uploading_Attack` | 8 | 0.003 | 1 | in_scope | Uploading Attack | Web-Based | exact |
| `Recon-PingSweep` | 6 | 0.003 | 1 | in_scope | Ping Sweep | Reconnaissance | exact |

## 7. Project scope coverage

- In-scope rows: **159,682** (attack 154,082 + benign 5,600)
- Excluded rows (Mirai / out-of-scope variants / optional): **79,005**
- Unknown-label rows: **0**
- In-scope classes observed: **23 / 23**  ·  coverage complete: **True**
- Mirai labels observed (will be excluded): `Mirai-greeth_flood`, `Mirai-greip_flood`, `Mirai-udpplain`

| Category | In-scope rows |
|---|---:|
| DDoS | 108,237 |
| DoS | 41,276 |
| Benign | 5,600 |
| Spoofing | 2,539 |
| Reconnaissance | 1,860 |
| Web-Based | 107 |
| Brute Force | 63 |

## 8. Feature statistics (streaming; finite values only)

| Feature | Finite | NaN | ±inf | Zero % | Min | Max | Mean | Std | Integral | Recommended dtype |
|---|---:|---:|---:|---:|---:|---:|---:|---:|:-:|---|
| `flow_duration` | 238,687 | 0 | 0 | 54.2 | 0 | 6.843e+04 | 5.908 | 327.7 | no | float32 |
| `Header_Length` | 238,687 | 0 | 0 | 15.9 | 0 | 9.81e+06 | 7.701e+04 | 4.596e+05 | no | float32 |
| `Protocol Type` | 238,687 | 0 | 0 | 0.0 | 0 | 47 | 9.053 | 8.902 | no | float32 |
| `Duration` | 238,687 | 0 | 0 | 0.0 | 0 | 255 | 66.35 | 14.03 | no | float32 |
| `Rate` | 238,687 | 0 | 0 | 2.0 | 0 | 7.34e+06 | 9384 | 1.008e+05 | no | float32 |
| `Srate` | 238,687 | 0 | 0 | 2.0 | 0 | 7.34e+06 | 9384 | 1.008e+05 | no | float32 |
| `Drate` | 238,687 | 0 | 0 | 100.0 | 0 | 0.8485 | 5.386e-06 | 0.001765 | no | float32 |
| `fin_flag_number` | 238,687 | 0 | 0 | 91.3 | 0 | 1 | 0.08653 | 0.2811 | yes | uint8 (binary indicator) |
| `syn_flag_number` | 238,687 | 0 | 0 | 79.4 | 0 | 1 | 0.2061 | 0.4045 | yes | uint8 (binary indicator) |
| `rst_flag_number` | 238,687 | 0 | 0 | 90.9 | 0 | 1 | 0.09065 | 0.2871 | yes | uint8 (binary indicator) |
| `psh_flag_number` | 238,687 | 0 | 0 | 91.1 | 0 | 1 | 0.08875 | 0.2844 | yes | uint8 (binary indicator) |
| `ack_flag_number` | 238,687 | 0 | 0 | 87.5 | 0 | 1 | 0.1247 | 0.3304 | yes | uint8 (binary indicator) |
| `ece_flag_number` | 238,687 | 0 | 0 | 100.0 | 0 | 0 | 0 | 0 | yes | uint8 (binary indicator) |
| `cwr_flag_number` | 238,687 | 0 | 0 | 100.0 | 0 | 0 | 0 | 0 | yes | uint8 (binary indicator) |
| `ack_count` | 238,687 | 0 | 0 | 87.6 | 0 | 2.2 | 0.09057 | 0.2865 | no | float32 |
| `syn_count` | 238,687 | 0 | 0 | 70.0 | 0 | 6.76 | 0.3287 | 0.6613 | no | float32 |
| `fin_count` | 238,687 | 0 | 0 | 86.8 | 0 | 46.5 | 0.09931 | 0.3158 | no | float32 |
| `urg_count` | 238,687 | 0 | 0 | 79.3 | 0 | 2985 | 6.315 | 72.78 | no | float32 |
| `rst_count` | 238,687 | 0 | 0 | 73.5 | 0 | 8744 | 38.15 | 320.5 | no | float32 |
| `HTTP` | 238,687 | 0 | 0 | 95.1 | 0 | 1 | 0.04912 | 0.2161 | yes | uint8 (binary indicator) |
| `HTTPS` | 238,687 | 0 | 0 | 94.5 | 0 | 1 | 0.05506 | 0.2281 | yes | uint8 (binary indicator) |
| `DNS` | 238,687 | 0 | 0 | 100.0 | 0 | 1 | 0.0001676 | 0.01294 | yes | uint8 (binary indicator) |
| `Telnet` | 238,687 | 0 | 0 | 100.0 | 0 | 0 | 0 | 0 | yes | uint8 (binary indicator) |
| `SMTP` | 238,687 | 0 | 0 | 100.0 | 0 | 0 | 0 | 0 | yes | uint8 (binary indicator) |
| `SSH` | 238,687 | 0 | 0 | 100.0 | 0 | 1 | 4.609e-05 | 0.006788 | yes | uint8 (binary indicator) |
| `IRC` | 238,687 | 0 | 0 | 100.0 | 0 | 0 | 0 | 0 | yes | uint8 (binary indicator) |
| `TCP` | 238,687 | 0 | 0 | 42.6 | 0 | 1 | 0.5745 | 0.4944 | yes | uint8 (binary indicator) |
| `UDP` | 238,687 | 0 | 0 | 78.8 | 0 | 1 | 0.2124 | 0.409 | yes | uint8 (binary indicator) |
| `DHCP` | 238,687 | 0 | 0 | 100.0 | 0 | 0 | 0 | 0 | yes | uint8 (binary indicator) |
| `ARP` | 238,687 | 0 | 0 | 100.0 | 0 | 1 | 7.96e-05 | 0.008922 | yes | uint8 (binary indicator) |
| `ICMP` | 238,687 | 0 | 0 | 83.7 | 0 | 1 | 0.163 | 0.3693 | yes | uint8 (binary indicator) |
| `IPv` | 238,687 | 0 | 0 | 0.0 | 0 | 1 | 0.9999 | 0.01193 | yes | uint8 (binary indicator) |
| `LLC` | 238,687 | 0 | 0 | 0.0 | 0 | 1 | 0.9999 | 0.01193 | yes | uint8 (binary indicator) |
| `Tot sum` | 238,687 | 0 | 0 | 0.0 | 42 | 5.837e+04 | 1313 | 2625 | no | float32 |
| `Min` | 238,687 | 0 | 0 | 0.0 | 42 | 3236 | 91.77 | 140 | no | float32 |
| `Max` | 238,687 | 0 | 0 | 0.0 | 42 | 3.033e+04 | 182.6 | 531.6 | no | float32 |
| `AVG` | 238,687 | 0 | 0 | 0.0 | 42 | 7861 | 125.2 | 242.7 | no | float32 |
| `Std` | 238,687 | 0 | 0 | 67.9 | 0 | 1.1e+04 | 33.73 | 163.9 | no | float32 |
| `Tot size` | 238,687 | 0 | 0 | 0.0 | 42 | 1.31e+04 | 125.4 | 244.8 | no | float32 |
| `IAT` | 238,687 | 0 | 0 | 0.0 | 0 | 1.676e+08 | 8.315e+07 | 1.711e+07 | no | float32 |
| `Number` | 238,687 | 0 | 0 | 0.0 | 1 | 14.5 | 9.497 | 0.8218 | no | float32 |
| `Magnitue` | 238,687 | 0 | 0 | 0.0 | 9.165 | 121 | 13.14 | 8.657 | no | float32 |
| `Radius` | 238,687 | 0 | 0 | 68.7 | 0 | 1.555e+04 | 47.67 | 231.7 | no | float32 |
| `Covariance` | 238,687 | 0 | 0 | 68.7 | 0 | 1.373e+08 | 3.198e+04 | 4.479e+05 | no | float32 |
| `Variance` | 238,687 | 0 | 0 | 68.7 | 0 | 1 | 0.09702 | 0.2341 | no | float32 |
| `Weight` | 238,687 | 0 | 0 | 0.0 | 1 | 244.6 | 141.5 | 21.14 | no | float32 |
