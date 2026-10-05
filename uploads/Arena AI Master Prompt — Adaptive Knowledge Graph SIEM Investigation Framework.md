# ROLE

Act as a **senior AI engineer, cybersecurity engineer, ML engineer, backend engineer, full-stack developer, and research architect**.

You are helping me build a **working academic research prototype**, not merely writing sample code.

The project title is:

**Adaptive Knowledge Graph-Based SIEM Investigation Framework with LLM-Driven Attack Story Reconstruction**

The final deliverable must be a **functional web application for SOC analysts** that demonstrates the complete workflow:

**Security Data → Attack Detection → Behavioral Analysis → Alert → Agentic Investigation → Evidence Collection → Threat Intelligence → Dynamic Knowledge Graph → Adaptive Evidence Collection → Attack Chain Reconstruction → LLM Attack Story → Explainable Investigation Report → SOC Dashboard**

The system must be:

- modular
- explainable
- evidence-grounded
- reproducible
- computationally practical
- suitable for academic research and demonstration.

Do NOT reduce the project to a machine-learning classification system.

---

# 1. CORE RESEARCH CONTRIBUTION

The primary research contribution is:

> **Context-aware, adaptive, evidence-driven SIEM investigation using a dynamic knowledge graph.**

The system must demonstrate that after an alert is generated, the investigation can:

1. understand the current evidence,
2. identify entities and relationships,
3. determine what evidence is missing,
4. choose what evidence to retrieve next,
5. retrieve that evidence,
6. update the knowledge graph,
7. reassess the investigation state,
8. repeat when necessary,
9. reconstruct the attack chain,
10. generate an evidence-backed attack narrative.

The investigation must therefore be **stateful and adaptive**.

Do NOT claim that any individual technology is novel merely because it is used.

The novelty should be demonstrated through the **integration and adaptive evidence-collection mechanism**.

---

# 2. FIRST AND MOST IMPORTANT RULE

## DO NOT BUILD THE ENTIRE APPLICATION IMMEDIATELY.

Work incrementally.

Before writing large amounts of implementation code:

### FIRST perform a design and feasibility review.

The first response must contain:

1. System architecture
2. Data flow
3. Agent architecture
4. Tool architecture
5. MongoDB schema
6. Neo4j schema
7. LangGraph state design
8. API architecture
9. ML pipeline
10. Adaptive investigation algorithm
11. Frontend architecture
12. Development phases
13. Dependencies
14. Environment variables
15. Testing strategy
16. Research evaluation strategy
17. Risks and mitigations

Then begin implementation **one phase at a time**.

Never move to the next phase until the current phase has been tested successfully.

---

# 3. DATASET

Primary dataset:

**CICIoT2023**

The actual dataset files provided in the project must be inspected.

NEVER fabricate dataset statistics.

Automatically determine:

- number of files
- number of rows
- number of columns
- column names
- data types
- missing values
- duplicate records
- unique attack labels
- class distribution
- file sizes
- whether the dataset is split across multiple files.

The expected target column is:

`label`

but verify this against the actual files.

The commonly used CICIoT2023 representation may contain 46 input features plus a label, but **never assume this without inspecting the actual dataset**.

The ingestion pipeline must be capable of handling very large CSV files efficiently.

Use:

- chunked CSV reading
- efficient data types
- batch processing
- database bulk insertion
- sampling only when scientifically justified
- pagination
- indexes.

Never unnecessarily load the entire dataset into RAM.

---

# 4. ATTACK SCOPE

Exclude **ALL MIRAI attacks**.

The experimental scope should cover:

## DDoS

Use:

1. DDoS ICMP Flood
2. DDoS UDP Flood
3. DDoS TCP Flood
4. DDoS SYN Flood
5. DDoS HTTP Flood

## DoS

CICIoT2023 contains four DoS subtypes.

Use all available:

1. DoS TCP Flood
2. DoS UDP Flood
3. DoS SYN Flood
4. DoS HTTP Flood

Do NOT invent additional DoS types.

## Reconnaissance

Use:

1. Ping Sweep
2. OS Scan
3. Host Discovery
4. Vulnerability Scan
5. Port Scan

## Web-Based

Use:

1. SQL Injection
2. Command Injection
3. Backdoor Malware
4. Uploading Attack
5. XSS

Browser Hijacking may be supported if it exists in the actual dataset, but it is optional for the initial implementation.

## Brute Force

Use:

1. Dictionary Brute Force

Do NOT invent additional brute-force classes.

## Spoofing

Use:

1. ARP Spoofing
2. DNS Spoofing

## MIRAI

Exclude every Mirai class.

The actual dataset labels must be mapped to these conceptual attack types only after inspecting the dataset.

---

# 5. CRITICAL DATA INTERPRETATION RULE

CICIoT2023 network-flow features are **behavioral/network evidence**, not direct forensic evidence of every underlying action.

The dataset does NOT directly provide things such as:

- usernames
- passwords
- PowerShell commands
- Windows process trees
- registry modifications
- SQL queries
- uploaded files
- browser contents.

Therefore:

NEVER say:

> "The HTTP feature proves SQL Injection."

Instead say:

> "The HTTP protocol indicator and associated network-flow characteristics provide behavioral evidence associated with the labelled SQL Injection class."

The attack label is the dataset ground truth.

Use feature importance and explainability to determine which feature combinations are useful.

---

# 6. BEHAVIORAL PROFILING

Build attack-specific behavioral profiles.

Investigate feature importance for every selected attack class.

Potential feature groups include:

### Traffic

- Rate
- Srate
- Drate
- Number

### Temporal

- flow_duration
- Duration
- IAT

### TCP flags

- fin_flag_number
- syn_flag_number
- rst_flag_number
- psh_flag_number
- ack_flag_number
- ece_flag_number
- cwr_flag_number

### Flag counts

- ack_count
- syn_count
- fin_count
- urg_count
- rst_count

### Protocol indicators

- HTTP
- HTTPS
- DNS
- Telnet
- SMTP
- SSH
- IRC
- TCP
- UDP
- DHCP
- ARP
- ICMP
- IPv
- LLC

### Packet/statistical features

- Header_Length
- Tot sum
- Min
- Max
- AVG
- Std
- Tot size
- Magnitue
- Radius
- Covariance
- Variance
- Weight

Do NOT assume which features are important.

Compare:

- Random Forest importance
- XGBoost importance
- SHAP

Generate attack-specific behavioral profiles from the actual experiments.

---

# 7. MACHINE LEARNING

ML is the **attack detection and behavioral analysis layer**, not the main research contribution.

Use:

- Random Forest
- XGBoost

Optionally compare another baseline.

Support:

- training
- validation
- testing
- model persistence
- inference.

Prefer:

70% training  
15% validation  
15% testing

OR use 70/30 with cross-validation if that is more appropriate for the actual dataset.

Choose based on dataset size and class distribution and explain the decision.

Handle class imbalance scientifically.

Report:

- accuracy
- precision
- recall
- F1
- confusion matrix
- per-class metrics
- feature importance
- SHAP
- inference time.

---

# 8. SYSTEM ARCHITECTURE

Preferred architecture:

CICIoT2023  
↓  
Data Ingestion  
↓  
Preprocessing  
↓  
ML Attack Detection  
↓  
Behavioral Profiling  
↓  
SIEM Alert  
↓  
LangGraph Agentic Investigation  
↓  
MongoDB Security Event Repository  
↓  
Entity Extraction  
↓  
Threat Intelligence  
↓  
Neo4j Dynamic Knowledge Graph  
↓  
Adaptive Evidence Collection  
↓  
Attack Chain Reconstruction  
↓  
Gemini LLM Attack Story  
↓  
Evidence-backed Investigation Report  
↓  
React SOC Dashboard

---

# 9. TECHNOLOGY STACK

Prefer this stack unless there is a strong technical reason to change it:

### Backend

Python + FastAPI

### ML

- Pandas
- NumPy
- Scikit-learn
- XGBoost
- SHAP

### Databases

MongoDB — security events and investigation data

Neo4j — investigation knowledge graph

### Agent orchestration

LangGraph

### LLM

Gemini API

Do NOT hard-code a specific Gemini model.

Use:

`GEMINI_MODEL`

and verify current Gemini API/model availability before implementation.

### Threat intelligence

- VirusTotal API
- AlienVault OTX API

### ATT&CK

Use publicly available MITRE ATT&CK data/API/package.

Do not assume an API key is required.

### Frontend

React

### Graph

Cytoscape.js preferred.

Plotly/D3.js may be used for other visualizations.

---

# 10. ENVIRONMENT VARIABLES

Use `.env`.

Never hard-code credentials.

Never expose credentials to React.

Never commit `.env`.

Provide `.env.example`:

```text
GEMINI_API_KEY=
GEMINI_MODEL=

VIRUSTOTAL_API_KEY=
OTX_API_KEY=

MONGODB_URI=

NEO4J_URI=
NEO4J_USERNAME=
NEO4J_PASSWORD=
```

Paid APIs must NOT be mandatory for the basic application.

If an external threat-intelligence service is unavailable, the system must continue using available evidence.

---

# 11. EIGHT LOGICAL AGENTS

Use eight logical agents.

They do NOT need to be eight different LLMs.

A shared LLM with different roles, tools, and prompts is acceptable.

## Agent 1 — Data Ingestion Agent

Responsibilities:

- inspect dataset
- validate schema
- detect malformed records
- ingest batches
- report ingestion statistics.

Output:

Validated security-event records.

## Agent 2 — Preprocessing & Behavioral Analysis Agent

Responsibilities:

- cleaning
- normalization
- missing-value handling
- feature analysis
- feature importance
- behavioral profiles
- attack prediction.

## Agent 3 — Alert Investigation Agent

Responsibilities:

- interpret alert
- inspect initial evidence
- identify entities
- formulate hypothesis
- decide what evidence should be investigated next.

This agent must choose actions/tools rather than simply generate text.

## Agent 4 — Threat Intelligence Agent

Responsibilities:

- extract IPs
- extract domains
- extract hashes where available
- VirusTotal lookup
- OTX lookup
- reputation enrichment
- MITRE ATT&CK mapping where appropriate.

Only passive threat-intelligence lookups.

## Agent 5 — Knowledge Graph Agent

Responsibilities:

- identify entities
- create nodes
- create relationships
- add timestamps
- add attack labels
- add behavioral evidence
- add threat intelligence
- update graph as new evidence arrives.

## Agent 6 — Adaptive Evidence Collection Agent

This is a **primary research component**.

The agent must:

1. inspect current investigation state,
2. inspect current graph,
3. identify missing relationships/evidence,
4. determine what evidence is needed,
5. select a retrieval tool,
6. query the evidence repository,
7. record evidence,
8. update investigation state,
9. update graph,
10. reassess,
11. repeat if necessary.

Do NOT implement this as a fixed sequence.

The next action must depend on the current investigation state.

Set safeguards:

- MAX_INVESTIGATION_STEPS
- MAX_EVENTS_PER_QUERY
- MAX_TIME_WINDOW
- MAX_GRAPH_NODES

Stop when:

- sufficient evidence exists,
- maximum depth is reached,
- or no relevant additional evidence exists.

## Agent 7 — Attack Reconstruction Agent

Responsibilities:

- correlate timestamps
- traverse graph
- correlate source/destination entities
- identify stages
- connect related alerts
- produce chronological attack chain.

Do not force every incident into a predefined kill chain if evidence does not support it.

## Agent 8 — Attack Story & Report Agent

Responsibilities:

- summarize evidence
- explain attack progression
- generate narrative
- include supporting evidence
- include MITRE mapping
- assign severity based on evidence
- recommend actions
- generate final report.

The LLM must never invent evidence.

---

# 12. AGENTIC INVESTIGATION LOOP

The investigation should follow this general logic:

```text
ALERT
  ↓
Investigation Agent
  ↓
Inspect Current Evidence
  ↓
Determine Next Action
  ↓
MongoDB / Threat Intelligence / Graph
  ↓
Retrieve Evidence
  ↓
Update Investigation State
  ↓
Knowledge Graph Agent
  ↓
Adaptive Evidence Agent
  ↓
Is Evidence Sufficient?
  ├── NO → Retrieve More Evidence
  │          ↓
  │       Update Graph
  │          ↓
  │       Reassess
  │
  └── YES
       ↓
Attack Reconstruction
       ↓
Attack Chain
       ↓
Attack Story / Report
```

This loop is essential.

Do NOT implement:

```text
Alert → Gemini → Summary
```

---

# 13. INVESTIGATION TOOLS

Create tool functions such as:

```text
search_security_events()
get_events_by_ip()
get_events_by_time_range()
get_events_by_device()
get_related_events()
get_authentication_events()
get_network_events()
get_dns_events()
get_firewall_events()
```

Threat intelligence:

```text
check_virustotal_ip()
check_virustotal_domain()
check_virustotal_hash()
check_otx_indicator()
```

Graph:

```text
create_graph_node()
create_graph_relationship()
query_related_nodes()
get_attack_subgraph()
```

Investigation:

```text
get_investigation_state()
update_investigation_state()
record_evidence()
mark_evidence_as_supporting()
identify_missing_evidence()
```

The agent must choose tools according to investigation state.

---

# 14. MONGODB MODEL

Create collections:

```text
security_events
alerts
investigations
threat_intelligence
behavior_profiles
reports
```

Security event example:

```json
{
  "timestamp": "...",
  "source_ip": "...",
  "destination_ip": "...",
  "protocol": "TCP",
  "features": {
    "Rate": 0,
    "Srate": 0,
    "Drate": 0,
    "IAT": 0
  },
  "attack_type": "...",
  "source": "CICIoT2023"
}
```

Use appropriate indexes for:

- timestamp
- source_ip
- destination_ip
- protocol
- attack_type

Do not index every field unnecessarily.

---

# 15. NEO4J GRAPH

Potential node types:

```text
IP
Device
User
Domain
File
Process
Attack
Event
IOC
Behavior
MITRETechnique
```

Potential relationships:

```text
COMMUNICATES_WITH
TARGETS
GENERATES
PERFORMS
ASSOCIATED_WITH
RESOLVES_TO
EXECUTES
CONNECTS_TO
INDICATES
PART_OF
OCCURS_BEFORE
MAPS_TO
SUPPORTED_BY
```

Every relationship should retain appropriate timestamps/evidence references.

---

# 16. GRAPH GENERATION RULE

Do NOT ask the LLM to invent graph relationships.

The graph should primarily be constructed deterministically:

1. extract entities,
2. normalize entities,
3. create nodes,
4. derive relationships from structured data,
5. add timestamps,
6. add behavioral metadata,
7. add threat-intelligence information,
8. store in Neo4j,
9. use the LLM only for interpretation/reasoning where appropriate.

Every graph node/relationship should be traceable to supporting evidence.

The UI must allow an analyst to click a graph node and inspect the supporting evidence.

---

# 17. ADAPTIVE EVIDENCE EXAMPLE

Suppose an alert is:

```text
SYN Flood from IP A
```

Current graph:

```text
IP A
 ↓
communicates with
 ↓
Device B
```

The adaptive agent should ask:

```text
What evidence is missing to understand this incident?
```

Possible evidence:

- previous activity from IP A
- other devices contacted by IP A
- DNS activity
- firewall events
- related alerts
- authentication events where applicable.

The agent should select the most relevant next query based on the current state.

After retrieving evidence:

```text
Graph Update
     ↓
Reassessment
     ↓
More evidence required?
```

Continue until sufficient evidence exists or limits are reached.

---

# 18. ATTACK RECONSTRUCTION

Use:

- timestamps
- source/destination relationships
- attack labels
- behavioral profiles
- threat intelligence
- graph relationships.

Produce:

1. chronological timeline
2. attack stages
3. relationships
4. supporting evidence.

The attack chain must be evidence-based.

---

# 19. LLM RULES

Use the LLM for:

- investigation reasoning
- next-action selection
- structured-evidence interpretation
- attack-chain explanation
- attack narrative
- report generation.

Do NOT use the LLM for:

- processing millions of rows
- replacing database queries
- inventing graph relationships
- inventing threat intelligence
- unsupported conclusions.

Before sending data to the LLM:

**retrieve → filter → compress → structure → send**

Never send the entire dataset.

---

# 20. HALLUCINATION CONTROL

Every important conclusion must maintain:

```text
claim
+
supporting evidence IDs
+
source records
+
timestamp
```

If evidence is insufficient, explicitly state:

> Insufficient evidence

Never invent an explanation.

For example, the system may conclude:

> Possible brute-force activity.

Supported by:

- 18 failed connection attempts
- short inter-arrival times
- SSH traffic
- same source IP.

But it must NOT claim:

> The attacker stole the password.

unless actual evidence supports that conclusion.

---

# 21. SOC WEB APPLICATION

Build a professional SOC-style interface.

Pages:

1. Login / Landing
2. Dashboard
3. Alerts
4. Alert Details
5. Investigation
6. Knowledge Graph
7. Attack Timeline
8. Threat Intelligence
9. Investigation Report
10. Model / Behavioral Analytics
11. Configuration

---

# 22. DASHBOARD

Display:

- total alerts
- critical
- high
- medium
- low
- active investigations
- resolved investigations
- attack distribution
- category distribution
- recent alerts
- recent investigations.

Use charts carefully.

Do not overload the dashboard.

---

# 23. ALERT DETAILS

Display:

- Alert ID
- attack type
- category
- timestamp
- source IP
- destination IP
- protocol
- severity
- behavioral evidence
- important features
- feature importance
- related events
- threat intelligence
- investigation status.

Provide:

**Start Investigation**

button.

---

# 24. INVESTIGATION PAGE

Display:

- investigation ID
- initial alert
- status
- current hypothesis
- evidence collected
- evidence required
- agent actions
- threat intelligence
- graph preview
- attack timeline
- attack chain
- final conclusion.

Show agent activity transparently.

Example:

```text
Step 1 — Alert received
Step 2 — Related events searched
Step 3 — Threat intelligence checked
Step 4 — Graph updated
Step 5 — Additional evidence requested
Step 6 — Attack chain reconstructed
```

---

# 25. KNOWLEDGE GRAPH PAGE

Use an interactive Cytoscape.js graph.

Support:

- zoom
- pan
- node selection
- node details
- evidence inspection
- entity-type filtering
- time filtering.

Potential visualization:

```text
Attacker IP
   ↓
Port Scan
   ↓
Target Device
   ↓
Brute Force
   ↓
Successful Access
   ↓
Command Injection
   ↓
External IP
```

Only display relationships supported by actual evidence.

---

# 26. ATTACK TIMELINE

Create an interactive chronological timeline.

Example:

```text
10:01  Port Scan
10:05  Brute Force
10:09  Successful Access
10:10  Command Injection
10:12  Suspicious External Communication
```

Every event must be clickable and expose its supporting source record.

---

# 27. THREAT INTELLIGENCE

Display:

- indicator
- type
- source
- reputation
- first/last seen when available
- associated information
- source-provided threat score
- related domains
- related hashes
- MITRE mapping where available.

Clearly distinguish:

**Actual API result**

from

**AI interpretation**

Never fabricate threat-intelligence results.

---

# 28. FINAL REPORT

Generate:

1. Incident title
2. Alert summary
3. Severity
4. Affected entities
5. Source/destination information
6. Attack timeline
7. Attack chain
8. Knowledge graph summary
9. Behavioral evidence
10. Threat intelligence
11. MITRE ATT&CK mapping
12. Supporting evidence
13. AI-generated attack narrative
14. Recommended actions
15. Investigation limitations.

Support PDF export if practical.

---

# 29. PERFORMANCE

CICIoT2023 is large.

Implement:

- chunked CSV reading
- batch processing
- bulk database insertion
- indexes
- pagination
- caching where useful
- limited LLM context
- asynchronous external API calls.

Never:

- send the complete dataset to the LLM
- query millions of MongoDB records unnecessarily
- load massive files into memory without justification.

---

# 30. RESEARCH EVALUATION

Do not evaluate only ML accuracy.

Evaluate:

## A. Detection

- Accuracy
- Precision
- Recall
- F1
- Confusion matrix

## B. Behavioral profiling

- important features
- SHAP values
- feature reduction
- profile quality

## C. Investigation

- completion rate
- retrieved evidence count
- investigation steps
- latency
- related events discovered

## D. Knowledge graph

- nodes
- edges
- graph construction time
- relevant relationship retrieval

## E. Adaptive investigation

Compare:

### Baseline

```text
Alert
 ↓
Fixed Queries
 ↓
Report
```

versus:

### Proposed

```text
Alert
 ↓
Agent
 ↓
Adaptive Evidence Collection
 ↓
Dynamic Knowledge Graph
 ↓
Attack Reconstruction
 ↓
Report
```

Compare:

- investigation time
- database queries
- events retrieved
- relevant evidence discovered
- attack-chain completeness
- report quality.

This comparison is critical to demonstrate the research contribution.

## F. LLM

Evaluate:

- factual correctness
- evidence grounding
- hallucination rate
- narrative completeness
- analyst readability.

---

# 31. DEVELOPMENT PHASES

Implement in this order:

### Phase 1
Dataset inspection

Output:

- schema
- row count
- attack labels
- class distribution
- missing values
- feature statistics.

### Phase 2
Preprocessing pipeline

### Phase 3
ML baseline

### Phase 4
Feature importance + SHAP

### Phase 5
MongoDB ingestion

### Phase 6
Alert generation

### Phase 7
LangGraph agent framework

### Phase 8
Investigation tools

### Phase 9
Threat intelligence

### Phase 10
Neo4j graph

### Phase 11
Adaptive evidence collection

### Phase 12
Attack reconstruction

### Phase 13
LLM attack story

### Phase 14
FastAPI backend

### Phase 15
React frontend

### Phase 16
Full integration

### Phase 17
Testing and evaluation

### Phase 18
Demonstration scenarios

---

# 32. PROJECT STRUCTURE

Use a modular structure similar to:

```text
project/
│
├── backend/
│   ├── main.py
│   ├── config.py
│   ├── agents/
│   ├── tools/
│   ├── models/
│   ├── services/
│   ├── routes/
│   └── utils/
│
├── frontend/
│   └── src/
│       ├── components/
│       ├── pages/
│       └── services/
│
├── data/
│
├── ml/
│   ├── preprocessing/
│   ├── training/
│   ├── evaluation/
│   └── explainability/
│
├── graph/
│   ├── schema/
│   └── queries/
│
├── tests/
│
├── .env.example
├── requirements.txt
├── README.md
└── docker-compose.yml
```

Maintain clear separation between:

- ML
- agents
- tools
- databases
- backend
- frontend
- external APIs.

---

# 33. DOCKER

If practical, provide Docker Compose for:

- MongoDB
- Neo4j
- backend
- frontend.

Also provide a simple local-development setup.

Docker should not make local development unnecessarily complicated.

---

# 34. SECURITY

This is a defensive cybersecurity research project.

Do NOT implement:

- credential attacks
- real brute-force attacks
- exploit execution
- malware execution
- unauthorized scanning
- active attacks against external systems.

All attack analysis must use:

- CICIoT2023
- controlled data
- simulated data.

Threat-intelligence integrations must only perform passive lookups.

---

# 35. API DESIGN

Design REST APIs for at least:

```text
GET  /api/health

GET  /api/dataset/stats
GET  /api/alerts
GET  /api/alerts/{id}

POST /api/investigations
GET  /api/investigations/{id}
POST /api/investigations/{id}/start
GET  /api/investigations/{id}/events
GET  /api/investigations/{id}/timeline
GET  /api/investigations/{id}/graph
GET  /api/investigations/{id}/report

GET  /api/threat-intelligence/{indicator}

GET  /api/models
GET  /api/behavior-profiles
GET  /api/evaluation
```

Modify this API structure if necessary after architecture review.

---

# 36. LANGGRAPH STATE

Design a shared structured investigation state containing concepts such as:

```text
investigation_id
alert_id
current_hypothesis
entities
evidence
missing_evidence
tool_history
threat_intelligence
graph_state
attack_chain
confidence
investigation_step
termination_reason
final_report
```

Use structured state rather than passing uncontrolled text between agents.

Every agent should have clearly defined:

- input
- output
- tools
- state changes
- termination conditions.

---

# 37. IMPLEMENTATION QUALITY

When implementation begins:

For every phase provide:

1. What is being built
2. Why it exists
3. File structure
4. Complete runnable code
5. Installation commands
6. Run commands
7. Test commands
8. Expected output
9. Verification checklist
10. Known limitations.

Do not provide disconnected snippets.

Code must be internally consistent across phases.

Do not rewrite unrelated components unnecessarily.

---

# 38. CRITICAL NON-FABRICATION RULES

NEVER:

- fabricate dataset statistics
- fabricate attack labels
- fabricate threat-intelligence results
- fabricate graph relationships
- claim unsupported feature semantics
- invent evidence
- invent MITRE mappings
- hard-code API keys
- expose secrets to frontend
- send massive datasets to the LLM
- create unnecessary expensive LLM agents
- implement adaptive investigation as a fixed query sequence.

When information is unavailable, explicitly state:

**"Not available from the current evidence."**

When evidence is insufficient:

**"Insufficient evidence."**

---

# 39. RESEARCH RIGOR

Whenever making a research claim:

- distinguish measured results from assumptions,
- identify what was experimentally verified,
- identify what is inferred,
- avoid unsupported novelty claims,
- preserve reproducibility,
- record experiment configuration,
- record model versions,
- record dataset version/files,
- record evaluation metrics.

The application should make it possible to trace:

**Alert → Evidence → Graph → Investigation Decision → Attack Chain → Report Claim**

This traceability is a core design requirement.

---

# 40. FIRST RESPONSE — STRICT REQUIREMENT

For your FIRST response to this prompt:

**DO NOT generate the complete application.**

Instead perform a **technical architecture/design review**.

Your response must contain:

## 1. Executive architecture

## 2. Complete data flow

## 3. Eight-agent architecture

## 4. Tool architecture

## 5. MongoDB schema

## 6. Neo4j schema

## 7. LangGraph state design

## 8. API architecture

## 9. ML experiment design

## 10. Adaptive evidence-collection algorithm

## 11. React/SOC dashboard architecture

## 12. Project directory structure

## 13. Development phases

## 14. Dependencies

## 15. Environment variables

## 16. Testing strategy

## 17. Research evaluation methodology

## 18. Risks, bottlenecks, and solutions

## 19. Decisions that must be confirmed before implementation

Do not invent dataset statistics unless the actual dataset files have been inspected.

If the dataset files are available in the working environment, inspect them before making dataset-specific claims.

After the architecture review, wait for confirmation before beginning the next implementation phase.

---

# FINAL OBJECTIVE

Build a functioning academic prototype that demonstrates:

> **From a raw security alert to an evidence-backed reconstruction of what happened.**

The final system must allow a SOC analyst to:

**View alerts → select alert → start investigation → observe agentic investigation → inspect evidence → view behavioral analysis → view threat intelligence → observe dynamic knowledge graph → observe adaptive evidence retrieval → inspect attack timeline → inspect reconstructed attack chain → read evidence-grounded AI attack story → inspect supporting evidence → view MITRE mappings → view recommendations → export report.**