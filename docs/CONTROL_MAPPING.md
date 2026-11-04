# Control mapping: what Perathos evidence supports, control by control

For compliance leads, AIUC-1 and SOC 2 auditors, and insurers. Perathos is not a compliance
product and nothing here is a claim that using it makes an organisation compliant. It produces
specific, independently verifiable artefacts. This page says which control each artefact is
evidence for, how much of the control it covers, and what you still need from elsewhere.

Control text is quoted from the primary sources listed at the end, as of 4 November 2026.
Where a source could only be read second-hand, the row says so.

## The artefacts

| Id | Artefact | Where | What it shows |
|---|---|---|---|
| P1 | Receipt log | `.perathos/sessions/<session>.jsonl` | One `pre` and one `post` receipt per agent tool call: tool name, SHA-256 of the arguments and of the result, status, timestamp, each chained to the previous receipt. Content is never stored, only hashes. |
| P2 | Signed checkpoints | in P1, `kind: checkpoint`; `.head.json` witness | Ed25519 signature over the chain at the end of every turn and at session end. Detects any edit, deletion, insertion or reordering before it. |
| P3 | Independent timestamps | `~/.perathos/anchors/<session>.jsonl` | RFC 3161 token from a Time Stamping Authority for each checkpoint. Gives each turn a time the operator's clock cannot fake and makes a cut-off log detectable. |
| P4 | Guard decisions | in P1, `guard` field on `pre` receipts | For each destructive command matched: `deny`, or `allow` with the hash of the precondition relied on. The denied command never ran. |
| P5 | Preconditions | `.perathos/preconditions/*.json` | A person's signed record that a named safety check ran and passed (command, exit code, output hash, signer, created, expires), created outside the agent session. |
| P6 | Evidence pack | `perathos session export` | P1 to P5 plus `verification.json`, a one-page report and a signed `MANIFEST.json` of every file's SHA-256. Re-checked by `perathos evidence verify` or the browser verifier. |
| P7 | Enforcement configuration | `.claude/settings.json`, `.cursor/hooks.json`, managed policy file | Hook entries with `onFailure: "block"` / `failClosed: true`; with `--scope managed`, `allowManagedHooksOnly: true` so the agent cannot change hooks. |
| P8 | Verifier | `perathos evidence verify`, `site/verify/` | Two independent implementations (Python, JavaScript) of the same checks; the receipt format is public (`specs/RECEIPT_V1.md`). |

Coverage key: **Full** = the artefact is the evidence the control's own evidence guidance
describes. **Partial** = it covers a named part; the row says which part is missing.
**Context** = useful supporting evidence, not the control's main evidence.

## AIUC-1 (AI Underwriting Company standard for AI agents)

Control text and tags are verbatim from the published control list at
standard.aiuc-1.com/evidence/index and the dated changelogs. "Mandatory Control" and
"Supplemental Control" are the standard's own tags.

| Control | Tag | The control asks for | Perathos evidence | Coverage | Still needed |
|---|---|---|---|---|---|
| **D003.4** Config: Human-approval workflows | Mandatory Control since 15 Oct 2026 | "Requiring human approval for sensitive tool operations ... Approval workflow configuration, code or ticketing system for sensitive, high-risk, or multi-step tool operations requiring human confirmation (e.g., executing financial transactions, **deleting or irreversibly modifying records**, and changing credentials or permissions)." | P4 + P5: the guard denies destructive commands until a person has run and signed a precondition; every allow records which one. P7 shows it is enforced and fail-closed. | **Full** for destructive data operations (the rule set in `guard.py`). | Financial transactions and credential changes are not in the rule set; add approval workflows for those separately. |
| **D003.3** Config: Tool call log | Mandatory Control | "tracking all tool calls ... log entries capturing the originating MCP server, tool name, tool version, input parameters, and timestamps per invocation" | P1: every tool call with tool name (MCP server name is part of the tool id), timestamps and hashes of inputs. | Partial | Input parameters are stored as hashes, not values; tool version is not recorded. Keep the originals if reviewers need parameter values. |
| **D003.1** Config: Tool authorization & validation | Mandatory Control | "restricting tool calls to approved functions and MCP servers, validating parameters before execution" | P4: parameter validation for destructive patterns before execution, including inside MCP arguments. | Partial | Perathos is a deny-list for destructive actions, not an allow-list of approved tools. |
| D003.2 Config: Rate limits for tools | Mandatory Control | rate limits and transaction caps | none | None | Rate limiting is out of scope. |
| D003.5 Documentation: tool call log reviews | Supplemental | "periodic review of tool usage patterns" | P1 via `perathos session show`, P6 reports as review input. | Context | The review itself and its records are yours. |
| **E015.4** Config: Log integrity protection | Supplemental | "logs are tamper-evident and independently verifiable ... captured records cannot be modified or deleted after creation, ensuring sequence integrity so that gaps, omissions, and reordering are detectable ... cryptographic hashing of log entries, append-only" | P1 + P2 + P3 + P8: hash-chained, signed, independently timestamped, verifiable by two implementations; `session verify` reports gaps, omissions, reordering and truncation. | **Full** | Nothing for the control as written. Note: truncation after the last checkpoint is detectable only with P3 kept where the agent cannot reach it. |
| **E015.2** Config: AI agent logging implementation | Supplemental | "tool call parameters and results, sub-agent delegations and their outcomes, approval/authorization events (e.g., human-in-the-loop approvals), and reasoning traces" | P1 for tool calls and results (hashed); P4 + P5 for approval events "linked to execution (approver identity, timestamp, decision outcome)". | Partial | Sub-agent delegation chains (only a `SubagentStop` checkpoint is recorded) and reasoning traces are not captured. |
| E015.1 Config: Logging implementation | Mandatory Control | "logging inputs, processing steps, outputs, and metadata" | P1 metadata and hashes. | Partial | Inputs and outputs themselves are not stored; pair Perathos with your transcript or application logs. |
| E015.3 Config: Log storage | Mandatory Control | retention periods, access controls, data sanitation | P1 is append-only and content-free (sanitation by design). | Partial | Retention and access control are your storage's job. |
| E001 / E001.1 AI failure plan for security breaches | Mandatory | "Establishing evidence collection requirements with guidance on preserving evidence for potential legal review. For example, system logs, user activity records" | P6: a signed, timestamped evidence pack per session, re-verifiable offline. | Partial (the evidence-collection bullet) | The plan document is yours. |
| E004.1 Documentation: Change approval policy and records | Mandatory Control | "approval records showing sign-offs with supporting evidence" | P5 + P4: signed approval records for destructive changes, bound to the action. | Partial | Covers destructive operations only, not model or prompt changes. |
| E009 / E009.1 Monitor third-party access | Mandatory | "logging for third-party interactions ... API connections, user access sessions, data exchanges, and service integrations" | P1 via `perathos mcp-proxy`: every call to a third-party MCP server. | Partial | Only MCP traffic; no sessions, IPs or alerting (E009.2). |
| **B006.3** Config: Execution-level safeguards | Supplemental | "monitoring MCP tool definitions for unauthorized changes after initial approval, providing **pre-execution authorization hooks that verify runtime tool calls against defined policy before execution proceeds**, or scanning agent configuration artifacts such as hooks" | P4 + P7: the guard is a pre-execution authorization hook; writes to hook and settings files are denied. | Partial (the hook bullet) | Sandboxing and MCP tool-definition monitoring are not provided. |
| B006.2 Config: Agent security monitoring and alerting | Mandatory Control | "logging all agent service interactions, alerting on access attempts" | P1 + P4 (denied attempts are receipts). | Partial | No alerting; wire deny receipts into your SIEM. |
| B006.1 Config: Agent service access restrictions | Mandatory Control | restrict agents to approved services and MCP servers | P4 restricts destructive actions only. | Context | Allow-listing is yours. |
| B007.1 Config: User access controls | Mandatory Control | "limiting ability to alter system behavior, tools, or models" | P7 with `--scope managed`: the agent cannot alter hooks. | Partial | Human user access control is yours. |
| A008.5 Secrets redaction in logs and stored artifacts | Supplemental (coding agents) | "prevent secrets from being retained in platform logs" | P1 never stores arguments or outputs, only SHA-256 hashes, so a secret cannot be read from a Perathos log. | **Full** for Perathos's own logs | Short guessable values can be confirmed by hashing a guess (documented). Your other logs are yours. |
| A003.2 Agent identity management | Supplemental | "each agent a unique, cryptographically verifiable identity" | none: P2 proves the operator's key, not the agent's. | None | Agent identity binding is not provided. |
| C005.2 / C007.3 Human review workflows | Supplemental / Optional | escalation and approval workflows for high-risk cases | P5 is a concrete approval workflow for one class of high-risk action. | Context | |
| E018.1 Third-party evaluation report | Mandatory Control since 15 Oct 2026 | third-party testing for accountability risk | P6 packs are portable artefacts an assessor can verify independently. | Context | The assessment itself is the assessor's. |

## SOC 2 (AICPA Trust Services Criteria, 2017, 2022 points of focus)

Criterion wording below is from a public transcription of the TSC; the AICPA PDF sits behind
a registration wall. Verify against the AICPA text before quoting in a report.

| Criterion | Text | Perathos evidence | Coverage |
|---|---|---|---|
| CC8.1 Change management | "The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures" | P1 is a tamper-evident record of every change an agent made (as hashes of tool calls); P5 is the authorisation record for destructive ones. | Partial: authorisation and documentation of agent-made changes. |
| CC7.2 Monitoring for anomalies | "monitors system components ... for anomalies that are indicative of malicious acts, natural disasters, and errors" | P4 deny receipts are detected anomalies in agent behaviour. | Partial |
| CC7.3 / CC7.4 Security event evaluation and incident response | evaluate events; "understand, contain, remediate, and communicate security incidents" | P6 is the evidence base for understanding what an agent did in an incident; P4 shows containment at the moment of the action. | Partial |
| CC6.3 Least privilege | "authorizes, modifies, or removes access ... giving consideration to the concepts of least privilege and segregation of duties" | P5 enforces segregation of duties: the agent cannot approve its own destructive action; the approver is a person with the key. P7 removes the agent's ability to alter its controls. | Partial |
| A1.2 Backup and recovery (Availability) | "data back-up processes, and recovery infrastructure" | P5 with a restore check (`--check "pg_restore --list ..."`) is a signed record that a backup was restorable at a given time before data was deleted. | Partial: verification evidence, not the backup process itself. |
| PI1.5 Storage of inputs and outputs (Processing Integrity) | "store inputs, items in processing, and outputs completely, accurately" | P1 + P2 prove stored records are complete and unmodified in sequence. | Partial: integrity of the record, not of the data itself. |

## NCSC and partner guidance

| Source | Text | Perathos evidence |
|---|---|---|
| Guidelines for secure AI system development (NCSC, CISA and 21 agencies, Nov 2023), Secure design | "if AI components need to trigger actions, for example amending files or directing output to external systems, you apply appropriate restrictions to the possible actions (this includes external AI and non-AI fail-safes if necessary)" | P4 + P7: a non-AI fail-safe in front of destructive actions, fail-closed. |
| Same, Secure development | "You treat logs as sensitive data and implement controls to protect their confidentiality, integrity and availability." | P1 to P3 for integrity; content-free logs for confidentiality. Availability is your storage's job. |
| Same, Secure deployment | "You provide high-quality audit logs and other security features or information to customers and users at no extra charge, to enable their incident response processes." | P6: portable, verifiable packs. |
| Same, Secure operation | "you monitor and log inputs to your system ... to enable compliance obligations, audit, investigation and remediation" | P1 (hashed inputs). |
| NCSC blog "Thinking carefully before adopting agentic AI" (15 May 2026) | "If you cannot understand, monitor or contain an agent's actions, it is not ready for deployment"; know "who approves its access, who monitors its behaviour, who reviews incidents, and ultimately who can stop it" | P1 (monitor), P4 (contain), P5 (who approved, signed), P6 (review incidents). |
| Joint guidance "Careful adoption of agentic AI services" (1 May 2026, ACSC lead, CISA, NSA, NCSC-UK and others) | Primary page could not be fetched; a secondary summary reports it calls for logging every agent action including tool-call chains and human-in-the-loop approval for high-impact or irreversible actions. | P1 and P4/P5 respectively. Treat this row as unconfirmed until read in the original. |

## ISO/IEC 42001:2023 (Annex A, titles only; the standard is paywalled)

| Control | Perathos evidence |
|---|---|
| A.6.2.6 AI system operation and monitoring | P1, P4 as operational records. |
| A.6.2.8 AI system recording of event logs | P1 to P3: event logs with integrity protection for the agent-execution phase of the life cycle. |
| A.8.4 Communication of incidents | P6 as the shareable incident record. |

ISO 42001 has no Annex A control titled "human oversight"; A.9.4 is "Intended use of the AI
system". Cite human-oversight evidence (P4, P5) against the standard's clause text and Annex B
guidance, not an Annex A number.

## EU AI Act (Regulation (EU) 2024/1689)

Applies to high-risk systems only. After Regulation (EU) 2026/1744, Annex III high-risk
obligations, including Articles 12 and 14, apply from 2 December 2027 (Annex I systems from
2 August 2028). Most coding-agent deployments are not high-risk; where one is embedded in a
high-risk system:

| Article | Text | Perathos evidence |
|---|---|---|
| Art. 12(1) Record-keeping | "High-risk AI systems shall technically allow for the automatic recording of events (logs) over the lifetime of the system." | P1 to P3 for the agent's actions. |
| Art. 12(2) | logging "shall enable the recording of events relevant for ... identifying situations that may result in the high-risk AI system presenting a risk" | P4 records every destructive attempt, allowed or denied. |
| Art. 14(1) Human oversight | systems "can be effectively overseen by natural persons during the period in which they are in use" | P5 is a built-in oversight measure for destructive actions; P4 proves it operated. |

## NIST AI RMF 1.0 (voluntary)

| Subcategory | Text | Perathos evidence |
|---|---|---|
| MEASURE 2.8 | "Risks associated with transparency and accountability ... are examined and documented." | P6 |
| MANAGE 2.4 | "Mechanisms are in place ... to supersede, disengage, or deactivate AI systems that demonstrate performance or outcomes inconsistent with intended use." | P4 (stops a specific class of action; not a system kill switch) |
| MANAGE 4.1 | post-deployment monitoring including "appeal and override, decommissioning, incident response, recovery, and change management" | P1, P5, P6 |
| MANAGE 4.3 | "Processes for tracking, responding to, and recovering from incidents and errors are followed and documented." | P6 |
| MAP 3.5 | "Processes for human oversight are defined, assessed, and documented" | P5 (defined and evidenced for destructive actions) |

NIST CAISI's AI Agent Standards Initiative publishes no audit or non-repudiation requirement
as of August 2026; do not cite it for that.

## US Federal Rules of Evidence 902(13) and (14)

Rule 902(14) allows data copied from a device or file to self-authenticate "by a process of
digital identification" certified by a qualified person; the 2017 Committee Note says this is
"ordinarily" a hash value. Rule 902(13) does the same for "a record generated by an electronic
process or system that produces an accurate result".

An evidence pack supports such a certification: every file's SHA-256 is in the signed
manifest, the receipt chain is reproducible from the public spec, and `perathos evidence
verify` is the process the certifier ran. The Committee Note is explicit that authentication
is all the rule establishes: it "does not preclude an objection that the information produced
is unreliable", and hearsay must be addressed separately. This is not legal advice.

## What Perathos does not supply, for every framework above

- Which model ran. The `model` field is self-reported.
- The content of inputs and outputs. Only hashes; keep originals if reviewers need them.
- Proof that recording was on for the whole period. A gap where hooks were off is invisible;
  P7 with managed settings is how you make switching off impossible rather than merely
  recorded.
- Protection against a deliberately hostile agent. The guard matches patterns; it is a
  safeguard against accidents.
- Retention, access control and alerting for the logs. Those belong to your log storage and
  SIEM.
- Agent identity, rate limits, sandboxing, allow-lists of approved tools.
- Any assessment, policy or plan document. Perathos produces evidence, not the paperwork
  around it.

## How to hand this to an auditor

1. Export the pack: `perathos session export <session> --out <dir>`.
2. Give the auditor the `.zip`, your public key through a separate channel, and this page.
3. They run `perathos evidence verify <zip> --verify-key <key>` (or use the browser verifier)
   and read `REPORT.html`.
4. For each control row above, point to the artefact id; for D003.4 and E015.4 the pack is the
   whole evidence.

## Sources

- AIUC-1 control list: https://standard.aiuc-1.com/evidence/index ; changelogs
  https://standard.aiuc-1.com/changelog/2026-10-15 and https://standard.aiuc-1.com/changelog/2026-07-15
- AICPA 2017 TSC with 2022 points of focus (registration required):
  https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022
- NCSC Guidelines for secure AI system development (27 Nov 2023):
  https://www.ncsc.gov.uk/collection/guidelines-secure-ai-system-development ;
  NCSC blog 15 May 2026: https://www.ncsc.gov.uk/blogs/thinking-carefully-before-adopting-agentic-ai ;
  joint guidance 1 May 2026: https://www.cisa.gov/resources-tools/resources/careful-adoption-agentic-ai-services
- ISO/IEC 42001:2023 Annex A titles (secondary): https://www.isms.online/iso-42001/annex-a-controls/
- EU AI Act Articles 12 and 14: https://artificialintelligenceact.eu/article/12/ ,
  https://artificialintelligenceact.eu/article/14/ ; applicability dates per Regulation (EU) 2026/1744
- NIST AI RMF 1.0: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf ;
  CAISI initiative: https://www.nist.gov/caisi/ai-agent-standards-initiative
- FRE 902: https://www.law.cornell.edu/rules/fre/rule_902
