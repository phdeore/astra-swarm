# Astra-Swarm — Multi-Agent SOC & Identity-Threat Triage System
(in progress)
Python · Anthropic Claude · LangGraph · Pydantic v2 · MITRE ATT&CK · Google Colab
An agentic AI system that triages security alerts (SIEM, EDR, IAM, firewall) through a compiled LangGraph state machine, with specialist worker agents, self-correcting evaluation loops, and entity-based incident correlation.

Agentic architecture: router → orchestrator → parallel worker nodes (ATT&CK enrichment, identity/auth analysis) → assessment → evaluator loop with bounded refinement passes.
Structured outputs: strict JSON-schema-constrained responses at every stage via Anthropic's output_config, with client-side Pydantic validation for constraints the grammar can't express.
Tool-augmented reasoning: real-time MITRE ATT&CK STIX lookups (700+ techniques indexed) and synthetic auth-log queries for identity-threat detection (impossible-travel, MFA fatigue, dormant reactivation).
Testable infrastructure: cassette-based API replay for deterministic iteration; golden-set evaluation harness for router accuracy; type-safe generics for structured LLM calls.
Aimed at: SOC automation and ITDR product areas at CrowdStrike, Palo Alto Networks, Okta, SailPoint, SentinelOne, Google Mandiant.