Load the pke design context before answering. Read the following files from `/context`:

1. `00_project_summary.md` — what pke is
2. `03_system_architecture.md` — how the system is structured
3. `04_protocol_overview.md` — the cryptographic protocol
4. `05_data_model_public.md` — data schemas and relationships
5. `06_threat_model.md` — security threats and mitigations
6. `08_security_assumptions.md` — trust boundaries and assumptions

After loading, use this context to answer the user's question: $ARGUMENTS

If no question was provided, summarize the current project state and architecture.
