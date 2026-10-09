# CodeSentinel Event Flow & Sequence Diagram

This document illustrates the end-to-end execution flow of CodeSentinel from the moment a GitHub Pull Request is created or synchronized to the asynchronous multi-agent audit and automated PR commentary.

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant GH as GitHub API / Webhooks
    participant API as FastAPI Ingestion Gateway
    participant Redis as Redis / ARQ Queue
    participant Worker as ARQ Background Worker
    participant Parser as Git Diff Parser
    participant Graph as LangGraph Multi-Agent Team
    
    Dev->>GH: Open / Synchronize Pull Request
    GH->>API: POST /webhook/github (HMAC SHA-256 Signature)
    
    activate API
    API->>API: Verify X-Hub-Signature-256 against Secret
    alt Invalid Signature
        API-->>GH: 401 Unauthorized
    else Valid PR Event
        API->>Redis: enqueue_job("analyze_pr_task", pr_payload)
        API-->>GH: 202 Accepted (job_id, status: queued)
    end
    deactivate API

    activate Worker
    Redis->>Worker: Dispatch task: analyze_pr_task
    Worker->>GH: GET /repos/{owner}/{repo}/pulls/{number} (Fetch Diff)
    GH-->>Worker: Unified Git Diff text
    Worker->>Parser: parse(raw_diff)
    Parser-->>Worker: List[DiffFile] (Files, Hunks, Line Mappings)
    
    Worker->>Graph: invoke(initial_agent_state)
    activate Graph
    Note over Graph: Security Scanner -> Test Generator -> Patch Creator -> Judge Loop
    Graph-->>Worker: Final Audited State & Approved Review Comments
    deactivate Graph

    Worker->>GH: POST /repos/{owner}/{repo}/issues/{number}/comments (Summary)
    Worker->>GH: POST /repos/{owner}/{repo}/pulls/{number}/comments (Inline Reviews)
    deactivate Worker
```
