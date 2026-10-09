# CODESENTINEL — OTONOM GİTHUB PR & GÜVENLİK DENETİM AJANI
## Kapsamlı Mimari, Teknik Yol Haritası ve Uygulama Planı
> **Geliştirici:** Enis Doğan  
> **Hedef:** Y Combinator & Avrupa AI Startup'ları için Production-Grade Portfolyo  
> **Temel Altyapı:** LangGraph, FastAPI, Redis, Docker, PyGitHub, LangSmith  

---

## 1. PROJE ÖZETİ VE VİZYON
**CodeSentinel**, GitHub depolarına açılan Pull Request'leri (PR) webhook aracılığıyla gerçek zamanlı yakalayan, çoklu ajan (multi-agent) grafiği ile kodu denetleyen, güvenlik açıklarını (OWASP Top 10, Secrets, SQLi) tespit eden, otomatik pytest testleri yazan ve gerekiyorsa düzeltme commit'i öneren **otonom bir yapay zeka mühendislik ajanıdır**.

### Yabancı CTO'lara ve Mülakatçılara Satış Cümlesi:
> *"I built CodeSentinel — an event-driven multi-agent GitHub review system using LangGraph and Redis. When a PR is opened, a team of specialized LLM agents (Security Scanner, Test Generator, and Judge) autonomously evaluates the git diff, validates proposed fixes in an isolated sandbox, and comments directly on the PR with zero human intervention."*

---

## 2. DETAYLI SİSTEM MİMARİSİ (ARCHITECTURE)

```
[GitHub PR Event]
       │
       ▼ (Webhook POST /webhook/github)
[FastAPI Ingestion Gateway]
       │
       ▼ (HMAC SHA-256 Signature Verification)
[Redis Task Queue / Celery or ARQ Worker]
       │
       ▼ (Asynchronous Task Pick-up)
[GitHub API Client] ──► Git Diff & File Tree Fetching
       │
       ▼
┌─────────────────────────────────────────────────────────────┐
│             LANGGRAPH MULTI-AGENT STATE GRAPH               │
│                                                             │
│  [State: pr_diff, ast_tree, security_issues, tests, status] │
│                                                             │
│  1. ┌───────────────────────────┐                           │
│     │   Security Scanner Agent  │ ──► Static AST + LLM Audit│
│     └─────────────┬─────────────┘                           │
│                   ▼                                         │
│  2. ┌───────────────────────────┐                           │
│     │    Test Generator Agent   │ ──► Synthesize PyTests    │
│     └─────────────┬─────────────┘                           │
│                   ▼                                         │
│  3. ┌───────────────────────────┐                           │
│     │   Patch/Fix Creator Agent │ ──► Propose Code Changes  │
│     └─────────────┬─────────────┘                           │
│                   ▼                                         │
│  4. ┌───────────────────────────┐     [Erased / Rejected]   │
│     │   Judge & Executive Agent │ ──► (Cycle back if bug)   │
│     └─────────────┬─────────────┘                           │
│                   │ (Approved)                              │
└───────────────────┼─────────────────────────────────────────┘
                    ▼
[GitHub API Integration Engine]
  ├── Inline Review Comments (Satır bazlı güvenlik uyarısı)
  ├── PR Summary Markdown Table (Güvenlik skoru ve özet)
  └── [Opsiyonel] Automated Suggestion Patch
```

---

## 3. KULLANILACAK TEKNOLOJİ YIĞINI (TECH STACK)

| Katman | Teknoloji | Seçim Sebebi |
| :--- | :--- | :--- |
| **Orchestration** | **LangGraph** (v0.2+) | Döngüsel (cyclic) durum grafiği, self-correction ve judge mekanizması için sektör standardı. |
| **API Gateway** | **FastAPI** (Async) | GitHub webhook'larını milisaniyeler içinde kabul edip 202 dönmek için yüksek hızlı asenkron yapı. |
| **Message Queue** | **Redis + ARQ** (veya Celery) | Webhook timeout yememek için iş yükünü asenkron işçilere devretmek (Rate limit & concurrency control). |
| **Git Integration** | **PyGitHub** & **GitPython** | GitHub REST & GraphQL API ile PR diff, dosya okuma ve satır içi yorum atma. |
| **LLM Inference** | **Claude 3.5 Sonnet / GPT-4o** + **Llama 3 (Local)** | Kod analizi ve patch üretiminde en yüksek F1 skorunu veren modeller. |
| **Observability** | **LangSmith** | Token harcaması, gecikme (latency), zincir adımları ve maliyet takibi. |
| **Container** | **Docker & Docker Compose** | Tek komutla (`docker compose up`) Redis + FastAPI + Worker'ı ayağa kaldırma. |

---

## 4. DÖNGÜSEL AJAN GRAFİĞİ DETAYLARI (AGENT NODES)

### A. State Schema (`AgentState`)
```python
class AgentState(TypedDict):
    repo_name: str
    pr_number: int
    pr_title: str
    git_diff: str
    changed_files: list[dict]
    security_vulnerabilities: list[dict]
    generated_tests: list[str]
    suggested_patch: str
    judge_approval: bool
    judge_feedback: str
    review_comments: list[dict]
    iteration_count: int
```

### B. Ajan Düğümleri (Nodes):
1. **Security Scanner Node:**
   * Gelen diff'i parçalar. Sadece metinsel değil, soyut sözdizim ağacı (AST) analiziyle eşleştirir.
   * Kontrol ettikleri: Hardcoded API Keys/Secrets, SQL Injection riskleri, XSS, Path Traversal, Insecure Deserialization.
2. **Test Generator Node:**
   * Değişen fonksiyonların sınır durumlarını (edge cases) analiz eder.
   * Orijinal koda dokunmadan çalışabilecek minimal `pytest` test blokları üretir.
3. **Patch / Fixer Node:**
   * Tespit edilen güvenlik açığı için diff formatında temiz çözüm üretir.
4. **Judge Agent Node (Kritik Katman):**
   * Üretilen yama (patch) orijinal kodu bozdu mu? Halüsinasyon var mı?
   * Onaylamazsa grafiği 1 adım geri döndürür (`iteration_count < 3` şartıyla).
   * Onaylarsa GitHub Markdown formatında temiz bir PR inceleme raporu oluşturur.

---

## 5. DÖRT ADIMLI UYGULAMA FAZLARI (ROADMAP)

### FAZ 1: Altyapı ve Webhook Dinleyici (1-3. Gün)
* [ ] Proje dizin yapısının kurulması (`src/api`, `src/agents`, `src/github`, `src/core`).
* [ ] FastAPI üzerinde `/webhook/github` endpoint'i.
* [ ] GitHub Webhook Secret doğrulama (HMAC SHA-256 hash validation).
* [ ] Redis kuyruğuna PR payload'unu basan yapı (`ARQ` worker).
* [ ] GitHub API üzerinden test PR'ının diff'ini çeken client.

### FAZ 2: LangGraph Durum Grafiği ve Ajanlar (4-8. Gün)
* [ ] `AgentState` veri modelinin oluşturulması.
* [ ] Security Scanner prompt ve yapılandırılmış çıktı (`Pydantic` şeması) entegrasyonu.
* [ ] Test Generator ajanının bağlanması.
* [ ] Judge Agent ve döngüsel düzeltme (`conditional_edge`) bağlantısı.
* [ ] LangSmith izleme (tracing) bağlantısının yapılması.

### FAZ 3: GitHub Yorum Motoru ve Canlı Entegrasyon (9-12. Gün)
* [ ] GitHub Pull Request'e genel özet tablosu basma (`POST /repos/{owner}/{repo}/issues/{issue_number}/comments`).
* [ ] Güvenlik açığı olan spesifik satırlara satır içi yorum (inline review comment) ekleme (`POST /repos/{owner}/{repo}/pulls/{pull_number}/comments`).
* [ ] GitHub App kurulumu veya Personal Access Token (PAT) entegrasyonu.

### FAZ 4: Prodüksiyon Cilası ve Vitrin (13-15. Gün)
* [ ] `Dockerfile` ve `docker-compose.yml` (FastAPI + Redis + Worker).
* [ ] Kök dizinde Mermaid mimari diyagramı içeren kusursuz İngilizce `README.md`.
* [ ] 1 dakikalık Loom video kaydı (Canlıda PR açıldığında botun 15 saniyede yorum attığı an).
* [ ] CV'ye ve LinkedIn'e ekleme.

---

## 6. PROJE DİZİN YAPISI (PROJECT FOLDER STRUCTURE)

```
codesentinel/
├── .github/
│   └── workflows/
│       └── ci.yml               # Otomatik lint ve test
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml       # Tek komutla redis + api + worker
├── docs/
│   ├── architecture.png         # Mimari şema
│   └── sequence_diagram.md      # Akış şeması
├── src/
│   ├── __init__.py
│   ├── config.py                # Pydantic Settings & Env vars
│   ├── api/
│   │   ├── __init__.py
│   │   ├── main.py              # FastAPI app
│   │   └── webhooks.py          # GitHub webhook receiver
│   ├── queue/
│   │   ├── __init__.py
│   │   └── worker.py            # Redis / ARQ async task worker
│   ├── github_client/
│   │   ├── __init__.py
│   │   ├── client.py            # PyGitHub wrapper
│   │   └── parser.py            # Git diff chunker & line mapper
│   └── agents/
│       ├── __init__.py
│       ├── state.py             # LangGraph TypedDict state
│       ├── graph.py             # StateGraph definition & compile
│       ├── security_scanner.py  # Ajan 1
│       ├── test_generator.py    # Ajan 2
│       ├── patch_creator.py     # Ajan 3
│       └── judge.py             # Ajan 4 (Yargıcı)
├── tests/
│   ├── test_webhook.py
│   └── test_security_scanner.py
├── .env.example
├── pyproject.toml / requirements.txt
└── README.md                    # Vitrin dökümanı
```

---

## 7. YENİ SOHBETTE BAŞLARKEN KULLANACAĞIN AÇILIŞ KOMUTU

Yeni bir sohbet açtığında şu cümleyi yapıştırman projeye anında sıfır gecikmeyle başlamamızı sağlar:

> *"CodeSentinel projesine başlıyoruz. Masaüstündeki CODESENTINEL_PROJE_PLANI.md dosyasındaki mimari plana göre Faz 1'den (FastAPI Webhook dinleyici, Redis kuyruğu ve proje iskeleti) kodlamaya başla."*
