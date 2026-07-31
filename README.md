# Pulse

Live signals. Real risk. Board-ready.

Pulse is an agent that does a threat analyst's job. It reads cybersecurity news from sixteen live sources, works out which stories are really the same story, decides which ones matter, and writes up each one as a card a CISO can take straight into a board meeting.

It is not a compliance tracker. It is a risk intelligence feed that tells you what is happening right now, how serious it is, and what to say about it.

**The agent writes the words on every card.** Nobody checks each card by hand before you read it, so it is worth knowing which parts of the work are a fixed calculation and which parts are the agent using judgement. The next section spells that out, and [How the agent is checked](#how-the-agent-is-checked) covers what stops a bad card reaching you.
<img width="1440" height="813" alt="image" src="https://github.com/user-attachments/assets/bdc11fe6-e544-4705-ace7-555e34e317b4" />

---

## What problem does it solve?

Security teams are buried in alerts. Most tools just list them. Pulse reads them, groups the ones that are connected, scores them by real-world risk, and writes a plain-English card for each one.

Each card has five parts:

1. **What is happening** - one sentence, present tense, threat-first
2. **The evidence** - which sources triggered this card and why
3. **A question for your team** - something you can ask in a meeting tomorrow
4. **Regulatory exposure** - which regulations make this risk commercially consequential
5. **Board talking point** - plain English the board can act on, written for non-technical directors

---

## How it works

Every day the agent:

1. Pulls threat data from sixteen built-in sources (see list below)
2. Groups signals that point at the same underlying threat, independently per risk domain so no domain starves another
3. Scores each group by severity, recency, source count, and active exploitation status (CISA KEV signals add a +20 bonus)
4. Writes a card for every group above the score threshold

### Which steps are judgement and which are arithmetic

This matters because the two kinds of step fail in completely different ways.

| Step | Who decides | Can it be wrong? |
|------|-------------|------------------|
| 1. Pulling data | Fixed code | Only if a feed breaks, and that is loud |
| 2. Grouping signals | The agent | Yes. It can split one threat into two cards or merge two threats into one |
| 3. Scoring a group | Fixed arithmetic | No. Same group in, same score out, every time |
| 4. Writing the card | The agent | Yes. This is the wording your board reads |

Steps 2 and 4 are the agent reading the evidence and making a call, the same way a human analyst would. Step 3 looks like the clever part but is just addition, and it is fully covered by unit tests.

So when a card looks wrong, the cause is almost always step 2 or step 4, and that is where the checking effort goes.

**Important:** clustering only looks at signals from the last 30 days. Signals are stored permanently but anything older than the window is ignored until the window is extended. See [How the signal window works](#how-the-signal-window-works) for details.

You can turn any source on or off, add your own RSS feeds, and tell it which technologies your organisation uses. Cards that mention your tech stack float to the top. You can filter the board by risk domain to see cross-lane cards that touch that domain, and by security team (IAM, SOC, AppSec, and others) to focus on what is relevant to a specific group. Technologies you do not run can be hidden so their cards never appear. A simple mode toggle rewrites card content for non-technical board members.

### Built-in sources

**Official feeds**

| Source | What it covers |
|--------|---------------|
| CISA KEV | US government list of vulnerabilities being actively exploited right now |
| CISA Advisories | US cybersecurity threat advisories |
| NCSC | UK National Cyber Security Centre alerts |
| NVD | Critical CVEs from the US National Vulnerability Database |
| GitHub Security Advisories | Open source software vulnerability database |

**Threat news**

| Source | What it covers |
|--------|---------------|
| SANS Internet Storm Center | Daily threat analysis from security practitioners |
| Bleeping Computer | Breaking cybersecurity news, often 24-48 hours ahead of official advisories |
| FCA News | UK Financial Conduct Authority enforcement actions and regulatory guidance |

**Threat research blogs**

| Source | What it covers |
|--------|---------------|
| Recorded Future | Threat intelligence analysis and adversary tracking |
| Google Threat Intelligence | Research from Google and Mandiant threat teams |
| Horizon3.ai | Adversarial attack path research and real-world exploit analysis |
| Dark Reading | In-depth cybersecurity research and analysis |
| CrowdStrike | Adversary intelligence and threat research |
| Microsoft Security | Microsoft threat research and security blog |
| Cofense | Phishing and email-based threat intelligence |
| Krebs on Security | Investigative cybersecurity journalism |

---

## What you need before you start

Install each of these before going any further.

**Python 3.11 or newer**
- Mac: download from [python.org](https://www.python.org/downloads/) or run `brew install python`
- Windows: download from [python.org](https://www.python.org/downloads/) - tick "Add Python to PATH" during install
- Check it worked: open a terminal and type `python3 --version` (Mac) or `python --version` (Windows)

**Node.js 20 or newer**
- Download from [nodejs.org](https://nodejs.org/) - choose the LTS version
- Check it worked: type `node --version` in your terminal

**Docker Desktop**
- Download from [docker.com](https://www.docker.com/products/docker-desktop)
- Install it, then open the app. You will see a whale icon in your menu bar (Mac) or taskbar (Windows). It needs to be running before you start the database in Step 3.

**Supabase CLI**
- Mac: run `brew install supabase/tap/supabase` in your terminal
- Windows: download the latest `supabase_windows_amd64.exe` from [github.com/supabase/cli/releases](https://github.com/supabase/cli/releases), rename it to `supabase.exe`, and move it to a folder that is in your PATH (e.g. `C:\Windows\System32`)

**An Anthropic API key**
- Get one free at [console.anthropic.com/keys](https://console.anthropic.com/keys)
- Keep this somewhere safe. You will need it in Step 2.

---

## Getting started

### Step 1 - Get the code

Open a terminal. On Mac that is the Terminal app. On Windows that is PowerShell (search for it in the Start menu).

```bash
git clone https://github.com/ejwmcdonagh/pulse.git
cd pulse
```

If you do not have Git installed, download it from [git-scm.com](https://git-scm.com/).

---

### Step 2 - Create your config file

This copies the example config file and creates a real one you can edit.

**Mac:**
```bash
cp backend/.env.example backend/.env
```

**Windows (PowerShell):**
```powershell
Copy-Item backend\.env.example backend\.env
```

Now open `backend/.env` in a text editor. On Mac you can use TextEdit. On Windows you can use Notepad. If you have VS Code installed, run `code backend/.env`.

The file looks like this:

```
SUPABASE_URL=
SUPABASE_SERVICE_ROLE_KEY=
ANTHROPIC_API_KEY=
...
```

Add your Anthropic API key on the `ANTHROPIC_API_KEY=` line so it looks like:

```
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

**Optional but recommended - GitHub token:**
The GitHub Security Advisories source works without a token but is limited to 60 requests per hour. To remove that limit, get a free token:
1. Go to [github.com/settings/tokens](https://github.com/settings/tokens)
2. Click "Generate new token (classic)"
3. Give it any name, leave all permission boxes unticked, set an expiry
4. Copy the token and add it to your `.env` file:

```
GITHUB_TOKEN=ghp_your-token-here
```

Leave everything else blank for now. You will fill in the Supabase values in the next step.

---

### Step 3 - Start the database

Make sure Docker Desktop is open and running first. You should see the whale icon in your menu bar or taskbar.

Then run:

```bash
supabase start --exclude edge-runtime
```

This will take a minute or two the first time. When it finishes you will see output like this:

```
Started supabase local development setup.

         API URL: http://127.0.0.1:54421
          DB URL: postgresql://postgres:postgres@127.0.0.1:54422/postgres
      Studio URL: http://127.0.0.1:54423
    Inbucket URL: http://127.0.0.1:54424
      JWT secret: super-secret-jwt-token-with-at-least-32-characters-long
        anon key: eyJhbGciOiJIUzI1NiIsInR5cCI6...
service_role key: eyJhbGciOiJIUzI1NiIsInR5cCI6...
```

Now open `backend/.env` in your text editor again and fill in these two lines using the values from the output above:

```
SUPABASE_URL=http://127.0.0.1:54421
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6...
```

The `SUPABASE_URL` is always `http://127.0.0.1:54421` when running locally. Pulse uses the 544xx
port range rather than Supabase's 543xx defaults, so it can run alongside another local Supabase
project without clashing. The ports are set in `supabase/config.toml`.
The `SUPABASE_SERVICE_ROLE_KEY` is the long `service_role key` value from the output. Copy the whole thing.

Save the file.

---

### Step 4 - Set up the database tables

This creates the tables the app needs. You only need to do this once.

```bash
supabase migration up --local
```

You should see `Local database is up to date.` when it finishes.

---

### Step 5 - Start the backend

Leave Terminal 1 running (with Supabase). Open a new terminal window for this step.

**Mac:**
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
uvicorn app.main:app --reload
```

**Windows (PowerShell):**
```powershell
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -e .
uvicorn app.main:app --reload
```

When it works you will see `Application startup complete.` in the terminal. Leave this running.

The API is now available at `http://localhost:8000`. You can view the full API docs at `http://localhost:8000/docs`.

---

### Step 6 - Start the frontend

Open a third terminal window. Navigate back to the project root first.

```bash
cd frontend
npm install
npm run dev
```

When it works you will see `Ready in Xms` and a local address. Leave this running.

Open your browser and go to `http://localhost:3000`. You will see an empty dashboard.

---

### Step 7 - Load your first data

Open a fourth terminal window. On Mac, activate the virtual environment first:

```bash
cd backend
source .venv/bin/activate
```

On Windows:
```powershell
cd backend
.venv\Scripts\activate
```

Run each of these one at a time. Wait for each to finish before running the next. Each one returns something like `{"inserted": 40}` when done.

```bash
curl -X POST "http://localhost:8000/api/ingest/run?source=cisa_kev"
curl -X POST "http://localhost:8000/api/ingest/run?source=nvd"
curl -X POST "http://localhost:8000/api/ingest/run?source=cisa_advisory"
curl -X POST "http://localhost:8000/api/ingest/run?source=ncsc"
curl -X POST "http://localhost:8000/api/ingest/run?source=exploit_db"
curl -X POST "http://localhost:8000/api/ingest/run?source=bleeping_computer"
curl -X POST "http://localhost:8000/api/ingest/run?source=ico_enforcement"
curl -X POST "http://localhost:8000/api/ingest/run?source=github_advisory"
curl -X POST "http://localhost:8000/api/ingest/run?source=recorded_future"
curl -X POST "http://localhost:8000/api/ingest/run?source=google_threat_intel"
curl -X POST "http://localhost:8000/api/ingest/run?source=horizon3"
curl -X POST "http://localhost:8000/api/ingest/run?source=dark_reading"
curl -X POST "http://localhost:8000/api/ingest/run?source=crowdstrike"
curl -X POST "http://localhost:8000/api/ingest/run?source=microsoft_security"
curl -X POST "http://localhost:8000/api/ingest/run?source=cofense"
curl -X POST "http://localhost:8000/api/ingest/run?source=krebs"
```

The `cisa_kev` command will return around 900 signals. The others return 10-50 each. The `github_advisory` command can be slow if you have not set a `GITHUB_TOKEN` in your `.env` file.

Now generate the intelligence clusters and cards. Both commands return immediately with a job ID - the work runs in the background.

```bash
curl -X POST http://localhost:8000/api/clusters/run
```

You will get back something like `{"job_id":"abc-123","status":"running"}`. Copy the job ID and poll until it completes:

```bash
curl "http://localhost:8000/api/pipeline/runs/abc-123"
```

When `status` shows `completed`, run card generation:

```bash
curl -X POST http://localhost:8000/api/cards/run
```

Poll the new job ID the same way. Card generation calls the AI and takes 1-3 minutes. Once complete, go to `http://localhost:3000` and refresh. You should see cards in the swim lanes.

To see all recent pipeline runs at any time:

```bash
curl http://localhost:8000/api/pipeline/runs
```

---

## Running the pipeline manually

The scheduler is off by default. To refresh your feed, run these two commands:

```bash
curl -X POST http://localhost:8000/api/clusters/run
curl -X POST http://localhost:8000/api/cards/run
```

Both return immediately with a `job_id`. Poll `GET /api/pipeline/runs/{job_id}` to check when each finishes before running the next. Card generation will find nothing to do if clustering has not completed yet.

To see all recent pipeline runs:

```bash
curl http://localhost:8000/api/pipeline/runs
```

To enable automatic daily runs, add this to `backend/.env`:

```
SCHEDULER_ENABLED=true
```

Then restart the backend. The pipeline will run every day at 08:00 UTC.

---

## How the signal window works

This is important to understand before you run the pipeline.

**Signals are stored permanently.** Every time you run an ingest command, signals are written to the database and kept there. Nothing is ever deleted automatically.

**Clustering only looks at the last 30 days.** When you run `clusters/run`, it ignores any signal older than 30 days. Those older signals stay in the database but will never appear in a cluster or card unless you extend the window.

**Dismissed cards stay dismissed.** If you dismiss a card from the board, its signals are permanently excluded from future clustering runs. The same threat will not return unless new signals come in after the dismissal.

**What this means in practice:**

- If you run the pipeline daily, you will always see a fresh view of the last 30 days of threat activity.
- If you stop running the pipeline for a month and start again, you will only see clusters built from the last 30 days. The gap in between is lost from the board view but still stored in the database.
- On your first ever run, the 30-day window is applied to whatever signals have been ingested. CISA KEV pulls its full catalogue (thousands of entries going back years), so you may see clusters from older vulnerabilities on day one. Every other source only fetches recent items.

**To change the window**, add this to `backend/.env` and restart the backend:

```
CLUSTERING_WINDOW_DAYS=60
```

Increasing the window means more signals are considered per run and clustering will take longer and cost slightly more. The default of 30 days is a good balance for daily use.

---

## How the agent is checked

The agent writes board copy without a human reading it first, so it needs its own checks. There are two, and they do different jobs.

### The problem being solved

Left alone, the agent writes regulation citations from memory. Asked three times for a card about the same threat, it produced three different sets of article numbers, and one run claimed a fine figure that did not exist in any source it was given. Every one of those cards looked completely convincing. That is the danger: a wrong fine figure in plain English reads exactly like a right one, and it ends up on a board slide.

### Check one: the card contract, on every single card

`app/services/card_validation.py` checks every card before it is saved. No AI involved, so it is free and it gives the same answer every time. It checks:

- **Citations are real.** Every article number and every fine figure in the card must appear in the regulation text the agent was actually given. If the agent was given nothing, it is not allowed to quote any article number or figure at all. It has to stay general.
- **Evidence links are real.** Every source the card lists must be one of the signals the agent was handed, and the link always comes from the database, never from the agent.
- **Board copy is readable.** No CVE numbers and no jargon in the two fields non-technical directors read.
- **Length rules.** Headlines stay under 15 words, board talking points stay at 3 or 4 sentences.
- **House style.** No em dashes.

If a card fails, the agent is told exactly what is wrong and asked to write it again, up to three times within a single run. If it still cannot produce a clean card, nothing is saved that run and the group goes back in the queue with the reasons recorded against it. After three runs end that way the group is marked failed and stops being retried, so a group that never comes right costs at most nine attempts in total. **A missing card is better than a card with an invented fine in it.**

Every saved card records how many attempts it took, in `metadata.validation_attempts`. If that number starts creeping up, the prompt is drifting.

### Check two: evals, run on purpose

The contract check proves a card is well formed. It cannot tell you whether the agent's *judgement* is any good. That needs examples where a human has already decided what the right answer is.

`backend/tests/eval/test_agent_quality.py` holds those examples. They call the real model, so they cost money and are skipped unless you ask for them:

```bash
cd backend && pytest -m eval      # live evals, needs ANTHROPIC_API_KEY
cd backend && pytest              # normal tests, evals skipped
```

The cases are:

| Eval | What it proves |
|------|----------------|
| One vulnerability reported by three sources | The agent makes one card, not three |
| Three unrelated products with the same bug type | The agent does not lump them together into a card nobody can act on |
| Citations trace back to source | Given real regulation text, every article number and fine figure the agent writes is actually in it, and the agent does use it rather than staying vague |
| Card with no regulation text available | The saved card survives a fresh check, and the links on it still point at the right pages |
| Card needs at most one rewrite | The agent can fix its own mistakes when told what they are |

The third one is the case that prompted this work. The agent was given text saying 10,000,000 EUR and 7,000,000 EUR, and wrote "10 to 14 million". Both halves of that eval are needed: a card that cites nothing at all would pass the accuracy half on a technicality.

That last one matters because the retry loop hides sloppiness. A card that took three attempts looks exactly like a card that took one, so the finished card can never tell you the prompt is getting worse. The number of attempts can.

The test itself is a loose gate on purpose. Card writing runs at default temperature, so one sample cannot prove a pass rate, and demanding a perfect first attempt every time would fail on a perfectly healthy prompt. The real number to watch is the average of `metadata.validation_attempts` across recent cards once the pipeline is running. If that drifts from near 1 towards 2, the prompt needs attention.

### Check three: read what it wrote

The two checks above tell you the rules held. Neither can tell you the writing is any
good. No mechanical check can: "attackers can take control of our network" and
"unauthorised access may occur" both pass every rule, and only one of them is worth
saying to a board.

So there is a third thing, and it is just you reading the output:

```bash
cd backend && python scripts/review_agent_output.py           # read it
cd backend && python scripts/review_agent_output.py > review.md   # keep it to compare later
```

This runs the agent over the same fixtures the evals use and prints everything it
wrote in full: both clustering decisions, and two complete cards, one with regulation
text retrieved and one without. For each card it shows how many rewrites it needed,
whether the contract passed, and the source regulation text so you can check the
citations yourself.

It needs an Anthropic key but **not** the database, so it works before the stack is
up. It costs a few cents per run.

Save the output when you change a prompt and diff it against the previous run. That
is the fastest way to see what a prompt edit actually did, because a passing test
suite will look identical either way.

### When an eval fails

Fix the prompt, not the eval. These cases exist because a human agreed with the answer, so a failure means the agent changed its mind, not that the bar is too high. Only rewrite a case if you can argue the original call was wrong.

Both prompt fixes currently in the code were found this way. The agent kept writing 17-word headlines against a 15-word limit, and it kept quoting article numbers when it had been given no regulation text to quote from. Neither was visible in the output. Both showed up the moment there was a test that could fail.

---

## Customising your feed

Go to `http://localhost:3000` and click **Customize your feed** in the top right.

**Your technology stack** - add the vendors and products your organisation runs (for example: Palo Alto, Microsoft Exchange, Cisco). Cards that mention these will be highlighted and sorted to the top of each lane.

**Hide technologies** - add technologies your organisation does not use. Cards that mention these will be hidden from the board entirely. Useful for filtering out noise from platforms completely irrelevant to your environment.

**Signal sources** - all sixteen built-in sources are listed with an Active/Paused toggle. Pause any source you do not want. Changes take effect on the next scheduled run.

**Add your own sources** - paste any RSS or Atom feed URL and give it a name. It will be ingested daily alongside the built-in sources.

---

## Regulatory knowledge base (RAG)

Cards include a compliance gap section that cites specific regulations, article numbers, and fine thresholds. This is powered by a RAG (Retrieval-Augmented Generation) knowledge base stored in the database.

When a card is generated, the cluster summary is embedded and matched against pre-indexed article extracts from five regulations: NIS2, UK GDPR, DORA, FCA SYSC 13, and NCSC CAF. The most relevant articles are injected into the prompt so Claude writes the compliance gap from actual regulatory text rather than training memory.

This requires a Voyage AI API key (free tier, no credit card required). Without it, cards are still generated but the compliance gap falls back to Claude's training knowledge.

**Setup:**

1. Sign up at [voyageai.com](https://www.voyageai.com) and get a free API key
2. Add it to `backend/.env`:
   ```
   VOYAGE_API_KEY=your-key-here
   ```
3. Run the indexing script once to embed the regulation articles:
   ```bash
   cd backend
   source .venv/bin/activate
   python scripts/index_regulations.py
   ```
   This takes about 15 minutes due to the free tier rate limit (one-time only).

To re-index after adding new regulation content, run the script again. It clears and rebuilds from scratch.

---

## Dismissing cards

Cards can be dismissed from the board using the X button in the top-right corner of each card tile. Dismissed cards:

- Are removed from the board immediately
- Are archived permanently and will not reappear
- Have their underlying cluster marked dismissed, so the same signals are not re-clustered on future pipeline runs

To view dismissed cards, click **Dismissed** in the main header. The archive page shows all dismissed cards with an optional date filter.

---

## API authentication

By default the API is open so local development requires no extra config. If you deploy Pulse somewhere accessible from the internet, set an API key to restrict access.

Add this to `backend/.env`:

```
API_KEY=your-secret-key-here
```

Generate a strong key with `openssl rand -hex 32`.

Once set, every API request must include the header `X-Api-Key: your-secret-key-here`. The frontend reads this from an environment variable - create `frontend/.env.local` and add:

```
NEXT_PUBLIC_API_KEY=your-secret-key-here
```

Use the same value in both files. Restart both the backend and frontend after changing either.

---

## Switching AI models

The system uses Claude Haiku by default. This costs about $0.74 per full pipeline run (including RAG regulatory context) and is good for testing.

For production, switch to Claude Opus for higher quality cards.

Both service files already have the Opus line written in as a comment. Open these two files:
- `backend/app/services/clustering.py`
- `backend/app/services/card_generator.py`

In each file, find this block:

```python
model="claude-haiku-4-5-20251001",
# model="claude-opus-4-7",
```

To switch to Opus, comment out the Haiku line and uncomment the Opus line:

```python
# model="claude-haiku-4-5-20251001",
model="claude-opus-4-7",
```

Note: both services use forced tool_choice for structured output, which is incompatible with extended thinking. Do not add a `thinking` parameter - it will cause a 400 error.

### Approximate costs per pipeline run

Based on actual runs with ~2,100 signals across all 13 sources, including RAG regulatory context retrieval.

| Step | Haiku | Opus |
|------|-------|------|
| Clustering | ~$0.06 | ~$0.30 |
| Card generation + RAG | ~$0.68 | ~$3.40 |
| **Total** | **~$0.74** | **~$3.70** |

The first run is more expensive because it processes the full signal backlog. Daily incremental runs will cost less as only new signals get clustered.

These figures were measured before the card contract check existed and assume every card passes first time. A card that gets rewritten costs that much again for each attempt, so real card generation cost is roughly the figure above multiplied by the average `metadata.validation_attempts`. Watch that average: it is both the quality signal and the cost signal.

Token usage per run is logged in the `metadata.usage` field on every cluster and card row in the database, so you can track actual spend over time.

---

## Troubleshooting

**"command not found: python3"**
On Windows, use `python` instead of `python3`. On Mac, make sure Python is installed from [python.org](https://www.python.org/downloads/).

**"command not found: supabase"**
The Supabase CLI is not installed or not in your PATH. Follow the install instructions in the Prerequisites section above.

**SSL certificate errors when starting the backend**
This usually happens on corporate laptops where the company controls internet traffic. The app uses `truststore` to read your system certificates automatically. If you still see errors, ask your IT team which certificate file your network uses.

**Docker not running**
Open Docker Desktop before running `supabase start`. Wait for the whale icon to appear and stop animating before you proceed.

**"Port already in use"**
Something else is already using port 8000 or 3000. Restart your terminal, or find and stop the other process.

**Cards not appearing on the dashboard**
Make sure you ran both `clusters/run` and `cards/run`. Clusters must exist before cards can be generated. Also check that `ANTHROPIC_API_KEY` is set correctly in `backend/.env`.

**The database command fails with "Cannot find project ref"**
Use `supabase migration up --local` not `supabase db push`. The `db push` command requires a remote Supabase project.

**GitHub Advisory ingest returns a 403 rate limit error**
You have hit the 60 requests/hour unauthenticated limit. Either wait an hour and try again, or add a free `GITHUB_TOKEN` to `backend/.env` (see Step 2 above). The token needs no permissions.

---

## Project structure

```
pulse/
├── backend/                  # Python API and data pipeline
│   ├── app/
│   │   ├── ingestion/        # One file per data source
│   │   ├── services/         # Clustering and card generation (AI logic)
│   │   ├── routes/           # API endpoints
│   │   └── ...
│   └── scripts/              # One-off maintenance scripts
├── frontend/                 # Next.js dashboard
│   └── src/
│       ├── app/              # Pages (dashboard, settings)
│       └── components/       # UI components
└── supabase/
    └── migrations/           # Database setup scripts
```

---

## What is built so far

- [x] Step 1 - Pull threat data from CISA, NVD, NCSC
- [x] Step 2 - Group related signals into clusters
- [x] Step 3 - Generate 5-layer intelligence cards using AI
- [x] Step 4 - Dashboard with five domain lanes, card modal, tech stack highlighting, domain filter, team filter, per-team AI impact summaries, simple mode for board-level readers, dismiss cards, hide technologies, RAG-grounded compliance gaps, card pagination, background pipeline jobs with status polling, and optional API key authentication
- [x] Step 4a - Quality controls on the agent: a contract check on every card, a rewrite loop when a card fails it, and live evals for the agent's judgement (see [How the agent is checked](#how-the-agent-is-checked))
- [ ] Step 5 - Connect to your SIEM or ticketing system
- [ ] Step 6 - Weekly email digest
- [ ] Step 7 - Onboarding flow for new organisations

---

## Licence

MIT
