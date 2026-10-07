<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Changelog

## 0.2.0 — 2026-10-06

The first release from this repository, and the first signed one. Release assets are signed with
the [Declass release key](docs/declass-release.pub); see [signed releases](docs/INSTALLATION.md#signed-releases).

### The local model checks what goes out

In hybrid mode the local model now judges, not only reads. Each check is on by default; a project
may turn one on but never off, and turning one off in your own config needs `--confirm`.
[Details](docs/USAGE.md#local-model-checks)

- **Disclosure judge** (`sensitivity.local_judge`): withholds paraphrased record details from local
  summaries, answers, briefs and explorer reports.
- **Question intent** (`sensitivity.question_intent`): a question aimed at one record or value, in
  any language, is answered as a question about format and structure.
- **Injection screen** (`sensitivity.injection_screen`): public files, web pages, MCP results and
  command output that address an AI agent are judged locally. A confirmed injection is marked as
  data and marks the run; `oversight.on_injection = "approve"` (the default) then asks before risky
  actions, web tools and MCP calls.
- **Outbound meaning** (`sensitivity.egress_meaning`): web and network MCP requests that carry facts
  the local model reported are refused; so is a request it could not check.
- **Content classification** (`sensitivity.classify_content`): public data files that hold real
  records are held as sensitive.
- **Operator text** (`sensitivity.operator_pii`): names and addresses in your task and messages
  become placeholders.
- **Local diff review** (`review.local_diff`): advisory findings at finish; a protected rewrite with
  exfiltration or a backdoor is refused.
- **Disclosure narrative** (`sensitivity.local_narrative`): an account, for you only, of what the
  frontier could have learned: `declass audit disclosure <run> --narrative`.
- Always on: local prompts are framed with tags a file cannot forge, local output reaches the
  frontier framed as data, and cited evidence lines are checked against the answer.
- `declass local-eval --suite judge,intent,injection,classify,review` measures your local model in
  these roles.

### ChatGPT plans

- `declass login chatgpt` signs in with a ChatGPT Plus or Pro plan in the browser, and
  `declass config preset chatgpt --confirm` sends the cloud model's requests through it.
  [Details](docs/USAGE.md#chatgpt-plan)

### Request limits replace cost tracking

- Dollar budgets, pricing settings and cost reports are removed. Sessions and runs are limited by
  frontier requests (`limits.frontier_requests`) and time. Retired `pricing.*` and `*_usd` settings
  still load, with a note.

### Setup

- **No default models.** The cloud and local endpoints and models start empty; nothing is sent
  until you choose them. Earlier versions defaulted to Z.ai GLM and a local `omlx-coding`.
- **Setup screen.** The first `declass` in a terminal (and `declass setup`) opens a full-screen
  setup: pick a cloud provider (API keys found in your environment are marked; ChatGPT plans sign in
  in the browser) and a local model (servers on this machine, or one at an address you allow),
  review who receives what, and save. API keys can be given as `$VARIABLE` or pasted; a pasted key
  is kept owner-only in Declass's credentials, never in the configuration.

### Upgrading

- If you relied on the old defaults, run `declass setup` (or set `frontier.base_url`,
  `frontier.model`, `frontier.api_key_env`, `local.base_url` and `local.model`).
- The local checks add local model time: about 5 seconds per question or outbound request and 8
  per judged output on a 27B model. Turn individual checks off with
  `declass config set <setting> false --confirm` if your model is slow.
- Rename `limits.*_usd` settings to request limits; the old keys are ignored.

## 0.1.0

The first public preview, published unsigned as Duet from the pre-rename repository
[maximpri/duet](https://github.com/maximpri/duet).
