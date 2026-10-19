# Rotating a leaked credential

Rotate first, clean up second. Revoking the old value is what ends the
exposure; everything else limits the damage. After rotating, put the new
value in the environment or a secrets manager, never back in the file.

The scanner's `advice` field names the place for each detector. This table
covers the most common ones.

## AI and LLM providers

| Credential | Where to revoke and reissue |
|---|---|
| OpenAI (`sk-proj-`, `sk-svcacct-`, `sk-admin-`) | platform.openai.com → API keys (project keys under the project) |
| Anthropic (`sk-ant-`) | console.anthropic.com → API keys |
| xAI (`xai-`) | console.x.ai → API keys |
| Google Gemini / Google API key (`AIza`) | Google Cloud Console → APIs & Services → Credentials; add restrictions to the new key |
| DeepSeek and other `sk-<hex>` providers | the provider's console → API keys |
| Hugging Face (`hf_`) | huggingface.co → Settings → Access Tokens |
| Groq, OpenRouter, Perplexity, Replicate, Together, Cerebras, NVIDIA | the provider's dashboard → API keys |
| LangSmith (`lsv2_`), Langfuse (`sk-lf-`) | project settings → API keys; traces may hold prompts and user data, so review them |
| Pinecone, Firecrawl, Tavily | the provider's dashboard → API keys |
| AWS Bedrock API key (`ABSK`) | IAM console → the user it belongs to → Bedrock API keys |

## Code hosting and packages

| Credential | Where |
|---|---|
| GitHub (`ghp_`, `github_pat_`, `gho_`, `ghs_`) | Settings → Developer settings → tokens, or the OAuth/GitHub App that issued it |
| GitLab (`glpat-` and friends) | User settings → Access tokens, or the project's CI/CD settings |
| npm (`npm_`) | `npm token revoke <id>` or npmjs.com → Access Tokens; check for unexpected package versions |
| PyPI (`pypi-`) | pypi.org → Account settings → API tokens; switch to Trusted Publishing |

## Cloud and infrastructure

| Credential | Where |
|---|---|
| AWS access key (`AKIA`, `ASIA`) | IAM → Users → Security credentials → deactivate, then delete; check CloudTrail |
| Azure storage key | Storage account → Access keys → rotate; prefer managed identity |
| Google service account key | IAM → Service accounts → Keys → delete the key |
| Cloudflare (`cfut_`, `cfat_`) | My Profile → API Tokens → roll |
| Vercel (`vcp_`, `vci_`, `vca_`, `vck_`) | Account Settings → Tokens |
| Supabase (`sb_secret_`, `sbp_`) | Project Settings → API Keys, or Account → Access Tokens |
| DigitalOcean, Fly.io, Neon, PlanetScale, Databricks | the provider's dashboard → API tokens / access tokens |
| HashiCorp Vault (`hvs.`) | `vault token revoke <token>`; move the app to an auth method |
| Doppler (`dp.pt.`) | Doppler dashboard → tokens |
| Database password in a connection string | change the database user's password, then update the secret store |
| Private key (`BEGIN ... PRIVATE KEY`) | generate a new key pair, replace the public half everywhere (servers, deploy keys, certificates), revoke the old certificate if any |

## Payments, messaging and SaaS

| Credential | Where |
|---|---|
| Stripe live key (`sk_live_`, `rk_live_`) | Dashboard → Developers → API keys → roll; review recent API logs |
| Square (`sq0atp-`, `sq0csp-`) | Developer Dashboard → credentials |
| Slack token or webhook | your Slack app's settings → reinstall or regenerate |
| Discord webhook | channel settings → Integrations → delete and recreate |
| Telegram bot | @BotFather → `/revoke` |
| SendGrid, Resend, Mailchimp | the provider's API keys page; check for spam sent from your domain |
| Twilio | Console → API keys |
| Linear, Notion, Atlassian, Postman, Sentry, Grafana, PostHog | the user or organization settings → API keys / tokens |

## After rotating

1. Update every place the old value lived (CI secrets, servers, teammates' `.env`).
2. Look at the provider's audit or usage logs for activity since the exposure.
3. Note what leaked, when, and what you did. If customer data could be
   involved, follow your organization's incident process.
