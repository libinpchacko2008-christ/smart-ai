# StudyMate AI

StudyMate AI is a web-based personal study assistant built with FastAPI, SQLite and Google Gemini. It includes authenticated chat history, study and coding modes, quiz/flashcard text generation, PDF/DOCX/text uploads, daily goals, personalized answer formats, a dashboard, and browser-based microphone/read-aloud controls.

## Local development

1. Install **Python 3.12** or newer, then open this folder in a terminal.
2. Create a virtual environment: `python -m venv .venv`.
3. Activate it: Windows `.venv\\Scripts\\activate` or macOS/Linux `source .venv/bin/activate`.
4. Install packages: `pip install -r requirements.txt`.
5. Copy `.env.example` to `.env` and provide your Gemini API key. Leave `APP_ENV=development` locally.
6. Run `uvicorn server:app --reload` and open `http://127.0.0.1:8000`.
7. Run API tests: `python -m pytest tests -q` (install pytest first if necessary).

## Deploy to Render (public HTTPS web URL)

The included `render.yaml` is a Render Blueprint for a **paid Starter web service with a persistent disk**. SQLite must use persistent disk storage, otherwise student accounts, chat history and uploads may disappear on redeploy. The service intentionally uses one worker because SQLite and in-memory rate limits are not configured for horizontally scaled replicas.

1. Create a **private GitHub repository** and push the project there. Never commit `.env`, API credentials, or `.db` files; `.gitignore` excludes them.
2. Sign into [Render](https://dashboard.render.com/), choose **New → Blueprint**, connect the GitHub repository and select `render.yaml`.
3. Set the requested `GEMINI_API_KEY` environment variable using your key from [Google AI Studio](https://aistudio.google.com/apikey). `APP_SECRET` is generated automatically. Keep `APP_ENV=production`.
4. Approve Render's hosting and disk charges, create the service and wait for it to pass its `/healthz` check. Render will supply a public HTTPS URL (often `https://<service-name>.onrender.com`; use the actual URL shown by Render).
5. Visit the URL, create a test account, upload a TXT file, start a study chat and verify Gemini returns a real answer. Also test on a phone.
6. Configure backups for `/var/data/studymate.db` **with SQLite-consistent snapshot/backup tooling** and test restoration. The disk is not a backup.

### Operating and privacy notes

- **Not yet a compliance-audited multi-tenant SaaS.** Before inviting students publicly, complete a security review, privacy notice, deletion/export workflow, abuse controls, age-appropriate policies, account recovery, monitoring, encrypted backup policy, and a cost/quota plan.
- Sessions are hashed in SQLite and delivered via `HttpOnly; Secure` cookies in production. Origin checks and basic per-IP authentication throttling are included. Passwords use salted PBKDF2. These controls are useful but do not replace a security audit, a perimeter rate limiter, or a managed identity system.
- **Uploaded documents** are stored as extracted text, not original files. Text is sent to Gemini when a document is selected for a question. Avoid uploading confidential information until you have a clear privacy and retention policy.
- **Images and scanned PDFs:** OCR and image understanding are not included. PDFs must contain extractable text.
- **Flashcards/quiz:** generated as text in chat, not a spaced-repetition deck or an auto-graded quiz.
- **Voice:** browser speech recognition and speech synthesis, not a continuous full-duplex assistant; device/browser support varies.
- **External scripts:** marked, DOMPurify, and highlight.js load from jsDelivr; for stronger supply-chain security bundle these locally and enforce a strict CSP.
- Gemini costs, quota, model availability and free-tier terms depend on the API account. Set `GEMINI_MODEL` to a supported model if the default becomes unavailable.
- The server-side `GEMINI_API_KEY` is never shipped to the browser. Any public deployment still needs monitoring for abusive API use and spend limits.
- This package is deployment-ready **configuration**, not evidence of a deployed live service. Hosting and Gemini credentials must be supplied by the service owner.
