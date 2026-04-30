# Privacy Filter Local

Local-only text redaction gateway for AI prompts and Linear writes.

## Setup

```bash
cd /Users/admin/Documents/privacy-filter/.worktrees/privacy-filter-v1/tools/privacy-filter-local
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 127.0.0.1 --port 7861
```

## Routes

- `GET /health`
- `POST /scan`
- `POST /decide`
- `POST /redact`
- `GET /`

## Notes

- First real OPF request may download a model into `~/.opf/privacy_filter`
- Set `PRIVACY_FILTER_DEVICE=cpu` or `cuda`
- Original text is not persisted by design
- Service should be bound to `127.0.0.1` only
