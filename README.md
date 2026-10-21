# crotalus

Real-time supply-chain monitoring for PyPI.

> **Early development.** Not usable yet.

## What it does

Malicious packages reach PyPI through typosquatting, malicious install scripts
and hijacked maintainer accounts. crotalus watches new releases as they are
published, flags suspicious ones within minutes, and lets you check whether a
specific release is safe.

## Status

- [x] Ingest new releases from PyPI's RSS feed
- [x] Database schema
- [x] Store releases 
- [x] Detection rules 
- [ ] Rule scoring + verdicts*(in progress)*
- [ ] LLM triaging for code diffs
- [ ] API
- [ ] Deployment on AWS

## Development

Requires Python 3.10+ and Docker.

```bash
pip install -e ".[dev]"
docker compose up -d
pytest
```

## License

MIT
