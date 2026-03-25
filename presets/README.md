# Preset Library

The public repository does not bundle third-party PCAP corpora.

If you want local preset captures:

- create category folders under `presets/`
- add your own `.pcap`, `.pcapng`, or `.cap` files locally
- or upload them through the admin UI after deployment

Preset capture files are ignored by `.gitignore` and `.dockerignore` so they do not get committed or baked into public images by default.
