# Utility tools

Run these from the package root.

| Tool | Purpose |
| --- | --- |
| `acquire_shared_wayback.py` | Acquire and content-address shared Wayback captures |
| `build_shared_contact_sheets.py` | Build visual contact sheets from acquired images |
| `decode_binary_hint_image.py` | Decode the creator's reversed-bit binary hint |
| `inspect_shared_images.py` | Inspect image dimensions, channels, metadata, and duplicates |
| `live_door_probe.py` | Probe candidate creator routes and classify responses |
| `ocr_pr16_hints.py` | OCR Telegram hint screenshots associated with PR 16 |
| `s91_direct_readability.py` | Render and score direct S91 reading hypotheses |

Tools acquire or inspect evidence; their output is not automatically an accepted
puzzle result. Record resulting hypotheses in `../../docs/ATTEMPT_LOG.md`.
