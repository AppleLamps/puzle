# Telegram Desktop export checklist

1. Open this invitation in Telegram Desktop and join **GSMG Puzzle Solvers**: <https://t.me/joinchat/AJXEwEWK9gvhxwkgeXJUVw>.
2. Let Telegram finish loading the group's history and media thumbnails.
3. Open **Settings → Advanced → Export Telegram data**.
4. Under chat selection, choose **GSMG Puzzle Solvers** only. If Telegram instead offers **Export chat history** from the group's three-dot menu, use that group-specific command.
5. Select **Machine-readable JSON**. Do not select HTML as the only format.
6. Include:
   - text messages;
   - photos;
   - files/documents;
   - reply metadata;
   - the full available date range.
7. Audio, video messages, stickers, GIFs, and voice messages can be omitted unless Telegram requires them for a complete export.
8. Set a generous media size limit so the creator-posted binary hint and other screenshots are included.
9. Export into a new dedicated folder, for example `C:\Users\lucas\Downloads\GSMG-Telegram-Export`.
10. When the export finishes, send Codex the absolute path to the folder containing `result.json`. Do **not** upload or paste your Telegram session files, API credentials, phone number, or unrelated private chats.

The next audit will first hash the export, then extract only creator messages plus minimal reply context. Unrelated participant data will not be reproduced in reports.
