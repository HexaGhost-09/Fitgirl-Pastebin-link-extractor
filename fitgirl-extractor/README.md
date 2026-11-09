# FitGirl Pastebin Link Extractor

A manually triggered GitHub Actions workflow that decrypts a FitGirl PrivateBin paste, extracts its FileKeeper file-page URLs, and resolves those pages to direct CDN links.

## Run

1. Add a FitGirl paste URL (including its key) or individual FileKeeper URLs to `fitgirl-extractor/links.txt`, one per line.
2. Commit the input changes.
3. Open **Actions** → **FitGirl Pastebin Link Extractor** → **Run workflow**.
4. Download the `fitgirl-extracted-links` artifact from the completed run. It contains `extracted_links.txt`.

The artifact is retained for 3 days. CAPTCHA-protected FileKeeper pages are skipped. This workflow does not solve CAPTCHAs. Direct CDN links may expire.

**Security:** Do not commit private paste keys to a public repository. For private pastes, store the full URL as a GitHub Actions secret and adapt the workflow to read it, or use a private repository.
