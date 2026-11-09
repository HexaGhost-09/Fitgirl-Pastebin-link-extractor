# FitGirl Pastebin Link Extractor

A manually triggered GitHub Actions workflow that decrypts FitGirl PrivateBin pastes, extracts FileKeeper file-page URLs, and resolves those pages to direct CDN links.

## Run

1. Open **Actions** → **FitGirl Pastebin Link Extractor** → **Run workflow**.
2. Expand the **Links** input and paste one or more FitGirl PrivateBin URLs (including their keys) and/or FileKeeper URLs. Separate multiple URLs with spaces, commas, or new lines.
3. Click **Run workflow**.
4. When the run finishes, download the `fitgirl-extracted-links` artifact. It contains `extracted_links.txt`.

If the **Links** field is left empty, the workflow uses `fitgirl-extractor/links.txt` as a fallback. The artifact is retained for 3 days.

CAPTCHA-protected FileKeeper pages are skipped; this workflow does not solve CAPTCHAs. Direct CDN links may expire.

**Security:** Do not commit private paste keys to a public repository. The workflow input is supplied at run time and is not written into the repository, but avoid sharing run logs or input values publicly.
