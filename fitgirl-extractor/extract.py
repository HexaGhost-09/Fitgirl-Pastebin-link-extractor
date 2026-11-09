# FitGirl PrivateBin / FileKeeper direct-link extractor for GitHub Actions
# Accepts FitGirl paste.fitgirl-repacks.site URLs and FileKeeper file-page URLs.

import base64
import json
import os
import re
import time
import zlib
from pathlib import Path

from curl_cffi import requests as cffi_requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
INPUT_FILE = Path(__file__).with_name("links.txt")
OUTPUT_FILE = Path(__file__).with_name("extracted_links.txt")


def base58_decode(value):
    number = 0
    for char in value:
        number = number * 58 + BASE58.index(char)
    result = b""
    while number:
        number, remainder = divmod(number, 256)
        result = bytes([remainder]) + result
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + result


def decrypt_privatebin(url, password=""):
    paste_url, url_key = url.split("#", 1)
    paste_id = paste_url.split("?")[-1]
    base_url = paste_url[:paste_url.index("?")]

    response = cffi_requests.get(
        f"{base_url}?{paste_id}",
        headers={"Accept": "application/json"},
        impersonate="chrome",
        timeout=60,
    )
    response.raise_for_status()
    data = response.json()
    if data.get("status") != 0:
        raise ValueError(f"PrivateBin API error: {data}")

    adata = data["adata"]
    iv_b64, salt_b64, iterations, key_size, _tag, _algo, _mode, compression = adata[0]
    key_input = base58_decode(url_key)
    if password:
        key_input += password.encode()

    derived = PBKDF2HMAC(
        hashes.SHA256(), key_size // 8, base64.b64decode(salt_b64), iterations
    ).derive(key_input)
    aad = json.dumps(adata, separators=(",", ":")).encode()
    raw = AESGCM(derived).decrypt(
        base64.b64decode(iv_b64), base64.b64decode(data["ct"]), aad
    )
    if compression == "zlib":
        raw = zlib.decompress(raw, wbits=-15)
    payload = json.loads(raw.decode())
    return payload.get("paste", raw.decode())


def extract_one(file_url, session):
    file_url = file_url.split("#", 1)[0].strip()
    page = session.get(file_url, timeout=60)
    if page.status_code != 200:
        print(f"  HTTP {page.status_code}: {file_url}")
        return None

    def attr(name, default=""):
        match = re.search(rf'data-{name}="([^"]*)"', page.text)
        return match.group(1) if match else default

    code = attr("code") or file_url.rstrip("/").split("/")[-1]
    if attr("has-captcha") == "true":
        print(f"  {code}: CAPTCHA required; skipped.")
        return None

    try:
        time.sleep(int(attr("countdown", "5")) + 1)
    except ValueError:
        time.sleep(6)

    form_data = {
        "op": "download2",
        "id": code,
        "rand": attr("rand"),
        "referer": attr("referer"),
        "method_free": attr("method") or "Free download",
        "down_direct": "1",
    }
    response = session.post(
        file_url, data=form_data, timeout=60, allow_redirects=False
    )
    direct_url = response.headers.get("location")
    if not direct_url:
        match = re.search(r'https://[^\s"\'<>]+dlproxy[^\s"\'<>]+', response.text)
        direct_url = match.group(0) if match else None
    if not direct_url:
        print(f"  {code}: no CDN link (HTTP {response.status_code}).")
    return direct_url


def extract_all(input_text):
    session = cffi_requests.Session(impersonate="chrome")
    extracted = []

    input_urls = re.findall(r"https?://[^\\s,;]+", input_text)
    for line in input_urls:
        line = line.strip().rstrip(\"\"'<>)]}\")
        if not line:
            continue

        if line.startswith("https://paste.fitgirl-repacks.site/"):
            try:
                paste_text = decrypt_privatebin(line)
                file_urls = re.findall(r"https://filekeeper\.net/[^\s<>\"]+", paste_text)
            except Exception as exc:
                print(f"  Could not decrypt paste: {exc}")
                continue
        elif "filekeeper.net/" in line:
            file_urls = [line]
        else:
            print(f"  Unsupported input skipped: {line}")
            continue

        for file_url in file_urls:
            try:
                result = extract_one(file_url, session)
                if result:
                    print(f"  ✓ {result}")
                    extracted.append(result)
            except Exception as exc:
                print(f"  Error for {file_url}: {exc}")

    return list(dict.fromkeys(extracted))


def main():
    workflow_links = os.environ.get("WORKFLOW_LINKS", "").strip()
    if workflow_links:
        input_text = workflow_links
        print("Using URLs supplied in the GitHub Actions Run workflow input.")
    elif INPUT_FILE.exists():
        input_text = INPUT_FILE.read_text(encoding="utf-8")
        print(f"Using URLs from {INPUT_FILE}.")
    else:
        raise SystemExit("No links supplied in the workflow input and links.txt was not found.")

    results = extract_all(input_text)
    OUTPUT_FILE.write_text(
        "\n".join(results) + ("\n" if results else ""), encoding="utf-8"
    )
    print(f"\nExtracted {len(results)} link(s). Output: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
