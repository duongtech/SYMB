# -*- coding: utf-8 -*-
import urllib.request
import json
import os
import sys

DEST_DIR = os.path.join("examples", "04_apk_sample")
os.makedirs(DEST_DIR, exist_ok=True)
DEST_APK = os.path.join(DEST_DIR, "real_app.apk")

# Let's download a real lightweight open-source Android APK
# E.g. AnKu (minimal Android app), or a known public test APK
CANDIDATE_URLS = [
    # Lightweight open source APKs
    ("https://github.com/SecUSo/privacy-friendly-dice/releases/download/v2.1.0/app-release.apk", "PrivacyFriendlyDice.apk"),
    ("https://github.com/SecUSo/privacy-friendly-memo/releases/download/v2.1.1/app-release.apk", "PrivacyFriendlyMemo.apk"),
    ("https://github.com/SecUSo/privacy-friendly-shopping-list/releases/download/v2.0.0/app-release.apk", "ShoppingList.apk"),
    ("https://github.com/termux/termux-app/releases/download/v0.118.1/termux-app_v0.118.1+github-debug_arm64-v8a.apk", "Termux.apk")
]

downloaded = False
for url, filename in CANDIDATE_URLS:
    target_file = os.path.join(DEST_DIR, filename)
    if os.path.exists(target_file) and os.path.getsize(target_file) > 10000:
        print(f"Already downloaded: {target_file} ({os.path.getsize(target_file)} bytes)")
        DEST_APK = target_file
        downloaded = True
        break

    print(f"Attempting download from: {url} ...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read()
            with open(target_file, "wb") as f:
                f.write(content)
            print(f"Successfully downloaded {filename} ({len(content)} bytes)!")
            DEST_APK = target_file
            downloaded = True
            break
    except Exception as e:
        print(f"Failed {url}: {e}")

if not downloaded:
    print("Could not download external APK, checking existing samples.")
    sys.exit(1)

print(f"Ready for analysis: {DEST_APK}")
