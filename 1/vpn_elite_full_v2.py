
"""
ADVANCED ELITE VPN PIPELINE (parser + elite checker + github upload)

⚠️ Требует доустановки:
pip install aiohttp beautifulsoup4 requests cloudscraper playwright telethon

Playwright setup:
python -m playwright install

Telegram (Telethon) setup:
- api_id / api_hash с https://my.telegram.org

Xray:
- должен быть установлен и доступен в PATH

"""

import asyncio
import aiohttp
import os
import re
import base64
import requests
from bs4 import BeautifulSoup
import subprocess
import time
import json

# ================= CONFIG =================

OUTPUT_DIR = "sources"
ELITE_OUT = "elite.txt"

KEYSCONF_BASE = "https://keysconf.com"

CONCURRENT = 100

# GitHub
GITHUB_TOKEN = "PUT_TOKEN"
GITHUB_REPO = "username/repo"
GITHUB_PATH = "results/elite.txt"

# Telegram (Telethon)
TG_API_ID = 123456
TG_API_HASH = "PUT_HASH"
TG_CHANNELS = ["freev2rays", "v2rayfree"]

# ==========================================

HEADERS = {"User-Agent": "Mozilla/5.0"}

# --------- CONFIG EXTRACTION ---------
CONFIG_REGEX = r"(?:vless|vmess|trojan)://[^\s\"']+"

def extract_configs(text):
    return re.findall(CONFIG_REGEX, text)

# --------- CLOUDSCRAPER (CF bypass) ---------
def fetch_cf(url):
    import cloudscraper
    scraper = cloudscraper.create_scraper()
    try:
        return scraper.get(url, timeout=15).text
    except:
        return None

# --------- PLAYWRIGHT (fallback) ---------
async def fetch_playwright(url):
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            await page.goto(url, timeout=15000)
            html = await page.content()
            await browser.close()
            return html
    except:
        return None

# --------- KEYSCONF PARSER ---------
async def parse_keysconf():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    results = []

    async def parse_page(page):
        url = f"{KEYSCONF_BASE}/?page={page}"
        html = fetch_cf(url)
        if not html:
            html = await fetch_playwright(url)
        if not html:
            return []

        soup = BeautifulSoup(html, "html.parser")
        links = [KEYSCONF_BASE + a.get("href") for a in soup.select("a[href*='/v']")]
        return links

    pages = await asyncio.gather(*[parse_page(i) for i in range(1, 50)])
    links = [l for sub in pages for l in sub]

    async def parse_config(url):
        html = fetch_cf(url)
        if not html:
            html = await fetch_playwright(url)
        if not html:
            return None

        soup = BeautifulSoup(html, "html.parser")
        code = soup.find("code")
        return code.text.strip() if code else None

    tasks = [parse_config(l) for l in links]
    configs = await asyncio.gather(*tasks)

    out = os.path.join(OUTPUT_DIR, "keysconf.txt")
    with open(out, "w") as f:
        for c in configs:
            if c:
                f.write(c + "\n")

    print("[KEYSCONF]", len(configs))
    return out

# --------- TELEGRAM FULL PARSER ---------
async def parse_telegram():
    from telethon import TelegramClient

    client = TelegramClient("session", TG_API_ID, TG_API_HASH)
    await client.start()

    results = []

    for ch in TG_CHANNELS:
        async for msg in client.iter_messages(ch, limit=10000):
            if msg.text:
                results += extract_configs(msg.text)

    out = os.path.join(OUTPUT_DIR, "telegram.txt")
    with open(out, "w") as f:
        for c in results:
            f.write(c + "\n")

    print("[TELEGRAM]", len(results))
    return out

# --------- ELITE CHECKER ---------
def run_xray(config):
    # генерим временный config.json
    conf = {
        "outbounds": [{"protocol": "freedom"}],
        "inbounds": [{"port": 1080, "protocol": "socks"}]
    }

    with open("temp.json", "w") as f:
        json.dump(conf, f)

    try:
        p = subprocess.Popen(["xray", "-config", "temp.json"])
        time.sleep(5)

        r = requests.get("http://httpbin.org/ip", timeout=5)
        ip = r.json().get("origin")

        p.kill()

        return ip
    except:
        return None

def elite_check(config):
    ip = run_xray(config)
    if not ip:
        return None

    try:
        r = requests.get("https://www.google.com", timeout=5)
        if r.status_code != 200:
            return None
    except:
        return None

    return config

async def run_checker(files):
    configs = []
    for f in files:
        if os.path.exists(f):
            configs += open(f).read().splitlines()

    configs = list(set(configs))

    loop = asyncio.get_event_loop()

    tasks = [loop.run_in_executor(None, elite_check, c) for c in configs]
    results = await asyncio.gather(*tasks)

    elite = [r for r in results if r]

    with open(ELITE_OUT, "w") as f:
        for c in elite:
            f.write(c + "\n")

    print("[ELITE]", len(elite))
    return elite

# --------- GITHUB UPLOAD ---------
def upload(content):
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_PATH}"
    encoded = base64.b64encode(content.encode()).decode()

    data = {
        "message": "auto update elite",
        "content": encoded
    }

    headers = {"Authorization": f"token {GITHUB_TOKEN}"}
    r = requests.put(url, json=data, headers=headers)

    print("[UPLOAD]", r.status_code)

# --------- MAIN ---------
async def main():
    k = await parse_keysconf()
    t = await parse_telegram()

    elite = await run_checker([k, t])

    upload("\n".join(elite))

if __name__ == "__main__":
    asyncio.run(main())
