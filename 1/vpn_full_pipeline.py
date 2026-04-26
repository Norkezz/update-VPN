
import asyncio
import aiohttp
import os
import re
import base64
import requests
from bs4 import BeautifulSoup

# ================= CONFIG =================
KEYSCONF_BASE = "https://keysconf.com"
OUTPUT_DIR = "sources"
KEYSCONF_OUT = os.path.join(OUTPUT_DIR, "keysconf_all.txt")
GITHUB_OUT = os.path.join(OUTPUT_DIR, "github_all.txt")
TELEGRAM_OUT = os.path.join(OUTPUT_DIR, "telegram_all.txt")

CONCURRENT = 80

GITHUB_TOKEN = "PUT_YOUR_TOKEN"
GITHUB_REPO = "username/repo"
GITHUB_PATH = "results/elite.txt"

TELEGRAM_BOT_TOKEN = "PUT_BOT_TOKEN"
TELEGRAM_CHANNELS = ["freev2rays", "v2ray_configs"]

# ==========================================

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

# --------- COMMON ---------
def extract_configs(text):
    pattern = r"(vless|vmess|trojan)://[^\s\"']+"
    return re.findall(pattern, text)

# --------- KEYSCONF PARSER (CF bypass via headers) ---------
async def fetch(session, url):
    try:
        async with session.get(url, headers=HEADERS, timeout=15) as r:
            return await r.text()
    except:
        return None

async def parse_keysconf():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    connector = aiohttp.TCPConnector(limit=CONCURRENT)
    async with aiohttp.ClientSession(connector=connector) as session:

        async def parse_page(page):
            url = f"{KEYSCONF_BASE}/?page={page}"
            html = await fetch(session, url)
            if not html:
                return []
            soup = BeautifulSoup(html, "html.parser")
            links = [KEYSCONF_BASE + a.get("href") for a in soup.select("a[href*='/v']")]
            return links

        pages = await asyncio.gather(*[parse_page(i) for i in range(1, 50)])
        links = [l for sub in pages for l in sub]

        async def parse_config(url):
            html = await fetch(session, url)
            if not html:
                return None
            soup = BeautifulSoup(html, "html.parser")
            code = soup.find("code")
            return code.text.strip() if code else None

        tasks = [parse_config(l) for l in links]
        results = await asyncio.gather(*tasks)

        with open(KEYSCONF_OUT, "w", encoding="utf-8") as f:
            for r in results:
                if r:
                    f.write(r + "\n")

        print("[KEYSCONF] done:", len(results))

# --------- GITHUB PARSER ---------
def parse_github():
    url = "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub"
    r = requests.get(url)
    lines = r.text.splitlines()

    with open(GITHUB_OUT, "w") as f:
        for l in lines:
            if l.startswith(("vless://","vmess://","trojan://")):
                f.write(l + "\n")

    print("[GITHUB] done")

# --------- TELEGRAM PARSER ---------
def parse_telegram():
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates"
    r = requests.get(url).json()

    results = []

    for upd in r.get("result", []):
        text = upd.get("message", {}).get("text", "")
        results += extract_configs(text)

    with open(TELEGRAM_OUT, "w") as f:
        for c in results:
            f.write(c + "\n")

    print("[TELEGRAM] done:", len(results))

# --------- SIMPLE CHECKER ---------
async def check_config(session, config):
    try:
        async with session.get("http://1.1.1.1", timeout=5):
            return config
    except:
        return None

async def run_checker(input_files):
    configs = []

    for file in input_files:
        if os.path.exists(file):
            with open(file) as f:
                configs += f.read().splitlines()

    configs = list(set(configs))

    connector = aiohttp.TCPConnector(limit=CONCURRENT)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [check_config(session, c) for c in configs]
        results = await asyncio.gather(*tasks)

    elite = [r for r in results if r]

    print("[CHECKED]", len(elite))

    return elite

# --------- GITHUB UPLOAD ---------
def upload_github(content):
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_PATH}"

    encoded = base64.b64encode(content.encode()).decode()

    data = {
        "message": "auto update",
        "content": encoded
    }

    headers = {"Authorization": f"token {GITHUB_TOKEN}"}

    r = requests.put(url, json=data, headers=headers)
    print("[UPLOAD]", r.status_code)

# --------- MAIN PIPELINE ---------
async def main():
    await parse_keysconf()
    parse_github()
    parse_telegram()

    elite = await run_checker([KEYSCONF_OUT, GITHUB_OUT, TELEGRAM_OUT])

    upload_github("\n".join(elite))


if __name__ == "__main__":
    asyncio.run(main())
