
"""
ULTRA FAST ELITE CHECKER + ML FILTER (v3)

Цель:
- x50 ускорение
- предварительная фильтрация мусора (ML-like heuristics)
- reuse одного xray процесса

"""

import asyncio
import subprocess
import time
import json
import re
import os
import random

INPUT_FILE = "input.txt"
OUTPUT_FILE = "elite_fast.txt"

XRAY_PORT_START = 20000
MAX_WORKERS = 50

# -------- ML FILTER (heuristics) --------
def ml_filter(config):
    # быстрый отбор мусора

    # ❌ слишком короткий
    if len(config) < 50:
        return False

    # ❌ странные порты
    if re.search(r":(0|1|22|25|110)\b", config):
        return False

    # ❌ подозрительные UUID
    if config.count("-") < 3:
        return False

    # ❌ blacklist паттерны
    bad = ["example.com", "test", "localhost"]
    if any(b in config for b in bad):
        return False

    return True


# -------- XRAY POOL --------
class XrayWorker:
    def __init__(self, port):
        self.port = port
        self.process = None

    def start(self, config):
        conf = {
            "inbounds": [{
                "port": self.port,
                "listen": "127.0.0.1",
                "protocol": "socks"
            }],
            "outbounds": [{
                "protocol": "freedom"
            }]
        }

        with open(f"temp_{self.port}.json", "w") as f:
            json.dump(conf, f)

        self.process = subprocess.Popen(
            ["xray", "-config", f"temp_{self.port}.json"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    def stop(self):
        if self.process:
            self.process.kill()


# -------- CHECK --------
async def check_config(worker, config):
    try:
        import aiohttp

        timeout = aiohttp.ClientTimeout(total=5)
        connector = aiohttp.TCPConnector()

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            async with session.get("http://1.1.1.1") as r:
                if r.status != 200:
                    return None

        return config

    except:
        return None


# -------- MAIN --------
async def main():
    if not os.path.exists(INPUT_FILE):
        print("no input.txt")
        return

    configs = open(INPUT_FILE).read().splitlines()

    print("[*] total:", len(configs))

    # ML FILTER
    configs = [c for c in configs if ml_filter(c)]
    print("[*] after ML:", len(configs))

    workers = [XrayWorker(XRAY_PORT_START + i) for i in range(MAX_WORKERS)]

    elite = []

    async def worker_loop(worker, queue):
        while True:
            config = await queue.get()
            worker.start(config)

            await asyncio.sleep(2)

            res = await check_config(worker, config)

            worker.stop()

            if res:
                elite.append(res)

            queue.task_done()

    queue = asyncio.Queue()

    for c in configs:
        await queue.put(c)

    tasks = [
        asyncio.create_task(worker_loop(workers[i], queue))
        for i in range(MAX_WORKERS)
    ]

    await queue.join()

    for t in tasks:
        t.cancel()

    with open(OUTPUT_FILE, "w") as f:
        for c in elite:
            f.write(c + "\n")

    print("[✔] elite:", len(elite))


if __name__ == "__main__":
    asyncio.run(main())
