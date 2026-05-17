"""
_run_xray_batch_patched.py
==========================
Готовая замена для функции _run_xray_batch в admin_config_update26.py.

Скопируйте тело функции ниже вместо оригинала.
Перед этим убедитесь, что в файле уже есть все функции из singbox_check_patch.py.
"""


def _run_xray_batch(
    links: list,
    xray_exe: str,
    port_base: int = 20000,
    workers: int = None,
    verbose: bool = True,
    enable_stage4: bool = False,
    stage4_threshold_ms: int = None,
) -> list:
    """Run the xray/singbox check on `links` and return those that pass.

    Роутинг по движку:
      vless://   → xray  (check_config_full, как раньше)
      vmess://   → sing-box  (check_config_singbox)
      trojan://  → sing-box
      ss://      → sing-box
      hy2://     → sing-box
      hysteria2://→ sing-box
      tuic://    → sing-box

    Если sing-box не найден — все протоколы идут через xray (старое поведение).
    """
    import threading
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # Дефолты из оригинального модуля (на случай standalone-запуска)
    if workers is None:
        workers = globals().get("CHECK_WORKERS", 24)
    if stage4_threshold_ms is None:
        stage4_threshold_ms = globals().get("CHECK4_MAX_STACK_PING_MS", 995)

    # ── Ищем sing-box один раз до запуска воркеров ───────────────────────────
    _singbox_exe = _find_or_download_singbox()
    if _singbox_exe:
        if verbose:
            print(f"  ✓  sing-box found: {_singbox_exe}", flush=True)
    else:
        if verbose:
            print("  ⚠  sing-box not found — vmess/trojan/ss/hy2 will use xray (may fail)", flush=True)

    if verbose:
        proto_stat: dict = {}
        for lnk in links:
            proto = _protocol_of(lnk)
            proto_stat[proto] = proto_stat.get(proto, 0) + 1
        engine_info = " | ".join(
            f"{p}({n})→{'sb' if _needs_singbox(p+' ') and _singbox_exe else 'xray'}"
            for p, n in sorted(proto_stat.items())
        )
        stage_label = "4-stage" if enable_stage4 else "3-stage"
        print(
            f"  🔬  check ({stage_label}): {len(links)} configs | "
            f"{workers} threads | {engine_info}",
            flush=True,
        )

    # ── Прогреваем reference MD5 до запуска воркеров ─────────────────────────
    _get_reference_md5(CHECK3_URL)

    working: list = []
    lock = threading.Lock()
    done = [0]

    # Фиксированный пул портов: workers слотов × 20 портов каждый
    _PORT_STEP  = 20
    _port_pool  = list(range(port_base, port_base + workers * _PORT_STEP, _PORT_STEP))
    _free_slots = list(_port_pool)
    _slot_lock  = threading.Lock()
    _slot_cv    = threading.Condition(_slot_lock)

    def _acquire_port() -> int:
        with _slot_cv:
            while not _free_slots:
                _slot_cv.wait()
            return _free_slots.pop()

    def _release_port(p: int) -> None:
        with _slot_cv:
            _free_slots.append(p)
            _slot_cv.notify()

    def _check_task(lnk: str):
        p = _acquire_port()
        try:
            proto = _protocol_of(lnk)
            use_singbox = _needs_singbox(lnk) and _singbox_exe is not None

            if use_singbox:
                # Не-VLESS: sing-box
                result = check_config_singbox(lnk, _singbox_exe, p)
            else:
                # VLESS/Reality/unknown: xray (оригинальная логика)
                result = check_config_full(
                    lnk, xray_exe, p,
                    skip_stage4=not enable_stage4,
                    stage4_threshold_ms=stage4_threshold_ms,
                )
        except Exception:
            result = False
        finally:
            _release_port(p)
        return lnk, result

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_check_task, l): l for l in links}
        for f in as_completed(futures):
            l, ok = f.result()
            with lock:
                done[0] += 1
                if ok:
                    working.append(l)
                if verbose and done[0] % 5 == 0:
                    print(
                        f"    check {done[0]}/{len(links)}  working: {len(working)}",
                        end="\r",
                        flush=True,
                    )

    if verbose:
        print(f"\n  ✓  check done: {len(working)}/{len(links)} working", flush=True)

    return working
