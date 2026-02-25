"""
Анализ дампа сети с помощью pyshark.
Извлекает: DNS-запросы, IP-адреса, DHCP-события, HTTP-запросы.
Визуализирует результаты и сохраняет артефакты в CSV/JSON/PNG.

Использование:
  python3 analyze_pcap.py
  python3 analyze_pcap.py --pcap dhcp.pcapng
  python3 analyze_pcap.py --pcap capture.pcap --out results
  python3 analyze_pcap.py --pcap traffic.pcapng --out /tmp/report

Аргументы:
  --pcap  PATH   Путь к pcap/pcapng-файлу (по умолчанию: dhcp.pcapng)
  --out   DIR    Папка для сохранения артефактов  (по умолчанию: artifacts)

Примеры:
  # Анализ стандартного файла, результаты в папке artifacts/
  python3 analyze_pcap.py

  # Указать другой дамп и выходную папку
  python3 analyze_pcap.py --pcap ~/captures/lab.pcap --out ~/captures/report

  # Быстрый запуск с перенаправлением лога в файл
  python3 analyze_pcap.py --pcap dhcp.pcapng 2>&1 | tee analysis.log

Зависимости (установка):
  pip install pyshark matplotlib pandas
"""

import argparse
import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import json
import os
from collections import Counter
from datetime import datetime


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Анализ pcap/pcapng-дампа сети: DNS, DHCP, IP, HTTP.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Примеры:\n"
            "  python3 analyze_pcap.py\n"
            "  python3 analyze_pcap.py --pcap capture.pcap\n"
            "  python3 analyze_pcap.py --pcap traffic.pcapng --out /tmp/report\n"
        ),
    )
    parser.add_argument(
        "--pcap", default="dhcp.pcapng",
        metavar="PATH",
        help="Путь к pcap/pcapng-файлу (по умолчанию: dhcp.pcapng)",
    )
    parser.add_argument(
        "--out", default="artifacts",
        metavar="DIR",
        help="Папка для сохранения артефактов (по умолчанию: artifacts)",
    )
    return parser.parse_args()


_ARGS = _parse_args()
PCAP_FILE = _ARGS.pcap
OUTPUT_DIR = _ARGS.out
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ─────────────────────────────────────────────
# 1. ПАРСИНГ ПАКЕТОВ
# ─────────────────────────────────────────────

def parse_pcap(path: str) -> dict:
    """
    Проходит по всем пакетам и собирает:
      - dns_queries  : список DNS-запросов
      - ip_pairs     : список (src_ip, dst_ip, proto, time)
      - dhcp_events  : список DHCP-событий
      - http_events  : список HTTP GET/POST
    """
    dns_queries = []
    ip_pairs = []
    dhcp_events = []
    http_events = []

    cap = pyshark.FileCapture(path, keep_packets=False)

    for pkt in cap:
        try:
            ts = float(pkt.sniff_timestamp)
            dt = datetime.fromtimestamp(ts)

            # ── IP-уровень ─────────────────────────────────────
            src_ip = dst_ip = proto = None
            if hasattr(pkt, "ip"):
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                proto = pkt.transport_layer or pkt.highest_layer
                ip_pairs.append({
                    "time": dt,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "proto": proto,
                })

            # ── DNS ────────────────────────────────────────────
            if hasattr(pkt, "dns"):
                dns = pkt.dns
                # qr == 0 → запрос, qr == 1 → ответ
                try:
                    qr = int(dns.flags_response)
                except Exception:
                    qr = -1

                try:
                    qname = dns.qry_name
                except Exception:
                    qname = None

                try:
                    answers_raw = dns.a  # первый A-ответ
                except Exception:
                    answers_raw = None

                if qname:
                    dns_queries.append({
                        "time": dt,
                        "src_ip": src_ip,
                        "qname": qname,
                        "type": "response" if qr == 1 else "query",
                        "answer": answers_raw,
                    })

            # ── DHCP / BOOTP ───────────────────────────────────
            if hasattr(pkt, "dhcp") or hasattr(pkt, "bootp"):
                layer = pkt.dhcp if hasattr(pkt, "dhcp") else pkt.bootp
                try:
                    msg_type = layer.option_dhcp
                except Exception:
                    msg_type = "unknown"

                try:
                    client_mac = layer.hw_mac_addr
                except Exception:
                    try:
                        client_mac = pkt.eth.src
                    except Exception:
                        client_mac = "unknown"

                try:
                    assigned_ip = layer.ip_your
                except Exception:
                    assigned_ip = None

                dhcp_events.append({
                    "time": dt,
                    "msg_type": msg_type,
                    "client_mac": client_mac,
                    "assigned_ip": assigned_ip,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                })

            # ── HTTP ───────────────────────────────────────────
            if hasattr(pkt, "http"):
                http = pkt.http
                try:
                    method = http.request_method
                    uri = http.request_uri
                    host = http.host if hasattr(http, "host") else dst_ip
                    http_events.append({
                        "time": dt,
                        "method": method,
                        "host": host,
                        "uri": uri,
                        "src_ip": src_ip,
                    })
                except Exception:
                    pass

        except Exception:
            continue

    cap.close()
    return {
        "dns_queries": dns_queries,
        "ip_pairs": ip_pairs,
        "dhcp_events": dhcp_events,
        "http_events": http_events,
    }


# ─────────────────────────────────────────────
# 2. АНАЛИЗ И ВЫВОД В КОНСОЛЬ
# ─────────────────────────────────────────────

def analyze(data: dict):
    dns = data["dns_queries"]
    ips = data["ip_pairs"]
    dhcp = data["dhcp_events"]
    http = data["http_events"]

    print("\n" + "═" * 60)
    print("  АНАЛИЗ СЕТЕВОГО ДАМПА")
    print("═" * 60)

    # ── Общая статистика ────────────────────────────────────────
    print(f"\n[*] Всего пакетов с IP:      {len(ips)}")
    print(f"[*] DNS-запросов/ответов:    {len(dns)}")
    print(f"[*] DHCP-событий:            {len(dhcp)}")
    print(f"[*] HTTP-запросов:           {len(http)}")

    # ── DNS ─────────────────────────────────────────────────────
    if dns:
        print("\n── DNS-запросы (топ-20) ─────────────────────────────")
        queries_only = [d["qname"] for d in dns if d["type"] == "query" and d["qname"]]
        counter = Counter(queries_only)
        df_dns = pd.DataFrame(counter.most_common(20), columns=["domain", "count"])
        print(df_dns.to_string(index=False))

    # ── DHCP ────────────────────────────────────────────────────
    if dhcp:
        print("\n── DHCP-события ─────────────────────────────────────")
        df_dhcp = pd.DataFrame(dhcp)
        # читаемые типы сообщений
        dhcp_type_map = {
            "1": "DISCOVER", "2": "OFFER",
            "3": "REQUEST",  "4": "DECLINE",
            "5": "ACK",      "6": "NAK",
            "7": "RELEASE",  "8": "INFORM",
        }
        df_dhcp["msg_label"] = df_dhcp["msg_type"].astype(str).map(
            lambda x: dhcp_type_map.get(x, x)
        )
        print(df_dhcp[["time", "msg_label", "client_mac", "assigned_ip"]].to_string(index=False))

    # ── IP-активность ────────────────────────────────────────────
    if ips:
        print("\n── Самые активные источники (топ-10) ────────────────")
        src_counter = Counter(p["src_ip"] for p in ips if p["src_ip"])
        df_src = pd.DataFrame(src_counter.most_common(10), columns=["src_ip", "packets"])
        print(df_src.to_string(index=False))

        print("\n── Самые популярные назначения (топ-10) ─────────────")
        dst_counter = Counter(p["dst_ip"] for p in ips if p["dst_ip"])
        df_dst = pd.DataFrame(dst_counter.most_common(10), columns=["dst_ip", "packets"])
        print(df_dst.to_string(index=False))

    # ── HTTP ─────────────────────────────────────────────────────
    if http:
        print("\n── HTTP-запросы ─────────────────────────────────────")
        df_http = pd.DataFrame(http)
        print(df_http[["time", "method", "host", "uri"]].to_string(index=False))

    return {
        "dns_counter": Counter(
            d["qname"] for d in dns if d["type"] == "query" and d["qname"]
        ),
        "src_counter": Counter(p["src_ip"] for p in ips if p["src_ip"]),
        "df_dns": pd.DataFrame(dns) if dns else pd.DataFrame(),
        "df_dhcp": pd.DataFrame(dhcp) if dhcp else pd.DataFrame(),
        "df_http": pd.DataFrame(http) if http else pd.DataFrame(),
        "df_ips": pd.DataFrame(ips) if ips else pd.DataFrame(),
    }


# ─────────────────────────────────────────────
# 3. СОХРАНЕНИЕ АРТЕФАКТОВ (CSV / JSON)
# ─────────────────────────────────────────────

def save_artifacts(data: dict, stats: dict):
    # DNS → CSV
    if not stats["df_dns"].empty:
        path = os.path.join(OUTPUT_DIR, "dns_queries.csv")
        stats["df_dns"].to_csv(path, index=False)
        print(f"\n[+] DNS-запросы сохранены: {path}")

    # DHCP → CSV
    if not stats["df_dhcp"].empty:
        path = os.path.join(OUTPUT_DIR, "dhcp_events.csv")
        stats["df_dhcp"].to_csv(path, index=False)
        print(f"[+] DHCP-события сохранены: {path}")

    # IP-пары → CSV
    if not stats["df_ips"].empty:
        path = os.path.join(OUTPUT_DIR, "ip_pairs.csv")
        stats["df_ips"].to_csv(path, index=False)
        print(f"[+] IP-пары сохранены:      {path}")

    # HTTP → CSV
    if not stats["df_http"].empty:
        path = os.path.join(OUTPUT_DIR, "http_events.csv")
        stats["df_http"].to_csv(path, index=False)
        print(f"[+] HTTP-события сохранены: {path}")

    # Сводный JSON
    summary = {
        "top_dns_domains": dict(stats["dns_counter"].most_common(20)),
        "top_src_ips":     dict(stats["src_counter"].most_common(20)),
        "total_dns":       len(stats["df_dns"]),
        "total_dhcp":      len(stats["df_dhcp"]),
        "total_http":      len(stats["df_http"]),
        "total_ip_pkts":   len(stats["df_ips"]),
    }
    path = os.path.join(OUTPUT_DIR, "summary.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"[+] Сводный JSON сохранён:  {path}")


# ─────────────────────────────────────────────
# 4. ВИЗУАЛИЗАЦИЯ
# ─────────────────────────────────────────────

def visualize(stats: dict, data: dict):
    plots_created = []

    # ── 4.1 Топ DNS-доменов (горизонтальный бар) ──────────────
    dns_counter = stats["dns_counter"]
    if dns_counter:
        top_n = dns_counter.most_common(15)
        domains, counts = zip(*top_n)

        fig, ax = plt.subplots(figsize=(10, 6))
        bars = ax.barh(list(reversed(domains)), list(reversed(counts)),
                       color="#4c72b0", edgecolor="white")
        ax.bar_label(bars, padding=3, fontsize=9)
        ax.set_xlabel("Количество запросов")
        ax.set_title("Топ DNS-доменов по количеству запросов")
        ax.spines[["top", "right"]].set_visible(False)
        plt.tight_layout()
        path = os.path.join(OUTPUT_DIR, "dns_top_domains.png")
        plt.savefig(path, dpi=150)
        plt.close()
        plots_created.append(path)

    # ── 4.2 DHCP: круговая диаграмма типов сообщений ──────────
    df_dhcp = stats["df_dhcp"]
    if not df_dhcp.empty and "msg_type" in df_dhcp.columns:
        dhcp_type_map = {
            "1": "DISCOVER", "2": "OFFER",
            "3": "REQUEST",  "4": "DECLINE",
            "5": "ACK",      "6": "NAK",
            "7": "RELEASE",  "8": "INFORM",
        }
        labels_raw = df_dhcp["msg_type"].astype(str).map(
            lambda x: dhcp_type_map.get(x, f"Type {x}")
        )
        type_counts = labels_raw.value_counts()

        fig, ax = plt.subplots(figsize=(7, 7))
        wedges, texts, autotexts = ax.pie(
            type_counts.values,
            labels=type_counts.index,
            autopct="%1.1f%%",
            startangle=90,
            colors=plt.cm.Set2.colors,
        )
        ax.set_title("Распределение DHCP-сообщений")
        plt.tight_layout()
        path = os.path.join(OUTPUT_DIR, "dhcp_distribution.png")
        plt.savefig(path, dpi=150)
        plt.close()
        plots_created.append(path)

    # ── 4.3 DNS-запросы по времени (временной ряд) ────────────
    df_dns = stats["df_dns"]
    if not df_dns.empty and "time" in df_dns.columns:
        df_q = df_dns[df_dns.get("type", pd.Series(["query"] * len(df_dns))) == "query"].copy()
        if not df_q.empty:
            df_q["time"] = pd.to_datetime(df_q["time"])
            df_q = df_q.set_index("time").sort_index()

            # ресемплируем по секундам (или минутам, если трафик длинный)
            span = (df_q.index[-1] - df_q.index[0]).total_seconds()
            freq = "1s" if span < 120 else "1min"
            ts = df_q["qname"].resample(freq).count()

            fig, ax = plt.subplots(figsize=(12, 4))
            ax.fill_between(ts.index, ts.values, alpha=0.4, color="#dd8452")
            ax.plot(ts.index, ts.values, color="#dd8452", linewidth=1.5)
            ax.set_ylabel("DNS-запросов")
            ax.set_xlabel("Время")
            ax.set_title("DNS-запросы по времени")
            ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
            plt.xticks(rotation=30)
            ax.spines[["top", "right"]].set_visible(False)
            plt.tight_layout()
            path = os.path.join(OUTPUT_DIR, "dns_over_time.png")
            plt.savefig(path, dpi=150)
            plt.close()
            plots_created.append(path)

    # ── 4.4 Топ источников IP (бар) ───────────────────────────
    src_counter = stats["src_counter"]
    if src_counter:
        top_ips = src_counter.most_common(10)
        ips_labels, ip_counts = zip(*top_ips)

        fig, ax = plt.subplots(figsize=(10, 5))
        bars = ax.bar(ips_labels, ip_counts, color="#55a868", edgecolor="white")
        ax.bar_label(bars, padding=3, fontsize=9)
        ax.set_ylabel("Пакетов")
        ax.set_title("Топ источников IP-трафика")
        plt.xticks(rotation=25, ha="right")
        ax.spines[["top", "right"]].set_visible(False)
        plt.tight_layout()
        path = os.path.join(OUTPUT_DIR, "top_src_ips.png")
        plt.savefig(path, dpi=150)
        plt.close()
        plots_created.append(path)

    if plots_created:
        print("\n[+] Графики сохранены:")
        for p in plots_created:
            print(f"    {p}")
    else:
        print("\n[!] Данных для графиков недостаточно.")


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print(f"[*] Загрузка файла: {PCAP_FILE}")
    data = parse_pcap(PCAP_FILE)

    stats = analyze(data)
    save_artifacts(data, stats)
    visualize(stats, data)

    print("\n[✓] Анализ завершён. Артефакты в папке:", OUTPUT_DIR)