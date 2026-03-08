"""
Автоматизированный мониторинг и реагирование на угрозы.

Скрипт выполняет полный цикл анализа безопасности:

Этап 1 — Сбор данных из двух источников:
    - Локальные логи (sample_logs.json): Windows Event Log, DNS, HTTP.
    - API VirusTotal v3: проверка подозрительных IP-адресов и доменов.

Этап 2 — Анализ данных и выявление угроз:
    - Brute-force атаки (множественные неудачные входы с одного IP).
    - Очистка/остановка журналов аудита.
    - Установка подозрительных служб, запуск опасных процессов.
    - Эскалация привилегий.
    - Подозрительные DNS-запросы (по TLD, DGA-паттернам, длине).
    - DNS-туннелирование (аномальные длинные запросы).
    - SQL Injection, XSS, Path Traversal, Command Injection.
    - Доступ к чувствительным файлам (.env, config.json и т.д.).

Этап 3 — Реагирование:
    - Имитация блокировки подозрительных IP-адресов.
    - Вывод предупреждений о критических угрозах.

Этап 4 — Формирование отчёта и визуализация:
    - Сохранение отчёта в форматах JSON и CSV.
    - Построение графиков: угрозы по типам, топ-5 IP, распределение
      по серьёзности. Сохранение в PNG.

Зависимости:
    pip install requests pandas matplotlib python-dotenv

Запуск:
    python threat_monitor.py
"""


import json
import os
import shutil
import sys
from collections import Counter
from datetime import datetime

import matplotlib.pyplot as plt
import pandas as pd
import requests
from dotenv import load_dotenv


# ==========================
# НАСТРОЙКИ
# ==========================

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": API_KEY, "Accept": "application/json"}

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_FILE = os.path.join(SCRIPT_DIR, "sample_logs.json")

# Пороги для анализа
BRUTE_FORCE_LIMIT = 5       # Сколько неудачных входов считаем brute-force
DNS_ANOMALY_LENGTH = 20     # Минимальная длина аномального DNS-запроса

# Известные безопасные домены (всё остальное проверяем через VirusTotal)
KNOWN_SAFE_DOMAINS = {
    "google.com", "microsoft.com", "update.microsoft.com",
    "github.com", "stackoverflow.com", "cdn.jsdelivr.net",
}

# Подозрительные TLD (часто используются для фишинга и C2)
SUSPICIOUS_TLDS = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq"}



# ==========================
# ЭТАП 1. СБОР ДАННЫХ — ЛОГИ
# ==========================

def load_logs():
    """Загружает логи из sample_logs.json"""
    print(f"\n Загрузка логов из {LOGS_FILE}...")

    if not os.path.exists(LOGS_FILE):
        print(f" Файл {LOGS_FILE} не найден!")
        sys.exit(1)

    with open(LOGS_FILE, "r", encoding="utf-8") as f:
        logs = json.load(f)

    frames = {}
    for name, records in logs.items():
        df = pd.DataFrame(records)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        frames[name] = df
        print(f"  [{name}] — {len(df)} записей")

    return frames


# ==========================
# ЭТАП 1. СБОР ДАННЫХ — API VIRUSTOTAL
# ==========================

def collect_virustotal_data(suspicious_ips, suspicious_domains):
    """Проверяет подозрительные IP и домены через VirusTotal"""
    if not API_KEY:
        print(" API-ключ VirusTotal не задан. Пропускаем.")
        return [], []

    print("\n Проверка через VirusTotal API...")

    ip_results = []
    for ip in suspicious_ips:
        print(f"  Проверяем IP: {ip}")
        stats = check_virustotal("ip_addresses", ip)
        ip_results.append({"ip": ip, **stats})

    domain_results = []
    for domain in suspicious_domains:
        print(f"  Проверяем домен: {domain}")
        stats = check_virustotal("domains", domain)
        domain_results.append({"domain": domain, **stats})

    return ip_results, domain_results

def check_virustotal(resource_type, value):
    """
    Универсальная проверка объекта через VirusTotal API.
    resource_type: "ip_addresses" или "domains"
    value: IP-адрес или доменное имя
    """
    url = f"{BASE_URL}/{resource_type}/{value}"
    empty = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}

    try:
        response = requests.get(url, headers=HEADERS, timeout=15)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"].get("last_analysis_stats", {})
            return {key: stats.get(key, 0) for key in empty}
        else:
            print(f"  VirusTotal вернул {response.status_code} для {value}")

    except requests.RequestException as e:
        print(f"  Ошибка запроса для {value}: {e}")

    return empty

# ==========================
# ЭТАП 2. АНАЛИЗ ДАННЫХ
# ==========================

def analyze_winevent(winevent, threats):
    """Анализ Windows Event Log"""

    # Brute-force: кол-во неудачных входов (event_id 4625) с одного IP
    failed = winevent[winevent["event_id"] == 4625]
    brute_ips = failed.groupby("source_ip")["count"].sum()

    for ip, total in brute_ips.items():
        if total > BRUTE_FORCE_LIMIT:
            threats.append({
                "source": "winevent", "type": "Brute-force",
                "severity": "HIGH", "ip": ip,
                "details": f"{total} неудачных попыток входа с IP {ip}",
            })

    # Очистка/остановка журнала (event_id 1102, 1100)
    for _, row in winevent[winevent["event_id"].isin([1102, 1100])].iterrows():
        threats.append({
            "source": "winevent", "type": "Очистка/остановка журнала",
            "severity": "CRITICAL", "ip": row["source_ip"],
            "details": f"{row['user']}: {row['description']} с IP {row['source_ip']}",
        })

    # Установка подозрительных служб (event_id 4697)
    for _, row in winevent[winevent["event_id"] == 4697].iterrows():
        threats.append({
            "source": "winevent", "type": "Подозрительная служба",
            "severity": "CRITICAL", "ip": row["source_ip"],
            "details": f"{row['description']} с IP {row['source_ip']}",
        })

    # Подозрительные процессы (event_id 4688)
    suspicious_keywords = ["powershell", "-enc", "cmd.exe /c", "certutil"]
    for _, row in winevent[winevent["event_id"] == 4688].iterrows():
        desc = row["description"].lower()
        if any(kw in desc for kw in suspicious_keywords):
            threats.append({
                "source": "winevent", "type": "Подозрительный процесс",
                "severity": "HIGH", "ip": row["source_ip"],
                "details": f"{row['description']} с IP {row['source_ip']}",
            })

    # Эскалация привилегий (event_id 4672, 4732)
    for _, row in winevent[winevent["event_id"].isin([4672, 4732])].iterrows():
        threats.append({
            "source": "winevent", "type": "Эскалация привилегий",
            "severity": "HIGH", "ip": row["source_ip"],
            "details": f"{row['description']} ({row['user']}) с IP {row['source_ip']}",
        })

def is_suspicious_domain(domain):
    """Определяет, подозрителен ли домен по эвристикам"""
    # Пропускаем известные безопасные домены
    if domain in KNOWN_SAFE_DOMAINS:
        return False, None

    # Нет точки — не домен (NetBIOS/NBNS/локальное имя)
    if "." not in domain:
        return False, None

    # Подозрительный TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return True, f"подозрительный TLD ({tld})"

    # Высокая доля цифр в имени — признак DGA
    name_part = domain.split(".")[0]
    if len(name_part) > 5:
        digit_ratio = sum(c.isdigit() for c in name_part) / len(name_part)
        if digit_ratio > 0.3:
            return True, "возможный DGA (много цифр в имени)"

    # Очень длинное имя домена
    if len(domain) > 40:
        return True, "аномально длинное имя домена"

    return False, None

def analyze_dns(dns, threats):
    """Анализ DNS-логов"""
    for _, row in dns.iterrows():
        domain = row["query"]

        # Проверяем домен по эвристикам
        suspicious, reason = is_suspicious_domain(domain)
        if suspicious:
            threats.append({
                "source": "dns", "type": "Подозрительный DNS-запрос",
                "severity": "HIGH", "ip": row["src_ip"], "domain": domain,
                "details": f"Запрос к {domain} — {reason} ({row['count']} раз) с IP {row['src_ip']}",
            })

        # Аномальные запросы (длинные заглавные строки — возможный tunneling)
        if len(domain) > DNS_ANOMALY_LENGTH and domain.isupper():
            threats.append({
                "source": "dns", "type": "Аномальный DNS (tunneling)",
                "severity": "MEDIUM", "ip": row["src_ip"],
                "details": f"Аномальный DNS-запрос: {domain} с IP {row['src_ip']}",
            })

# Правила проверки URL: (название, серьёзность, маркеры, режим проверки)
# Режимы: "contains" — маркер содержится в URL, "endswith" — URL заканчивается на маркер
URL_RULES = [
    ("Path Traversal",              "CRITICAL", ["../"],                                              "contains"),
    ("SQL Injection",               "CRITICAL", ["' or", "union select", "1=1", "drop table", "--"], "contains"),
    ("XSS",                         "HIGH",     ["<script", "javascript:", "onerror=", "onload=", "alert("], "contains"),
    ("Command Injection",           "CRITICAL", ["cmd=", "exec=", ";ls", ";cat", "|whoami", "&&", ";id"],    "contains"),
    ("Доступ к чувствительным файлам", "HIGH",  ["/.env", "/config.json", "/debug.log", "/.git", "/wp-config.php"], "endswith"),
]


def analyze_http(http, threats):
    """Анализ HTTP-логов"""

    for _, row in http.iterrows():
        url_lower = row["url"].lower()

        # Проверка URL по таблице правил
        for rule_name, severity, markers, mode in URL_RULES:
            if mode == "contains" and any(m in url_lower for m in markers):
                matched = True
            elif mode == "endswith" and any(url_lower.endswith(m) for m in markers):
                matched = True
            else:
                matched = False

            if matched:
                threats.append({
                    "source": "http", "type": rule_name,
                    "severity": severity, "ip": row["src_ip"],
                    "details": f"{rule_name}: {row['url']} с IP {row['src_ip']}",
                })

def analyze_logs(frames):
    """Анализирует все логи и возвращает список угроз"""
    print("\n Анализ логов...")
    threats = []

    analyze_winevent(frames["winevent"], threats)
    analyze_dns(frames["dns"], threats)
    analyze_http(frames["http"], threats)

    print(f"  Найдено {len(threats)} потенциальных угроз")
    return threats

# ==========================
# ЭТАП 3. РЕАГИРОВАНИЕ
# ==========================

def respond_to_threats(threats, vt_ip_results, vt_domain_results):
    """Имитирует блокировку IP и выводит предупреждения"""
    print("\n" + "=" * 60)
    print(" РЕАГИРОВАНИЕ НА УГРОЗЫ")
    print("=" * 60)

    blocked_ips = set()
    actions = []

    # По результатам анализа логов
    for t in threats:
        ip = t.get("ip", "N/A")
        severity = t["severity"]

        if severity in ("CRITICAL", "HIGH") and ip not in blocked_ips:
            blocked_ips.add(ip)
            print(f"  [BLOCK] IP {ip} заблокирован — {t['type']}")
            actions.append({
                "action": "BLOCK_IP", "ip": ip,
                "reason": t["type"], "severity": severity,
            })

        if severity == "CRITICAL":
            print(f"  [ALERT] {t['details']}")
            actions.append({
                "action": "ALERT", "details": t["details"],
                "severity": "CRITICAL",
            })

    # По результатам VirusTotal
    for result in vt_ip_results:
        if result["malicious"] > 0:
            ip = result["ip"]
            if ip not in blocked_ips:
                blocked_ips.add(ip)
                print(f"  [BLOCK] IP {ip} — VirusTotal: {result['malicious']} malicious")
                actions.append({
                    "action": "BLOCK_IP", "ip": ip,
                    "reason": f"VirusTotal: {result['malicious']} detections",
                    "severity": "HIGH",
                })

    for result in vt_domain_results:
        if result["malicious"] > 0:
            domain = result["domain"]
            print(f"  [ALERT] Домен {domain} — вредоносный ({result['malicious']} движков)")
            actions.append({
                "action": "ALERT_DOMAIN", "domain": domain,
                "reason": f"VirusTotal: {result['malicious']} detections",
                "severity": "HIGH",
            })

    if not actions:
        print("  Угроз не обнаружено.")

    print(f"\n  Заблокировано IP: {len(blocked_ips)}")
    print(f"  Действий: {len(actions)}")
    print("=" * 60)

    return actions, list(blocked_ips)


# ==========================
# ЭТАП 4. ОТЧЁТ И ГРАФИК
# ==========================

def save_report(threats, vt_ip_results, vt_domain_results, actions):
    """Сохраняет отчёт в JSON и CSV"""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Формируем отчёт
    report = {
        "report_date": datetime.now().isoformat(),
        "summary": {
            "total_threats": len(threats),
            "critical": sum(1 for t in threats if t["severity"] == "CRITICAL"),
            "high": sum(1 for t in threats if t["severity"] == "HIGH"),
            "medium": sum(1 for t in threats if t["severity"] == "MEDIUM"),
            "actions_taken": len(actions),
        },
        "threats": threats,
        "virustotal_ip_results": vt_ip_results,
        "virustotal_domain_results": vt_domain_results,
        "response_actions": actions,
    }

    # JSON
    json_path = f"results/report_{ts}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    print(f"\n JSON-отчёт: {json_path}")

    # CSV
    csv_path = f"results/report_{ts}.csv"
    pd.DataFrame(threats).to_csv(csv_path, index=False, encoding="utf-8-sig")
    print(f" CSV-отчёт:  {csv_path}")

    return json_path, csv_path


def build_chart(threats):
    """Строит графики и сохраняет в PNG"""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    fig.suptitle("Результаты мониторинга угроз", fontsize=14, fontweight="bold")

    # --- 1. Угрозы по типам ---
    type_counts = Counter(t["type"] for t in threats)
    types = list(type_counts.keys())
    counts = list(type_counts.values())
    cmap = plt.colormaps["Reds"]
    colors = cmap([0.3 + 0.7 * i / max(len(types), 1) for i in range(len(types))])

    axes[0].barh(types, counts, color=colors)
    axes[0].set_xlabel("Количество")
    axes[0].set_title("Угрозы по типам")
    for i, v in enumerate(counts):
        axes[0].text(v + 0.1, i, str(v), va="center", fontweight="bold")

    # --- 2. Топ-5 IP по количеству угроз ---
    ip_counter = Counter(t.get("ip", "N/A") for t in threats)
    top_ips = ip_counter.most_common(5)
    ips = [x[0] for x in top_ips]
    ip_vals = [x[1] for x in top_ips]
    bar_colors = ["#e74c3c" if v >= 3 else "#f39c12" if v >= 2 else "#3498db" for v in ip_vals]

    axes[1].bar(ips, ip_vals, color=bar_colors)
    axes[1].set_ylabel("Количество угроз")
    axes[1].set_title("Топ-5 IP по угрозам")
    axes[1].tick_params(axis="x", rotation=25)
    for i, v in enumerate(ip_vals):
        axes[1].text(i, v + 0.1, str(v), ha="center", fontweight="bold")

    # --- 3. Распределение по серьёзности ---
    sev_counter = Counter(t["severity"] for t in threats)
    labels = list(sev_counter.keys())
    sizes = list(sev_counter.values())
    sev_colors = {"CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#f1c40f", "LOW": "#2ecc71"}
    pie_colors = [sev_colors.get(s, "#95a5a6") for s in labels]

    axes[2].pie(sizes, labels=labels, colors=pie_colors,
                autopct="%1.0f%%", startangle=90, textprops={"fontweight": "bold"})
    axes[2].set_title("Распределение по серьёзности")

    plt.tight_layout()
    chart_path = f"results/threats_chart_{ts}.png"
    fig.savefig(chart_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f" График:     {chart_path}")
    return chart_path


# ==========================
# ГЛАВНАЯ ЧАСТЬ
# ==========================

def clear_results():
    """Очищает папку results/ перед новым запуском"""
    results_dir = os.path.join(SCRIPT_DIR, "results")
    if os.path.exists(results_dir):
        shutil.rmtree(results_dir)
        print(" Папка results/ очищена")
    os.makedirs(results_dir, exist_ok=True)


if __name__ == "__main__":
    print("=" * 60)
    print(" АВТОМАТИЗИРОВАННЫЙ МОНИТОРИНГ И РЕАГИРОВАНИЕ НА УГРОЗЫ")
    print("=" * 60)

    # Очистка предыдущих результатов
    clear_results()

    # Этап 1: загрузка логов
    frames = load_logs()

    # Этап 2: анализ логов
    threats = analyze_logs(frames)

    # Собираем подозрительные IP и домены из результатов анализа
    suspicious_ips = set()
    suspicious_domains = set()
    for t in threats:
        ip = t.get("ip")
        if ip and not ip.startswith(("192.168.", "10.", "172.16.")):
            suspicious_ips.add(ip)
        domain = t.get("domain")
        if domain:
            suspicious_domains.add(domain)

    # Этап 1 (продолжение): проверка через VirusTotal
    vt_ip_results, vt_domain_results = collect_virustotal_data(
        suspicious_ips, suspicious_domains
    )

    # Вывод результатов VirusTotal
    if vt_ip_results or vt_domain_results:
        print("\n Результаты VirusTotal:")
        for r in vt_ip_results:
            status = "ВРЕДОНОСНЫЙ" if r["malicious"] > 0 else "чистый"
            print(f"  IP {r['ip']}: {status} (malicious={r['malicious']})")
        for r in vt_domain_results:
            status = "ВРЕДОНОСНЫЙ" if r["malicious"] > 0 else "чистый"
            print(f"  Домен {r['domain']}: {status} (malicious={r['malicious']})")

    # Этап 3: реагирование
    actions, blocked = respond_to_threats(threats, vt_ip_results, vt_domain_results)

    # Этап 4: отчёт и визуализация
    json_path, csv_path = save_report(threats, vt_ip_results, vt_domain_results, actions)
    chart_path = build_chart(threats)

    # Итого
    print("\n" + "=" * 60)
    print(" ИТОГО")
    print("=" * 60)
    print(f"  Источников данных: 2 (логи + VirusTotal API)")
    print(f"  Обнаружено угроз:  {len(threats)}")
    print(f"  Заблокировано IP:  {len(blocked)}")
    print(f"  Действий:          {len(actions)}")
    print("=" * 60)
