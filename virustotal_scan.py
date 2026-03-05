"""
VirusTotal API Scanner
======================

Скрипт для взаимодействия с API VirusTotal v3.
Позволяет проверять URL-адреса, домены, IP-адреса и хеши файлов
на наличие угроз через базу данных VirusTotal.

Как запустить:
--------------
1. Зарегистрируйтесь на https://www.virustotal.com и получите бесплатный API-ключ.
2. Откройте файл .env и вставьте ваш ключ:
       VIRUSTOTAL_API_KEY=ваш_ключ_здесь
3. Установите зависимости:
       pip install requests python-dotenv
4. Запустите скрипт:
       python virustotal_scan.py

Переменные окружения (файл .env):
----------------------------------
   VIRUSTOTAL_API_KEY  — API-ключ от сервиса VirusTotal (обязательно).

Что делает скрипт:
------------------
   - Загружает API-ключ из файла .env
   - Отправляет URL на сканирование (POST /urls)
   - Получает результат анализа (GET /analyses/{id})
   - Выводит результаты в читаемом виде и сохраняет полный JSON в файл
"""

import json
import os
import sys
import time

import requests
from dotenv import load_dotenv

# Загружаем переменные окружения из файла .env
load_dotenv()

# API-ключ VirusTotal берётся из переменной окружения VIRUSTOTAL_API_KEY
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"

# Заголовок авторизации — передаётся в каждом запросе
HEADERS = {
    "x-apikey": API_KEY,
    "Accept": "application/json",
}


def check_api_key():
    """Проверяет, что API-ключ задан."""
    if not API_KEY or API_KEY == "your_api_key_here":
        print("[ERROR] API-ключ не задан.")
        print("Откройте файл .env и укажите ваш ключ: VIRUSTOTAL_API_KEY=<ключ>")
        sys.exit(1)


def submit_url(url: str) -> str:
    """
    Отправляет URL на сканирование в VirusTotal.
    Возвращает ID анализа для последующего получения результата.
    """
    endpoint = f"{BASE_URL}/urls"
    # VirusTotal принимает URL в теле запроса в формате form-data
    data = {"url": url}

    print(f"[*] Отправка URL на сканирование: {url}")
    response = requests.post(endpoint, headers=HEADERS, data=data)
    response.raise_for_status()

    result = response.json()
    analysis_id = result["data"]["id"]
    print(f"[+] URL принят. ID анализа: {analysis_id}")
    return analysis_id


def get_analysis(analysis_id: str) -> dict:
    """
    Получает результат анализа по его ID.
    Ждёт завершения сканирования (статус 'completed').
    """
    endpoint = f"{BASE_URL}/analyses/{analysis_id}"

    print("[*] Ожидание результатов сканирования...")
    for attempt in range(10):
        response = requests.get(endpoint, headers=HEADERS)
        response.raise_for_status()

        result = response.json()
        status = result["data"]["attributes"]["status"]

        if status == "completed":
            print("[+] Сканирование завершено.")
            return result

        print(f"    [{attempt + 1}/10] Статус: {status}. Повтор через 5 секунд...")
        time.sleep(5)

    print("[!] Превышено время ожидания. Возвращаем последний ответ.")
    return result


def print_summary(analysis: dict):
    """Выводит сводку результатов сканирования в консоль."""
    attrs = analysis["data"]["attributes"]
    stats = attrs.get("stats", {})
    meta = analysis.get("meta", {})

    print("\n" + "=" * 50)
    print("РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ")
    print("=" * 50)

    # Информация о проверяемом объекте
    url_info = meta.get("url_info", {})
    if url_info:
        print(f"URL:          {url_info.get('url', 'N/A')}")

    print(f"Статус:       {attrs.get('status', 'N/A')}")

    # Статистика детектирования
    print("\nСтатистика антивирусных движков:")
    print(f"  Вредоносных:    {stats.get('malicious', 0)}")
    print(f"  Подозрительных: {stats.get('suspicious', 0)}")
    print(f"  Безопасных:     {stats.get('undetected', 0)}")
    print(f"  Не определили:  {stats.get('harmless', 0)}")
    print(f"  Ошибок:         {stats.get('failure', 0)}")

    # Детектирование по движкам (только те, кто нашёл угрозу)
    results = attrs.get("results", {})
    detections = {
        engine: info
        for engine, info in results.items()
        if info.get("category") in ("malicious", "suspicious")
    }

    if detections:
        print(f"\nОбнаружено {len(detections)} движками:")
        for engine, info in list(detections.items())[:10]:
            print(f"  - {engine}: {info.get('result', 'N/A')} ({info.get('category')})")
        if len(detections) > 10:
            print(f"  ... и ещё {len(detections) - 10} движков")
    else:
        print("\nНи один антивирусный движок угрозы не обнаружил.")

    print("=" * 50)


def save_json(data: dict, filename: str):
    """Сохраняет JSON-ответ в файл."""
    os.makedirs("results", exist_ok=True)
    filepath = os.path.join("results", filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"[+] Полный JSON-ответ сохранён в: {filepath}")


def scan_url(url: str):
    """Полный цикл проверки URL через VirusTotal API."""
    # Шаг 1: авторизация и отправка URL на сканирование
    analysis_id = submit_url(url)

    # Шаг 2: получение результатов анализа (с ожиданием завершения)
    analysis = get_analysis(analysis_id)

    # Шаг 3: вывод сводки результатов в консоль
    print_summary(analysis)

    # Шаг 4: сохранение полного JSON-ответа в файл
    safe_name = url.replace("://", "_").replace("/", "_").replace(".", "_")[:50]
    save_json(analysis, f"scan_{safe_name}.json")


def get_url_report(url: str):
    """
    Получает отчёт по уже известному URL без повторного сканирования.
    Использует GET /urls/{id}, где id — base64url-кодировка URL.
    """
    import base64

    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    endpoint = f"{BASE_URL}/urls/{url_id}"

    print(f"[*] Запрос отчёта для URL: {url}")
    response = requests.get(endpoint, headers=HEADERS)

    if response.status_code == 404:
        print("[!] URL не найден в базе VirusTotal. Запустите scan_url() для сканирования.")
        return

    response.raise_for_status()
    report = response.json()

    # Выводим полный JSON-ответ в консоль
    print("\nJSON-ответ от VirusTotal:")
    print(json.dumps(report, indent=2, ensure_ascii=False))

    save_json(report, "url_report.json")
    return report


if __name__ == "__main__":
    check_api_key()

    # URL для проверки — замените на любой адрес, который хотите проверить
    target_url = "http://testphp.vulnweb.com/"

    print(f"\nVirusTotal Scanner")
    print(f"Цель: {target_url}\n")

    # Полное сканирование URL: отправка + ожидание + вывод результатов
    scan_url(target_url)
