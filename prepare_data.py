import re
import textwrap
import pandas as pd
import json
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import seaborn as sns


def load_and_prepare_data(file_path):
    print(f"Загрузка данных из {file_path}...")

    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    records = [item['result'] for item in data if 'result' in item]
    df = pd.DataFrame(records)

    print(f"Всего записей загружено: {len(df)}")

    winevent_df = df[df['sourcetype'].str.contains('WinEventLog', na=False, case=False)].copy()
    dns_df = df[df['sourcetype'].str.contains('dns', na=False, case=False)].copy()

    print(f"Записей WinEventLog: {len(winevent_df)}")
    print(f"Записей DNS: {len(dns_df)}")

    return winevent_df, dns_df


def normalize_winevent(df):
    if df.empty:
        return df

    print("\nНормализация WinEventLog...")

    # Приведение временной метки (убираем нераспознанные аббревиатуры TZ вроде MDT)
    if '_time' in df.columns:
        cleaned = df['_time'].str.replace(r'\s+[A-Z]{2,4}$', '', regex=True)
        df['_time'] = pd.to_datetime(cleaned, errors='coerce')

    # Числовые поля
    for col in ['EventCode', 'date_hour', 'date_mday', 'date_minute',
                'date_month', 'date_second', 'date_year']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')

    # Заполнение пропусков в ключевых полях
    str_defaults = {
        'Account_Name': 'UNKNOWN',
        'ComputerName': 'UNKNOWN',
        'Security_ID': 'UNKNOWN',
        'New_Process_Name': '',
        'Process_Command_Line': '',
    }
    for col, default in str_defaults.items():
        if col in df.columns:
            df[col] = df[col].fillna(default).replace('', default if default else '')

    # Нормализация строковых полей: убираем лишние пробелы
    str_cols = df.select_dtypes(include='object').columns
    for col in str_cols:
        df[col] = df[col].apply(
            lambda x: x.strip() if isinstance(x, str) else x
        )

    # Удаление дубликатов (списки → кортежи, т.к. pandas не хеширует списки)
    for col in df.columns:
        if df[col].apply(lambda x: isinstance(x, list)).any():
            df[col] = df[col].apply(lambda x: tuple(x) if isinstance(x, list) else x)

    before = len(df)
    df = df.drop_duplicates()
    removed = before - len(df)
    if removed:
        print(f"  Удалено дубликатов: {removed}")

    df = df.reset_index(drop=True)
    print(f"  Итоговых записей: {len(df)}")
    return df


def normalize_dns(df):
    if df.empty:
        print("\nDNS записей нет — нормализация пропущена.")
        return df

    print("\nНормализация DNS...")

    if '_time' in df.columns:
        df['_time'] = pd.to_datetime(df['_time'], errors='coerce')

    str_defaults = {
        'query': 'UNKNOWN',
        'answer': 'UNKNOWN',
        'src_ip': 'UNKNOWN',
    }
    for col, default in str_defaults.items():
        if col in df.columns:
            df[col] = df[col].fillna(default)

    for col in df.columns:
        if df[col].apply(lambda x: isinstance(x, list)).any():
            df[col] = df[col].apply(lambda x: tuple(x) if isinstance(x, list) else x)

    before = len(df)
    df = df.drop_duplicates()
    removed = before - len(df)
    if removed:
        print(f"  Удалено дубликатов: {removed}")

    df = df.reset_index(drop=True)
    print(f"  Итоговых записей: {len(df)}")
    return df


# ---------------------------------------------------------------------------
# Коды событий Windows и их описания (Security Event Log)
# ---------------------------------------------------------------------------
EVENTCODE_DESCRIPTIONS = {
    4624: 'Успешный вход в систему',
    4625: 'Неудачная попытка входа',
    4634: 'Завершение сеанса',
    4648: 'Вход с явными учётными данными (Pass-the-Hash/Ticket)',
    4656: 'Запрос дескриптора объекта',
    4688: 'Создание нового процесса',
    4689: 'Завершение процесса',
    4697: 'Установка службы',
    4698: 'Создание запланированной задачи',
    4702: 'Изменение запланированной задачи',
    4703: 'Изменение прав маркера (эскалация привилегий)',
    4720: 'Создание учётной записи пользователя',
    4722: 'Включение учётной записи пользователя',
    4724: 'Попытка сброса пароля',
    4732: 'Добавление в привилегированную группу',
    4768: 'Запрос TGT Kerberos',
    4769: 'Запрос сервисного билета Kerberos',
    4771: 'Ошибка предварительной аутентификации Kerberos',
    4776: 'Проверка учётных данных NTLM',
}

# Логонные типы Windows
LOGON_TYPE_NAMES = {
    '2': 'Интерактивный',
    '3': 'Сетевой',
    '4': 'Пакетный',
    '5': 'Сервис',
    '7': 'Разблокировка',
    '8': 'Сетевой в открытом виде',
    '9': 'Новые учётные данные',
    '10': 'Удалённый интерактивный (RDP)',
    '11': 'Кэшированный интерактивный',
}

# Исполняемые файлы, часто используемые при атаках (LOLBins + RAT-инструменты)
SUSPICIOUS_PROC_PATTERNS = re.compile(
    r'(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|'
    r'certutil|msiexec|psexec|wmic|bitsadmin|net\.exe|net1\.exe|sc\.exe|'
    r'at\.exe|schtasks|reg\.exe|regasm|regsvcs|installutil|'
    r'mimikatz|procdump|dump|nmap|nc\.exe|netcat)',
    re.IGNORECASE,
)


def _str_val(val):
    """Приводит список или значение к строке для вывода."""
    if isinstance(val, (list, tuple)):
        return ', '.join(str(v) for v in val)
    return str(val) if pd.notna(val) else ''


def analyze_winevent_suspicious(df):
    """
    Анализирует WinEventLog на подозрительные события.

    Проверки:
    1. Неудачные входы (4625) — возможный брутфорс.
    2. Сетевые / RDP-входы (4624, Logon_Type 3 или 10) — латеральное перемещение.
    3. Вход с явными учётными данными (4648).
    4. Создание процесса с полными привилегиями (4688 + TokenElevationTypeFull).
    5. Создание процесса с подозрительным именем / командной строкой (LOLBins).
    6. Изменение прав маркера (4703) — эскалация привилегий.
    7. Установка служб / задач (4697, 4698, 4702) — закрепление.
    8. Манипуляции с учётными записями (4720, 4722, 4724, 4732).
    9. Доступ к объектам не-системными пользователями (4656).
    """
    if df.empty:
        print("\n[WinEvent] Нет данных для анализа.")
        return []

    print("\n" + "=" * 60)
    print("АНАЛИЗ WINEVENTLOG — ПОДОЗРИТЕЛЬНЫЕ СОБЫТИЯ")
    print("=" * 60)

    ec_col = 'EventCode'
    if ec_col not in df.columns:
        print("  Поле EventCode отсутствует.")
        return []

    ec = pd.to_numeric(df[ec_col], errors='coerce')
    findings = []

    def _get(row, col):
        return _str_val(row[col]) if col in df.columns else ''

    # --- 1. Неудачные входы ---
    mask = ec == 4625
    if mask.any():
        sub = df[mask]
        findings.append({
            'категория': 'Брутфорс / неудачные входы',
            'код': 4625,
            'кол-во': len(sub),
            'детали': sub.apply(
                lambda r: f"{_get(r,'Account_Name')} @ {_get(r,'ComputerName')} "
                          f"(тип: {_get(r,'Logon_Type')}, IP: {_get(r,'Source_Network_Address')})",
                axis=1,
            ).tolist(),
        })

    # --- 2. Сетевые и RDP-входы ---
    mask = (ec == 4624) & df.get('Logon_Type', pd.Series(dtype=str)).astype(str).isin(['3', '10'])
    if 'Logon_Type' in df.columns:
        lt = df['Logon_Type'].astype(str)
        mask = (ec == 4624) & lt.isin(['3', '10'])
        if mask.any():
            sub = df[mask]
            findings.append({
                'категория': 'Сетевой / RDP-вход (латеральное перемещение)',
                'код': 4624,
                'кол-во': len(sub),
                'детали': sub.apply(
                    lambda r: f"{_get(r,'Account_Name')} → {_get(r,'ComputerName')} "
                              f"(тип: {LOGON_TYPE_NAMES.get(_get(r,'Logon_Type'), _get(r,'Logon_Type'))}, "
                              f"IP: {_get(r,'Source_Network_Address')})",
                    axis=1,
                ).tolist(),
            })

    # --- 3. Вход с явными учётными данными ---
    mask = ec == 4648
    if mask.any():
        sub = df[mask]
        findings.append({
            'категория': 'Явные учётные данные (Pass-the-Hash/Ticket)',
            'код': 4648,
            'кол-во': len(sub),
            'детали': sub.apply(
                lambda r: f"{_get(r,'Account_Name')} → {_get(r,'ComputerName')}",
                axis=1,
            ).tolist(),
        })

    # --- 4. Процесс с полными привилегиями ---
    if 'Token_Elevation_Type' in df.columns:
        elev_mask = (ec == 4688) & df['Token_Elevation_Type'].astype(str).str.contains(
            r'%%1936|TokenElevationTypeFull|Full', na=False
        )
        if elev_mask.any():
            sub = df[elev_mask]
            findings.append({
                'категория': 'Процесс запущен с полными привилегиями (эскалация)',
                'код': 4688,
                'кол-во': len(sub),
                'детали': sub.apply(
                    lambda r: f"{_get(r,'Account_Name')} → {_get(r,'New_Process_Name')} "
                              f"[{_get(r,'Token_Elevation_Type')}]",
                    axis=1,
                ).tolist(),
            })

    # --- 5. LOLBins / подозрительные процессы ---
    if 'New_Process_Name' in df.columns or 'Process_Command_Line' in df.columns:
        proc_mask = ec == 4688
        if proc_mask.any():
            sub = df[proc_mask].copy()
            name_col = sub.get('New_Process_Name', pd.Series('', index=sub.index)).astype(str)
            cmd_col = sub.get('Process_Command_Line', pd.Series('', index=sub.index)).astype(str)
            combined = name_col + ' ' + cmd_col
            susp = sub[combined.apply(lambda x: bool(SUSPICIOUS_PROC_PATTERNS.search(x)))]
            if not susp.empty:
                findings.append({
                    'категория': 'Подозрительный процесс (LOLBin / инструмент атаки)',
                    'код': 4688,
                    'кол-во': len(susp),
                    'детали': susp.apply(
                        lambda r: f"{_get(r,'Account_Name')} → {_get(r,'New_Process_Name')} "
                                  f"cmd: {_get(r,'Process_Command_Line')[:80]}",
                        axis=1,
                    ).tolist(),
                })

    # --- 6. Изменение прав маркера ---
    mask = ec == 4703
    if mask.any():
        sub = df[mask]
        findings.append({
            'категория': 'Изменение прав маркера (эскалация привилегий)',
            'код': 4703,
            'кол-во': len(sub),
            'детали': sub.apply(
                lambda r: f"{_get(r,'Account_Name')} @ {_get(r,'ComputerName')}",
                axis=1,
            ).tolist(),
        })

    # --- 7. Закрепление: службы / задачи ---
    for code, label in [(4697, 'Установка службы'), (4698, 'Создание задачи'), (4702, 'Изменение задачи')]:
        mask = ec == code
        if mask.any():
            sub = df[mask]
            findings.append({
                'категория': label,
                'код': code,
                'кол-во': len(sub),
                'детали': sub.apply(
                    lambda r: f"{_get(r,'Account_Name')} @ {_get(r,'ComputerName')}",
                    axis=1,
                ).tolist(),
            })

    # --- 8. Манипуляции с учётными записями ---
    acct_codes = {4720: 'Создание УЗ', 4722: 'Включение УЗ', 4724: 'Сброс пароля', 4732: 'Добавление в группу'}
    for code, label in acct_codes.items():
        mask = ec == code
        if mask.any():
            sub = df[mask]
            findings.append({
                'категория': label,
                'код': code,
                'кол-во': len(sub),
                'детали': sub.apply(
                    lambda r: f"{_get(r,'Account_Name')} @ {_get(r,'ComputerName')}",
                    axis=1,
                ).tolist(),
            })

    # --- 9. Доступ к объектам не-системными пользователями ---
    if 'Security_ID' in df.columns:
        mask = (ec == 4656) & ~df['Security_ID'].astype(str).str.contains(
            r'SYSTEM|NETWORK SERVICE|LOCAL SERVICE|NULL SID', na=False
        )
        if mask.any():
            sub = df[mask]
            findings.append({
                'категория': 'Несанкционированный доступ к объекту',
                'код': 4656,
                'кол-во': len(sub),
                'детали': sub.apply(
                    lambda r: f"{_get(r,'Account_Name')} → {_get(r,'Object_Name') if 'Object_Name' in df.columns else '?'} "
                              f"@ {_get(r,'ComputerName')}",
                    axis=1,
                ).tolist(),
            })

    # --- Вывод ---
    if not findings:
        print("  Подозрительных событий не обнаружено.")
        return []

    for f in findings:
        desc = EVENTCODE_DESCRIPTIONS.get(f['код'], '')
        print(f"\n[!] {f['категория']} (EventCode {f['код']}: {desc})")
        print(f"    Найдено событий: {f['кол-во']}")
        for line in f['детали'][:5]:
            print(f"    • {line}")
        if len(f['детали']) > 5:
            print(f"    ... и ещё {len(f['детали']) - 5}")

    print(f"\n  Итого категорий с находками: {len(findings)}")
    return findings


def analyze_dns_suspicious(df):
    """
    Анализирует DNS-логи на подозрительную активность.

    Проверки:
    1. Редкие домены — к которым обратились <= 2 раз (возможен C2).
    2. Длинные поддомены (>= 50 символов) — DNS-туннелирование / DGA.
    3. Высокое число уникальных поддоменов у одного base-домена (DGA).
    4. Нестандартные TLD (не из списка распространённых).
    5. Домены со случайным видом (высокая доля согласных / цифр) — DGA.
    """
    if df.empty:
        print("\n[DNS] Нет данных для анализа.")
        return []

    if 'query' not in df.columns or df['query'].dropna().empty:
        print("\n[DNS] Поле query отсутствует или пусто — анализ невозможен.")
        return []

    print("\n" + "=" * 60)
    print("АНАЛИЗ DNS — ПОДОЗРИТЕЛЬНЫЕ ЗАПРОСЫ")
    print("=" * 60)

    COMMON_TLDS = {
        'com', 'net', 'org', 'edu', 'gov', 'mil', 'int',
        'io', 'co', 'uk', 'de', 'ru', 'fr', 'jp', 'cn',
        'au', 'ca', 'us', 'info', 'biz', 'name',
    }

    queries = df['query'].dropna().astype(str)
    # Убираем конечные точки (FQDN)
    queries = queries.str.rstrip('.')
    src_col = df['src_ip'] if 'src_ip' in df.columns else pd.Series(['?'] * len(df), index=df.index)

    def base_domain(q):
        parts = q.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return q

    def tld(q):
        parts = q.split('.')
        return parts[-1].lower() if parts else ''

    def dga_score(q):
        """Эвристика: доля согласных + цифр в самом длинном лейбле."""
        label = max(q.split('.'), key=len) if '.' in q else q
        if not label:
            return 0.0
        consonants = sum(1 for c in label.lower() if c in 'bcdfghjklmnpqrstvwxyz')
        digits = sum(1 for c in label if c.isdigit())
        return (consonants + digits) / len(label)

    df_work = df.copy()
    df_work['_query'] = queries
    df_work['_base'] = queries.apply(base_domain)
    df_work['_tld'] = queries.apply(tld)
    df_work['_src'] = src_col.values

    findings = []

    # --- 1. Редкие домены ---
    freq = df_work['_base'].value_counts()
    rare = freq[freq <= 2].index
    rare_rows = df_work[df_work['_base'].isin(rare)]
    if not rare_rows.empty:
        findings.append({
            'категория': 'Редкие домены (<=2 запросов) — возможный C2/Beacon',
            'детали': rare_rows[['_query', '_src']].drop_duplicates()
                        .apply(lambda r: f"{r['_query']}  (src: {r['_src']})", axis=1)
                        .tolist(),
        })

    # --- 2. Длинные поддомены (DNS-туннелирование) ---
    long_mask = df_work['_query'].str.len() >= 50
    if long_mask.any():
        sub = df_work[long_mask]
        findings.append({
            'категория': 'Длинные запросы (>=50 символов) — DNS-туннелирование',
            'детали': sub[['_query', '_src']].drop_duplicates()
                        .apply(lambda r: f"{r['_query']}  (src: {r['_src']})", axis=1)
                        .tolist(),
        })

    # --- 3. Много уникальных поддоменов у одного домена ---
    subdomain_counts = (
        df_work.groupby('_base')['_query']
        .nunique()
        .sort_values(ascending=False)
    )
    high_sub = subdomain_counts[subdomain_counts >= 5]
    if not high_sub.empty:
        findings.append({
            'категория': 'Высокое число уникальных поддоменов (>=5) — DGA / туннелирование',
            'детали': [f"{dom}: {cnt} уникальных поддоменов"
                       for dom, cnt in high_sub.items()],
        })

    # --- 4. Нестандартные TLD ---
    nonstandard = df_work[~df_work['_tld'].isin(COMMON_TLDS) & (df_work['_tld'] != '')]
    if not nonstandard.empty:
        findings.append({
            'категория': 'Нестандартный TLD — нетипичная зона',
            'детали': nonstandard[['_query', '_tld', '_src']].drop_duplicates()
                        .apply(lambda r: f"{r['_query']}  (TLD: .{r['_tld']}, src: {r['_src']})", axis=1)
                        .tolist(),
        })

    # --- 5. DGA-паттерн (высокая доля согласных/цифр) ---
    df_work['_dga'] = df_work['_query'].apply(dga_score)
    dga_rows = df_work[df_work['_dga'] >= 0.75]
    if not dga_rows.empty:
        findings.append({
            'категория': 'Случайно выглядящие домены (DGA-эвристика, score>=0.75)',
            'детали': dga_rows[['_query', '_dga', '_src']].drop_duplicates()
                        .apply(lambda r: f"{r['_query']}  (score={r['_dga']:.2f}, src: {r['_src']})", axis=1)
                        .tolist(),
        })

    # --- Вывод ---
    if not findings:
        print("  Подозрительных DNS-запросов не обнаружено.")
        return []

    for f in findings:
        print(f"\n[!] {f['категория']}")
        print(f"    Найдено: {len(f['детали'])}")
        for line in f['детали'][:5]:
            print(f"    • {line}")
        if len(f['детали']) > 5:
            print(f"    ... и ещё {len(f['детали']) - 5}")

    return findings


def _wrap_label(text, width=36):
    """Переносит длинный лейбл на несколько строк для оси Y."""
    return '\n'.join(textwrap.wrap(text, width))


def plot_suspicious_events(winevent_findings, dns_findings,
                           output_file='suspicious_events.png'):
    """
    Строит объединённую визуализацию топ-10 подозрительных событий:
    - левый график: WinEventLog (горизонтальные бары по числу событий)
    - правый график: DNS-логи (горизонтальные бары по числу записей)
    Сохраняет PNG и показывает окно.
    """
    sns.set_theme(style='whitegrid')
    fig, (ax_we, ax_dns) = plt.subplots(1, 2, figsize=(18, 7))
    fig.suptitle(
        'Топ-10 подозрительных событий — BOSS of the SOC v1',
        fontsize=14, fontweight='bold',
    )

    # ── WinEventLog ───────────────────────────────────────────────
    if winevent_findings:
        top = sorted(winevent_findings, key=lambda x: x['кол-во'], reverse=True)[:10]
        # Выводим снизу вверх (наибольшее — вверху)
        labels  = [_wrap_label(f['категория']) for f in reversed(top)]
        counts  = [f['кол-во']                 for f in reversed(top)]
        codes   = [str(f.get('код', ''))        for f in reversed(top)]

        palette = sns.color_palette('Reds_r', len(counts))
        bars = ax_we.barh(labels, counts, color=palette, edgecolor='white', linewidth=0.6)

        # Подписи: число событий + EventCode
        x_max = max(counts)
        for bar, cnt, code in zip(bars, counts, codes):
            ax_we.text(
                bar.get_width() + x_max * 0.02,
                bar.get_y() + bar.get_height() / 2,
                f'{cnt}  EC {code}',
                va='center', ha='left', fontsize=8.5,
            )

        ax_we.set_title('WinEventLog — подозрительные события', fontsize=11)
        ax_we.set_xlabel('Количество событий')
        ax_we.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))
        ax_we.margins(x=0.28)
        ax_we.tick_params(axis='y', labelsize=8)
    else:
        ax_we.text(0.5, 0.5, 'Нет данных', ha='center', va='center',
                   fontsize=13, color='gray', transform=ax_we.transAxes)
        ax_we.set_title('WinEventLog — подозрительные события', fontsize=11)
        ax_we.axis('off')

    # ── DNS ───────────────────────────────────────────────────────
    if dns_findings:
        top = sorted(dns_findings, key=lambda x: len(x['детали']), reverse=True)[:10]
        labels = [_wrap_label(f['категория']) for f in reversed(top)]
        counts = [len(f['детали'])             for f in reversed(top)]

        palette = sns.color_palette('Blues_r', len(counts))
        bars = ax_dns.barh(labels, counts, color=palette, edgecolor='white', linewidth=0.6)

        x_max = max(counts)
        for bar, cnt in zip(bars, counts):
            ax_dns.text(
                bar.get_width() + x_max * 0.02,
                bar.get_y() + bar.get_height() / 2,
                str(cnt),
                va='center', ha='left', fontsize=8.5,
            )

        ax_dns.set_title('DNS — подозрительные запросы', fontsize=11)
        ax_dns.set_xlabel('Количество записей')
        ax_dns.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))
        ax_dns.margins(x=0.2)
        ax_dns.tick_params(axis='y', labelsize=8)
    else:
        ax_dns.text(0.5, 0.5, 'Нет DNS-данных\nв текущем экспорте',
                    ha='center', va='center', fontsize=13, color='gray',
                    transform=ax_dns.transAxes)
        ax_dns.set_title('DNS — подозрительные запросы', fontsize=11)
        ax_dns.axis('off')

    plt.tight_layout()
    plt.savefig(output_file, dpi=150, bbox_inches='tight')
    print(f"\nГрафик сохранён: {output_file}")

if __name__ == "__main__":
    file_path = 'botsv1.json'

    winevent_df, dns_df = load_and_prepare_data(file_path)

    winevent_df = normalize_winevent(winevent_df)
    dns_df = normalize_dns(dns_df)

    print("\n--- Пример данных WinEventLog ---")
    cols = [c for c in ['_time', 'EventCode', 'Account_Name', 'ComputerName', 'New_Process_Name'] if c in winevent_df.columns]
    print(winevent_df[cols].head() if not winevent_df.empty else "Пусто")

    print("\n--- Пример данных DNS ---")
    dns_cols = [c for c in ['_time', 'query', 'answer', 'src_ip'] if c in dns_df.columns]
    print(dns_df[dns_cols].head() if not dns_df.empty else "Пусто")

    we_findings  = analyze_winevent_suspicious(winevent_df)
    dns_findings = analyze_dns_suspicious(dns_df)

    plot_suspicious_events(we_findings, dns_findings)
