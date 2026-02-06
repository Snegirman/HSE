#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скрипт для анализа событий информационной безопасности.
Загружает данные из JSON файла и анализирует распределение событий по типам.
"""

import json
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 6)
plt.rcParams['font.size'] = 10
plt.rcParams['font.family'] = ['DejaVu Sans', 'Arial', 'sans-serif']


def load_json_to_dataframe(json_file_path):
    """
    Загружает данные из JSON файла в датафрейм Pandas.
        
    Returns:
        pd.DataFrame: Датафрейм с данными о событиях
    """
    with open(json_file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    df = pd.DataFrame(data['events'])
    
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    return df


def analyze_signature_distribution(df, verbose=True):
    """
    Анализирует распределение событий по типам (signature).
    
    Args:
        df (pd.DataFrame): Датафрейм с событиями
        verbose (bool): Если True, выводит подробную информацию
    """
    total_events = len(df)
    
    signature_counts = df['signature'].value_counts()
    
    category_counts = df['signature'].str.split(n=1, expand=True)[0].value_counts()
    
    if verbose:
        print("=" * 80)
        print("АНАЛИЗ РАСПРЕДЕЛЕНИЯ СОБЫТИЙ ИНФОРМАЦИОННОЙ БЕЗОПАСНОСТИ")
        print("=" * 80)
        print()
        
        # Общая статистика
        print(f"Общее количество событий: {total_events}")
        print(f"Уникальных типов событий (signature): {df['signature'].nunique()}")
        print()
        
        print("-" * 80)
        print("РАСПРЕДЕЛЕНИЕ СОБЫТИЙ ПО ТИПАМ (SIGNATURE):")
        print("-" * 80)
        print()
        
        output_lines = []
        for signature, count in signature_counts.items():
            percentage = (count / total_events) * 100
            output_lines.append(f"{signature}:")
            output_lines.append(f"  Количество: {count}")
            output_lines.append(f"  Процент от общего числа: {percentage:.2f}%")
            output_lines.append("")
        
        print("\n".join(output_lines))
        
        print("-" * 80)
        print("РАСПРЕДЕЛЕНИЕ ПО КАТЕГОРИЯМ:")
        print("-" * 80)
        print()
        
        category_output = []
        for category, count in category_counts.items():
            percentage = (count / total_events) * 100
            category_output.append(f"{category}: {count} событий ({percentage:.2f}%)")
        
        print("\n".join(category_output))
        print()
    
    return signature_counts, category_counts


def visualize_distribution(signature_counts, category_counts, save_plots=True):
    """
    Создает графики распределения событий информационной безопасности.
    
    Args:
        signature_counts (pd.Series): Распределение по типам событий (signature)
        category_counts (pd.Series): Распределение по категориям
        save_plots (bool): Если True, сохраняет графики в файлы
    """
    fig, axes = plt.subplots(2, 1, figsize=(14, 12))
    
    ax1 = axes[0]
    signature_counts_plot = signature_counts.head(20)  # Показываем топ-20 для читаемости
    
    sns.barplot(x=signature_counts_plot.values, 
                y=signature_counts_plot.index, 
                palette="viridis", 
                ax=ax1)
    
    ax1.set_xlabel('Количество событий', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Тип события (signature)', fontsize=12, fontweight='bold')
    ax1.set_title('Распределение событий информационной безопасности по типам (signature)', 
                  fontsize=14, fontweight='bold', pad=20)
    ax1.grid(axis='x', alpha=0.3)
    
    for i, v in enumerate(signature_counts_plot.values):
        ax1.text(v + 0.5, i, str(v), va='center', fontsize=9)
    
    # График 2: Распределение по категориям
    ax2 = axes[1]
    sns.barplot(x=category_counts.index, 
                y=category_counts.values, 
                palette="mako", 
                ax=ax2)
    
    ax2.set_xlabel('Категория события', fontsize=12, fontweight='bold')
    ax2.set_ylabel('Количество событий', fontsize=12, fontweight='bold')
    ax2.set_title('Распределение событий по категориям (первое слово в signature)', 
                  fontsize=14, fontweight='bold', pad=20)
    ax2.grid(axis='y', alpha=0.3)
    
    ax2.tick_params(axis='x', rotation=45)
    
    for i, v in enumerate(category_counts.values):
        ax2.text(i, v + 0.5, str(v), ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    plt.tight_layout()
    
    if save_plots:
        plt.savefig('security_events_distribution.png', dpi=300, bbox_inches='tight')
        print("График сохранен в файл: security_events_distribution.png")
    
    plt.close(fig)
    
    fig2, ax3 = plt.subplots(figsize=(10, 8))
    
    colors = sns.color_palette("pastel", len(category_counts))
    wedges, texts, autotexts = ax3.pie(category_counts.values, 
                                        labels=category_counts.index,
                                        autopct='%1.1f%%',
                                        colors=colors,
                                        startangle=90,
                                        textprops={'fontsize': 11, 'fontweight': 'bold'})
    
    ax3.set_title('Распределение событий по категориям (круговая диаграмма)', 
                  fontsize=14, fontweight='bold', pad=20)
    
    for autotext in autotexts:
        autotext.set_color('black')
        autotext.set_fontsize(10)
    
    plt.tight_layout()
    
    if save_plots:
        plt.savefig('security_events_pie_chart.png', dpi=300, bbox_inches='tight')
        print("Круговая диаграмма сохранена в файл: security_events_pie_chart.png")
    
    plt.close(fig2)


def main():    
    json_file = "events (1).json"
    
    try:
        print(f"Загрузка данных из файла: {json_file}")
        df = load_json_to_dataframe(json_file)
        print(f"Данные успешно загружены. Записей: {len(df)}")
        print()
        
        signature_counts, category_counts = analyze_signature_distribution(df)
        
        print("-" * 80)
        print("Создание графиков распределения...")
        print("-" * 80)
        visualize_distribution(signature_counts, category_counts)
        
        signature_counts.to_csv('signature_distribution.csv', header=['count'])
        print("Результаты сохранены в файл: signature_distribution.csv")
        
    except FileNotFoundError:
        print(f"Ошибка: Файл '{json_file}' не найден!")
    except json.JSONDecodeError:
        print(f"Ошибка: Не удалось распарсить JSON файл '{json_file}'!")
    except Exception as e:
        print(f"Произошла ошибка: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
