#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Скрипт для перехвата сетевого трафика и сохранения в файл
Использует Scapy для перехвата трафика
"""

import sys
from scapy.all import *
from scapy.sendrecv import sniff
from scapy.utils import wrpcap
import argparse


def sniff_traffic(interface=None, filter_str="tcp port 80", count=0, output_file=None):
    """Перехват трафика и сохранение в файл"""
    packets = []
    
    print(f"Начинаю перехват трафика...")
    print(f"Фильтр: {filter_str}")
    if output_file:
        print(f"Сохранение в файл: {output_file}")
    print("Нажмите Ctrl+C для остановки\n")
    
    def packet_handler(packet):
        """Обработчик пакетов"""
        packets.append(packet)
        return packet
    
    try:
        sniff(
            iface=interface,
            filter=filter_str,
            prn=packet_handler,
            count=count,
            stop_filter=lambda x: False
        )
        
        if output_file and packets:
            wrpcap(output_file, packets)
            print(f"\n✓ Сохранено {len(packets)} пакетов в {output_file}")
        
        return packets
        
    except KeyboardInterrupt:
        print("\n\nПерехват остановлен пользователем")
        if output_file and packets:
            wrpcap(output_file, packets)
            print(f"✓ Сохранено {len(packets)} пакетов в {output_file}")
        return packets
    except Exception as e:
        print(f"\n\nОшибка при захвате трафика: {e}", file=sys.stderr)
        print("Сохраняю уже захваченные пакеты...")
        if output_file and packets:
            try:
                wrpcap(output_file, packets)
                print(f"✓ Сохранено {len(packets)} пакетов в {output_file}")
            except Exception as save_error:
                print(f"Ошибка при сохранении: {save_error}", file=sys.stderr)
        return packets


def main():
    parser = argparse.ArgumentParser(
        description='Перехват сетевого трафика и сохранение в файл',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:

1. Перехват трафика на порту 80:
   python script.py --sniff --filter "tcp port 80" --output traffic.pcap

2. Перехват трафика с ограничением количества пакетов:
   python script.py --sniff --filter "tcp port 80" --count 50 --output sample.pcap

3. Перехват трафика конкретного хоста:
   python script.py --sniff --filter "host example.com" --output host_traffic.pcap

4. Перехват на конкретном интерфейсе:
   python script.py --sniff --interface eth0 --filter "tcp port 80" --output traffic.pcap
        """
    )
    
    parser.add_argument('--sniff', action='store_true', help='Перехват трафика')
    parser.add_argument('--output', type=str, required=True, help='Файл для сохранения трафика (.pcap)')
    parser.add_argument('--filter', type=str, default='tcp port 80', help='Фильтр для перехвата (по умолчанию: tcp port 80)')
    parser.add_argument('--interface', type=str, help='Сетевой интерфейс для перехвата')
    parser.add_argument('--count', type=int, default=0, help='Количество пакетов для перехвата (0 = бесконечно)')
    
    args = parser.parse_args()
    
    # Если нет аргументов, показываем справку
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    if args.sniff:
        if not args.output:
            print("Ошибка: необходимо указать --output для сохранения трафика")
            sys.exit(1)
        sniff_traffic(
            interface=args.interface,
            filter_str=args.filter,
            count=args.count,
            output_file=args.output
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
