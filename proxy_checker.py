#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Proxy Checker - асинхронный инструмент для проверки HTTP/HTTPS/SOCKS прокси

Этот скрипт проверяет работоспособность прокси из JSON-файла,
измеряет скорость и задержку, а также сохраняет результаты в
структурированном виде для дальнейшего использования.

Автор: Sergei Dyshkant (SergD)
"""

import os
import json
import time
import asyncio
import aiohttp
import logging
import argparse
import pandas as pd
import matplotlib.pyplot as plt
from aiohttp_socks import ProxyConnector, ProxyType
from datetime import datetime
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TaskProgressColumn, TimeRemainingColumn
from rich.table import Table
from rich.logging import RichHandler

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
log = logging.getLogger("rich")

# Инициализация консоли Rich
console = Console()


class ProxyChecker:
    """Класс для асинхронной проверки прокси-серверов"""
    
    def __init__(self, timeout=10, test_url="http://httpbin.org/ip", check_anonymity=True,
                max_concurrent=100, proxy_types=None):
        """
        Инициализация объекта ProxyChecker
        
        Args:
            timeout (int): Таймаут подключения в секундах
            test_url (str): URL для проверки прокси
            check_anonymity (bool): Проверять ли анонимность прокси
            max_concurrent (int): Максимальное количество одновременных проверок
            proxy_types (list): Типы прокси для проверки (http, https, socks4, socks5)
        """
        self.timeout = timeout
        self.test_url = test_url
        self.check_anonymity = check_anonymity
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
        
        # Типы прокси для проверки
        self.proxy_types = proxy_types or ["http", "https", "socks4", "socks5"]
        
        # Для хранения результатов
        self.working_proxies = []
        self.failed_proxies = []
        
        # Статистика
        self.stats = {
            "total": 0,
            "working": 0,
            "failed": 0,
            "anonymity": {
                "elite": 0,
                "anonymous": 0,
                "transparent": 0
            },
            "types": {
                "http": 0,
                "https": 0,
                "socks4": 0,
                "socks5": 0
            }
        }
    
    async def check_proxy(self, ip_address, port, proxy_type="http"):
        """Проверка одного прокси-сервера
        
        Args:
            ip_address (str): IP-адрес прокси
            port (int): Порт прокси
            proxy_type (str): Тип прокси (http, https, socks4, socks5)
            
        Returns:
            dict: Результат проверки
        """
        async with self.semaphore:
            result = {
                "ip_address": ip_address,
                "port": port,
                "type": proxy_type,
                "working": False,
                "anonymity": None,
                "country": None,
                "response_time": None,
                "error": None
            }
            
            # Формируем строку прокси в зависимости от типа
            if proxy_type in ["http", "https"]:
                proxy_url = f"{proxy_type}://{ip_address}:{port}"
                connector = None
            else:  # SOCKS прокси
                proxy_url = None
                proxy_type_enum = ProxyType.SOCKS4 if proxy_type == "socks4" else ProxyType.SOCKS5
                connector = ProxyConnector(proxy_type=proxy_type_enum, host=ip_address, port=port)
            
            try:
                start_time = time.time()
                
                # Создаем сессию
                if connector:
                    session = aiohttp.ClientSession(connector=connector)
                else:
                    session = aiohttp.ClientSession()
                
                async with session:
                    # Устанавливаем таймаут для запроса
                    timeout = aiohttp.ClientTimeout(total=self.timeout)
                    
                    # Выполняем запрос через прокси
                    if proxy_url:
                        async with session.get(self.test_url, proxy=proxy_url, timeout=timeout) as response:
                            response_time = time.time() - start_time
                            response_json = await response.json()
                    else:
                        async with session.get(self.test_url, timeout=timeout) as response:
                            response_time = time.time() - start_time
                            response_json = await response.json()
                    
                    # Проверка успешности ответа
                    if response.status == 200:
                        result["working"] = True
                        result["response_time"] = round(response_time, 3)
                        
                        # Проверка анонимности (если IP в ответе не совпадает с реальным IP,
                        # то прокси может быть анонимным)
                        if self.check_anonymity and "origin" in response_json:
                            proxy_ip = response_json["origin"]
                            if "," in proxy_ip:  # Случай, когда возвращается несколько IP через запятую
                                ips = [ip.strip() for ip in proxy_ip.split(",")]
                                if ip_address in ips:
                                    result["anonymity"] = "transparent"
                                else:
                                    result["anonymity"] = "anonymous"
                            else:
                                if proxy_ip == ip_address:
                                    result["anonymity"] = "transparent"
                                else:
                                    result["anonymity"] = "anonymous"  # или "elite" в зависимости от деталей
            
            except asyncio.TimeoutError:
                result["error"] = "Timeout"
            except aiohttp.ClientProxyConnectionError:
                result["error"] = "Connection Error"
            except aiohttp.ClientConnectorError:
                result["error"] = "Connection Error"
            except Exception as e:
                result["error"] = str(e)[:100]  # Обрезаем длинные сообщения об ошибках
            
            return result
    
    async def check_proxy_all_types(self, ip_address, port):
        """Проверяет прокси на всех поддерживаемых типах (HTTP, HTTPS, SOCKS4, SOCKS5)
        
        Args:
            ip_address (str): IP-адрес прокси
            port (int): Порт прокси
            
        Returns:
            dict: Лучший результат проверки
        """
        results = []
        tasks = []
        
        for proxy_type in self.proxy_types:
            task = asyncio.create_task(self.check_proxy(ip_address, port, proxy_type))
            tasks.append(task)
        
        # Ожидаем выполнения всех задач
        completed_results = await asyncio.gather(*tasks)
        results.extend(completed_results)
        
        # Фильтруем только рабочие прокси
        working_results = [r for r in results if r["working"]]
        
        if working_results:
            # Сортируем по времени отклика (от меньшего к большему)
            best_result = sorted(working_results, key=lambda x: x["response_time"])[0]
            return best_result
        else:
            # Если ни один тип не работает, возвращаем первый результат с ошибкой
            return results[0]
    
    async def check_proxies(self, proxies):
        """Проверяет список прокси
        
        Args:
            proxies (list): Список прокси для проверки
        """
        self.stats["total"] = len(proxies)
        
        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeRemainingColumn(),
        ) as progress:
            task = progress.add_task("[cyan]Проверка прокси...", total=len(proxies))
            
            tasks = []
            for proxy in proxies:
                ip_address = proxy.get("ip_address")
                port = proxy.get("port")
                
                if not ip_address or not port:
                    progress.update(task, advance=1)
                    continue
                
                # Создаем задачу для проверки прокси по всем типам
                proxy_task = asyncio.create_task(
                    self.check_proxy_all_types(ip_address, port)
                )
                tasks.append(proxy_task)
            
            # Обрабатываем результаты по мере их поступления
            for i, future in enumerate(asyncio.as_completed(tasks)):
                result = await future
                progress.update(task, advance=1)
                
                if result["working"]:
                    self.working_proxies.append(result)
                    self.stats["working"] += 1
                    
                    # Обновляем статистику по типам
                    proxy_type = result["type"]
                    if proxy_type in self.stats["types"]:
                        self.stats["types"][proxy_type] += 1
                    
                    # Обновляем статистику по анонимности
                    anonymity = result["anonymity"]
                    if anonymity and anonymity in self.stats["anonymity"]:
                        self.stats["anonymity"][anonymity] += 1
                else:
                    self.failed_proxies.append(result)
                    self.stats["failed"] += 1
    
    def save_results(self, output_dir="results"):
        """Сохраняет результаты проверки в файлы
        
        Args:
            output_dir (str): Директория для сохранения результатов
        """
        # Создаем директорию для результатов, если она не существует
        os.makedirs(output_dir, exist_ok=True)
        
        # Текущая дата и время для имени файла
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Сохраняем рабочие прокси в JSON
        working_file = os.path.join(output_dir, f"working_proxies_{timestamp}.json")
        with open(working_file, "w", encoding="utf-8") as f:
            json.dump(self.working_proxies, f, indent=2)
        
        # Сохраняем в CSV для удобства анализа
        if self.working_proxies:
            df = pd.DataFrame(self.working_proxies)
            csv_file = os.path.join(output_dir, f"working_proxies_{timestamp}.csv")
            df.to_csv(csv_file, index=False)
        
        # Сохраняем статистику
        stats_file = os.path.join(output_dir, f"stats_{timestamp}.json")
        with open(stats_file, "w", encoding="utf-8") as f:
            json.dump(self.stats, f, indent=2)
        
        return working_file, stats_file
    
    def generate_report(self, output_dir="results"):
        """Генерирует отчет о проверке прокси
        
        Args:
            output_dir (str): Директория для сохранения отчета
        """
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Создаем DataFrame из рабочих прокси
        if not self.working_proxies:
            console.print("[bold red]Не найдено рабочих прокси для отчета![/bold red]")
            return
        
        df = pd.DataFrame(self.working_proxies)
        
        # График распределения типов прокси
        plt.figure(figsize=(10, 6))
        type_counts = df["type"].value_counts()
        type_counts.plot(kind="bar", color="skyblue")
        plt.title("Распределение типов прокси")
        plt.xlabel("Тип прокси")
        plt.ylabel("Количество")
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f"proxy_types_{timestamp}.png"))
        
        # График времени отклика
        plt.figure(figsize=(10, 6))
        df.sort_values("response_time")["response_time"].plot(kind="hist", bins=20, color="lightgreen")
        plt.title("Распределение времени отклика прокси")
        plt.xlabel("Время отклика (с)")
        plt.ylabel("Количество прокси")
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, f"response_times_{timestamp}.png"))
        
        # График анонимности (если проверялась)
        if "anonymity" in df and df["anonymity"].notna().any():
            plt.figure(figsize=(10, 6))
            anonymity_counts = df["anonymity"].value_counts()
            anonymity_counts.plot(kind="pie", autopct="%1.1f%%")
            plt.title("Распределение уровней анонимности прокси")
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f"anonymity_{timestamp}.png"))
        
        console.print(f"[bold green]Отчет сохранен в директории {output_dir}[/bold green]")
    
    def print_summary(self):
        """Выводит сводку результатов проверки"""
        console.print("\n[bold]Результаты проверки прокси:[/bold]")
        
        # Создаем таблицу для сводки
        table = Table(show_header=True, header_style="bold green")
        table.add_column("Метрика", style="dim")
        table.add_column("Значение")
        
        table.add_row("Всего проверено", str(self.stats["total"]))
        table.add_row("Рабочих прокси", f"[green]{self.stats['working']}[/green] ({self.stats['working']/self.stats['total']*100:.1f}%)")
        table.add_row("Нерабочих прокси", f"[red]{self.stats['failed']}[/red] ({self.stats['failed']/self.stats['total']*100:.1f}%)")
        
        # Добавляем статистику по типам
        for proxy_type, count in self.stats["types"].items():
            if count > 0:
                table.add_row(f"Тип {proxy_type}", str(count))
        
        # Добавляем статистику по анонимности
        for anonymity_type, count in self.stats["anonymity"].items():
            if count > 0:
                table.add_row(f"Анонимность {anonymity_type}", str(count))
        
        console.print(table)
        
        # Если есть рабочие прокси, покажем лучшие по времени отклика
        if self.working_proxies:
            console.print("\n[bold]Топ-10 самых быстрых прокси:[/bold]")
            
            # Сортируем прокси по времени отклика
            fastest_proxies = sorted(self.working_proxies, key=lambda x: x["response_time"])[:10]
            
            # Создаем таблицу для быстрых прокси
            fast_table = Table(show_header=True, header_style="bold cyan")
            fast_table.add_column("IP:Порт")
            fast_table.add_column("Тип")
            fast_table.add_column("Время отклика (с)")
            fast_table.add_column("Анонимность")
            
            for proxy in fastest_proxies:
                fast_table.add_row(
                    f"{proxy['ip_address']}:{proxy['port']}",
                    proxy["type"],
                    f"{proxy['response_time']:.3f}",
                    proxy["anonymity"] or "Не определена"
                )
            
            console.print(fast_table)


def load_proxies_from_json(file_path):
    """Загружает прокси из JSON файла
    
    Args:
        file_path (str): Путь к JSON файлу с прокси
        
    Returns:
        list: Список прокси
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            proxies = json.load(f)
        return proxies
    except Exception as e:
        log.error(f"Ошибка при загрузке прокси из файла: {e}")
        return []


async def main():
    parser = argparse.ArgumentParser(description="Асинхронный проверщик прокси-серверов")
    parser.add_argument(
        "-f", "--file", type=str, required=True,
        help="JSON файл с прокси (формат: [{\"ip_address\": \"127.0.0.1\", \"port\": 8080}, ...])"
    )
    parser.add_argument(
        "-t", "--timeout", type=int, default=10,
        help="Таймаут подключения в секундах (по умолчанию: 10)"
    )
    parser.add_argument(
        "-u", "--url", type=str, default="http://httpbin.org/ip",
        help="URL для проверки прокси (по умолчанию: http://httpbin.org/ip)"
    )
    parser.add_argument(
        "-c", "--concurrent", type=int, default=100,
        help="Максимальное количество одновременных проверок (по умолчанию: 100)"
    )
    parser.add_argument(
        "-o", "--output", type=str, default="results",
        help="Директория для сохранения результатов (по умолчанию: results)"
    )
    parser.add_argument(
        "--no-anonymity", action="store_true",
        help="Отключить проверку анонимности прокси"
    )
    parser.add_argument(
        "--types", type=str, default="http,https,socks4,socks5",
        help="Типы прокси для проверки, через запятую (по умолчанию: http,https,socks4,socks5)"
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Ограничить количество проверяемых прокси (по умолчанию: 0 - проверять все)"
    )
    
    args = parser.parse_args()
    
    # Загружаем прокси из файла
    proxies = load_proxies_from_json(args.file)
    if not proxies:
        log.error("Не удалось загрузить прокси или файл пуст.")
        return
    
    # Ограничиваем количество прокси, если указан лимит
    if args.limit > 0 and args.limit < len(proxies):
        log.info(f"Ограничение проверки до {args.limit} прокси")
        proxies = proxies[:args.limit]
    
    # Разбираем типы прокси
    proxy_types = [t.strip() for t in args.types.split(",") if t.strip()]
    
    # Создаем проверщик прокси
    checker = ProxyChecker(
        timeout=args.timeout,
        test_url=args.url,
        check_anonymity=not args.no_anonymity,
        max_concurrent=args.concurrent,
        proxy_types=proxy_types
    )
    
    # Запускаем проверку
    console.print(f"[bold]Начинаем проверку {len(proxies)} прокси-серверов...[/bold]")
    start_time = time.time()
    
    await checker.check_proxies(proxies)
    
    # Выводим статистику
    total_time = time.time() - start_time
    console.print(f"\n[bold]Проверка завершена за {total_time:.2f} секунд[/bold]")
    
    # Выводим сводку
    checker.print_summary()
    
    # Сохраняем результаты
    working_file, stats_file = checker.save_results(args.output)
    console.print(f"\n[bold green]Рабочие прокси сохранены в:[/bold green] {working_file}")
    console.print(f"[bold green]Статистика сохранена в:[/bold green] {stats_file}")
    
    # Генерируем отчет
    if checker.working_proxies:
        checker.generate_report(args.output)


if __name__ == "__main__":
    # Запускаем асинхронную функцию main
    asyncio.run(main())
