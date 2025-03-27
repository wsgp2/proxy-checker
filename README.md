# SergD Proxy Checker 🔍

Профессиональный инструмент для проверки работоспособности HTTP/HTTPS/SOCKS прокси-серверов

[![GitHub](https://img.shields.io/badge/GitHub-SergD_Proxy_Checker-blue.svg)](https://github.com/wsgp2/proxy-checker)
[![Telegram](https://img.shields.io/badge/Telegram-@sergei__dyshkant-blue.svg)](https://t.me/sergei_dyshkant)

## ✨ Возможности

- Асинхронная проверка большого количества прокси-серверов
- Определение типа прокси (HTTP, HTTPS, SOCKS4, SOCKS5)
- Измерение времени отклика и скорости работы
- Проверка уровня анонимности
- Генерация подробных отчетов и визуализаций
- Сохранение результатов в JSON и CSV форматах

## 🚀 Установка

```bash
# Установка зависимостей
pip install -r requirements.txt
```

## 🛠️ Использование

### Базовое использование

```bash
python proxy_checker.py -f proxies.json
```

### Расширенное использование

```bash
python proxy_checker.py \
  -f proxies.json \
  -t 5 \
  -c 200 \
  --types http,https \
  --limit 1000
```

### Параметры командной строки

| Параметр | Описание |
|----------|----------|
| `-f, --file` | JSON файл с прокси (обязательный) |
| `-t, --timeout` | Таймаут подключения в секундах (по умолчанию: 10) |
| `-u, --url` | URL для проверки прокси (по умолчанию: http://httpbin.org/ip) |
| `-c, --concurrent` | Максимальное количество одновременных проверок (по умолчанию: 100) |
| `-o, --output` | Директория для сохранения результатов (по умолчанию: results) |
| `--no-anonymity` | Отключить проверку анонимности прокси |
| `--types` | Типы прокси для проверки, через запятую (по умолчанию: http,https,socks4,socks5) |
| `--limit` | Ограничить количество проверяемых прокси (по умолчанию: 0 - проверять все) |

## 📊 Результаты

После завершения проверки, в указанной директории (по умолчанию `results/`) будут созданы следующие файлы:

- `working_proxies_[timestamp].json` - Список рабочих прокси в JSON формате
- `working_proxies_[timestamp].csv` - Список рабочих прокси в CSV формате
- `stats_[timestamp].json` - Статистика проверки
- Визуализации (графики распределения типов прокси, времени отклика и т.д.)

## 📋 Формат файла с прокси

Файл должен содержать массив JSON-объектов следующего формата:

```json
[
    {
        "ip_address": "127.0.0.1",
        "port": 8080
    },
    {
        "ip_address": "192.168.1.1",
        "port": 3128
    }
]
```

## 🧰 Требования

- Python 3.8+
- aiohttp
- aiohttp-socks
- pandas
- matplotlib
- rich

## 🧠 Автор

**Разработчик**: [Sergei Dyshkant (SergD)](https://t.me/sergei_dyshkant)

[![Telegram](https://img.shields.io/badge/Telegram-Связаться_со_мной-2CA5E0.svg?style=for-the-badge&logo=telegram&logoColor=white)](https://t.me/sergei_dyshkant)

---

<p align="center">© 2025 SergD. Все права защищены.</p>
