# 🛡️ Ghost Proxy: AI Privacy Firewall

> **Protect your prompts. Own your data. Trust no one.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)]()

---

## 🔐 Что это?

**Ghost Proxy** — это локальный прокси-сервер, который встаёт между вами и любыми LLM (OpenAI, Anthropic, Google).

**Он делает три вещи:**
1. **Анонимизирует** ваши запросы на лету (удаляет PII: имена, emails, телефоны, адреса).
2. **Шифрует** историю диалогов локально (вы владеете ключами, не облако).
3. **Добавляет "шум"** (дифференциальная приватность) для защиты от стилеметрических атак.

**Зачем?** Потому что вы не должны доверять свои личные данные сторонним API.

---

## 🚀 Быстрый старт

### Через Docker (рекомендуется):

```bash
# 1. Клонировать репозиторий
git clone https://github.com/krisstern9-create/ghost-proxy.git
cd ghost-proxy

# 2. Настроить окружение
cp .env.example .env
# Отредактируйте .env: добавьте ваши API ключи

# 3. Запустить
docker-compose up -d

# 4. Проверить статус
curl http://localhost:8000/health

Настройка вашего приложения:
# Вместо прямого запроса к OpenAI:
# openai.ChatCompletion.create(...)

# Используйте Ghost Proxy:
import requests

response = requests.post(
    "http://localhost:8000/v1/chat/completions",
    json={
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Мой секретный запрос..."}]
    },
    headers={"Authorization": "Bearer your-local-token"}
)
```

⚙️ Возможности
🔒 Приватность
| Функция | Описание | 
|---------|----------|
| PII Redaction | Автоматическое удаление персональных данных (Presidio + spaCy) | 
| Differential Privacy | Добавление статистического шума для защиты метаданных |
| Local Encryption | AES-256 шифрование логов на вашем диске |
| Zero-Knowledge | Сервер не видит ваши данные в открытом виде |

🛡️ Безопасность
| Функция | Описание |
|---------|----------|
| Input Validation | Проверка запросов на инъекции и вредоносные паттерны |
| Output Filtering | Блокировка опасных ответов от LLM |
| Rate Limiting | Защита от DoS и злоупотреблений (Redis) |
| Audit Logging | Полная трассировка всех запросов (зашифрована) |

📊 Мониторинг
| Функция | Описание |
|---------|----------|
| Prometheus Metrics | Экспорт метрик для Grafana |
| Health Checks | Автоматическая проверка здоровья сервисов |
| Structured Logging | JSON-логи с контекстом для анализа |

🏗️ Архитектура
          
| Ваше приложение | Ghost Proxy | LLM API |
|-----------------|-------------|---------|
│ Пример | (Local) │ (Cloud) |
| Пример | PII Redaction | Пример|
| Пример | Encryption │ Пример |
| Пример | Audit Log | Пример |
| Пример | Rate Limit | Пример |

Компоненты:
- FastAPI — асинхронный веб-фреймворк
- Presidio — Microsoft NLP для обнаружения PII
- Cryptography — надёжное шифрование
- PostgreSQL — хранение зашифрованных аудит-логов
- Redis — кэш и rate limiting
- Prometheus/Grafana — мониторинг и визуализация

⚙️ Конфигурация
.env параметры:
# Приватность
PRIVACY_MODE=strict          # strict | balanced | permissive
REDACT_ENTITIES=PERSON,EMAIL,PHONE,ADDRESS  # Что удалять

# Шум (дифференциальная приватность)
DP_EPSILON=1.0              # Меньше = больше шума, больше приватности
DP_ENABLED=true

# Логирование
LOG_ENCRYPTION_KEY=your-32-char-key  # AES-256 ключ
LOG_RETENTION_DAYS=30

# Rate Limiting
RATE_LIMIT_REQUESTS=100     # Запросов
RATE_LIMIT_WINDOW=60        # В секундах

🧪 Тестирование
# Установить dev-зависимости
pip install -r requirements.txt

# Запустить тесты
pytest tests/ -v --cov=app

# Запустить с покрытием
pytest --cov=app --cov-report=html

🔧 Разработка
# Предварительные хуки (black, flake8, mypy)
pre-commit install

# Запуск локально (без Docker)
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Линтинг
black . && flake8 . && mypy app/

🤝 Contributing
Fork репозиторий
Создай ветку (git checkout -b feature/amazing-feature)
Закоммить изменения (git commit -m 'Add amazing feature')
Запушь (git push origin feature/amazing-feature)
Открой Pull Request

📜 Лицензия
MIT License. См. LICENSE для деталей.

