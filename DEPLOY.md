# Деплой ip-roller на Ubuntu

Инструкция рассчитана на Ubuntu 22.04/24.04, один экземпляр приложения, systemd и Caddy. Caddy принимает HTTPS и автоматически выпускает/обновляет сертификат. Uvicorn слушает только `127.0.0.1`; порт приложения наружу не открывается.

## 1. Подготовить DNS и сервер

Создайте DNS-запись `A` для домена панели на IPv4 сервера. Если добавляете `AAAA`, убедитесь, что IPv6 сервера действительно доступен. Разрешите входящий TCP 22 (SSH), 80 и 443; порт 8000 наружу не открывайте.

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip sqlite3 curl gnupg debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
sudo chmod o+r /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy
sudo adduser --system --group --home /opt/ip-roller iproller
sudo install -d -o iproller -g iproller -m 0750 /opt/ip-roller
sudo install -d -o iproller -g iproller -m 0700 /opt/ip-roller/data
```

Через WinSCP/SFTP загрузите содержимое папки проекта, включая скрытый `.env.example`, в `/tmp/ip-roller-upload/`; **не загружайте локальный `.env` и `data/`**. Затем на сервере:

```bash
sudo cp -a /tmp/ip-roller-upload/. /opt/ip-roller/
```

Не переносите рабочую базу или секреты через открытый канал.

```bash
sudo chown -R root:iproller /opt/ip-roller
sudo chown -R iproller:iproller /opt/ip-roller/data
sudo chmod 0750 /opt/ip-roller
sudo chmod 0700 /opt/ip-roller/data
```

Если включён UFW, разрешите SSH до изменения правил, затем откройте web-порты:

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw status
```

## 2. Создать конфигурацию и ключи

```bash
cd /opt/ip-roller
sudo cp .env.example .env
sudo python3 -m venv .venv
sudo .venv/bin/pip install --upgrade pip
sudo .venv/bin/pip install -r requirements.txt
```

Сгенерируйте два независимых секрета. Ключ шифрования паролей нужно хранить отдельно от резервной копии базы и не терять: без него приложение не сможет расшифровать сохранённые учётные данные.

```bash
sudo /opt/ip-roller/.venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
sudo /opt/ip-roller/.venv/bin/python -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Сгенерируйте bcrypt-хэш пароля администратора:

```bash
sudo /opt/ip-roller/.venv/bin/python -m app.security_cli hash-password
```

Откройте `/opt/ip-roller/.env` командой `sudo nano /opt/ip-roller/.env` и задайте как минимум:

```dotenv
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=ВСТАВЬТЕ_BCRYPT_ХЭШ
SESSION_SECRET=ВСТАВЬТЕ_СЕКРЕТ_СЕССИИ
CREDENTIALS_ENCRYPTION_KEY=ВСТАВЬТЕ_FERNET_КЛЮЧ
SESSION_HTTPS_ONLY=true
HOST=127.0.0.1
PORT=8000
```

Если в старой SQLite базе пароли лежат открытым текстом, приложение зашифрует их при старте. **До обновления обязательно остановите службу и сделайте резервную копию базы и `.env`.** Миграция требует правильный `CREDENTIALS_ENCRYPTION_KEY`. Права на `.env`:

```bash
sudo chown root:iproller /opt/ip-roller/.env
sudo chmod 0640 /opt/ip-roller/.env
```

Не публикуйте `.env`, Fernet-ключ, пароли или содержимое базы в тикетах и чатах.

## 3. Настроить ограничения и whitelist

Проверьте `config/zones.json` и `config/cidr_whitelist.json` вручную, зафиксируйте источник данных и дату их проверки. Приложение проверяет адреса по локальному CIDR-файлу; оно не подтверждает актуальность CIDR у внешнего сервиса.

По умолчанию действует общий лимит на все аккаунты: 10 create-операций в минуту, максимум 100 зарезервированных операций в сутки и 20 активных/неопределённых ресурсов. При необходимости задайте меньшие значения в `.env`:

```dotenv
MAX_CREATES_PER_MINUTE=10
MAX_CREATE_OPERATIONS_PER_DAY=100
MAX_ACTIVE_MANAGED_IPS=20
```

Эти пределы — предохранители приложения, а не официальные лимиты или расчёт цены Selectel. Перед запуском сверьте допустимые операции, тарифы и квоты с Selectel; контролируйте расходы в кабинете провайдера. Если API-запрос завершился неопределённо, приложение оставит операцию на ручную сверку и не будет повторять её автоматически.

Сервис выдаёт активным аккаунтам последовательные слоты на создание ресурсов. Время последнего запроса и состояние backoff/зон сохраняются в SQLite и переживают перезапуск. Если `429` или сетевые/5xx-ошибки возникают у нескольких аккаунтов в коротком окне, включается общая пауза API; одиночный `429` ограничивает только свой аккаунт. Эти настройки можно переопределить:

```dotenv
SCHEDULER_LEASE_SECONDS=60
GLOBAL_429_THRESHOLD_ACCOUNTS=2
GLOBAL_429_WINDOW_SECONDS=120
```

В интерфейсе доступны **Аналитика** и **История IP**. Реестр хранит первый/последний момент появления, число повторов, регион и результат сравнения с локальным CIDR. Отрицательные результаты пересматриваются через 24 часа; ошибка проверки хранится как `error`, повторяется через 5 минут и никогда не означает `miss`. Фоновый обработчик использует CIDR-файл, загруженный при запуске, и не обращается к Telegram или внешней БС. Перепроверка обновляет историю IP, но сама по себе не создаёт Floating IP и не переводит его в защищённые. Старые IP автоматически импортируются из таблиц `attempts` и `found_ips` при старте.

Рублёвая стоимость не запрашивается из биллинга Selectel и по умолчанию выключена. Если известна фактическая ставка из вашего тарифа, её можно указать в `.env`:

```dotenv
FLOATING_IP_COST_PER_HOUR_RUB=0
MAX_ESTIMATED_DAILY_COST_RUB=0
MAX_ESTIMATED_HOURLY_COST_RUB=0
```

При ненулевой ставке панель покажет **оценку** по часам удержания ресурсов, известных приложению; она не заменяет счёт Selectel и не учитывает автоматически тарифные исключения, округления или льготные квоты. Не задавайте ставку наугад. Если дополнительно указать `MAX_ESTIMATED_DAILY_COST_RUB` и/или `MAX_ESTIMATED_HOURLY_COST_RUB`, приложение остановит новые выделения при достижении ориентировочного лимита за скользящие сутки и/или час, добавляя стоимость ещё одного IP-часа в прогноз. Ставка и лимиты должны быть проверены по вашей детализации; это предохранитель, а не точный биллинг.

Кнопка **«Аварийная остановка»** выключает все фоновые воркеры и сохраняет это намерение в базе. Она не удаляет Floating IP, в том числе защищённые.

## 4. Установить systemd unit и Caddy

Поменяйте `monitor.example.com` в `deploy/Caddyfile` на свой домен. DNS должен уже указывать на сервер, а порты 80/443 должны быть доступны снаружи. Caddy устанавливается из официального APT-репозитория; команды выше соответствуют [официальной инструкции для Debian/Ubuntu](https://caddyserver.com/docs/install#debian-ubuntu-raspbian).

```bash
sudo install -m 0644 deploy/ip-roller.service /etc/systemd/system/ip-roller.service
sudo install -m 0644 deploy/Caddyfile /etc/caddy/Caddyfile
sudo nano /etc/caddy/Caddyfile
sudo systemctl daemon-reload
sudo systemctl enable --now ip-roller
sudo systemctl reload caddy
```

Проверить запуск и журналы:

```bash
sudo systemctl status ip-roller --no-pager
sudo journalctl -u ip-roller -n 100 --no-pager
sudo journalctl -u caddy -n 100 --no-pager
curl -sS -o /dev/null -w '%{http_code}\n' https://ВАШ.ДОМЕН/login
```

В панели создайте отдельного сервисного пользователя Selectel с минимально необходимой ролью на целевом проекте. Убедитесь, что аккаунт и проект правильные, выберите нужные зоны и только затем запускайте worker. Первый запуск рекомендуется наблюдать в журналах и кабинете Selectel.

### Telegram-отчёты роллинга (опционально)

Задайте `TELEGRAM_BOT_TOKEN` и `TELEGRAM_CHAT_ID` в `/opt/ip-roller/.env`. После перезапуска приложения оно будет отправлять сводку за завершившийся час через две минуты после смены часа. Часовой пояс по умолчанию — `Europe/Moscow`; его можно изменить через `TELEGRAM_REPORT_TIMEZONE`. Отчёт включает проверки, совпадения и повторы IP, 429 и другие ошибки, состояние аккаунтов, показатели по зонам и, только при заданной `FLOATING_IP_COST_PER_HOUR_RUB`, оценку стоимости.

Для ручной проверки отправь в чат тестовую сводку за последний завершённый час:

```bash
cd /opt/ip-roller
sudo -u iproller .venv/bin/python -m app.telegram_reports --test
```

Telegram остаётся необязательным. Почасовые отчёты можно отключить переменной `TELEGRAM_HOURLY_REPORT_ENABLED=false`; мгновенные уведомления о найденном IP и сбое зоны при этом остаются доступны, пока настроены токен и chat_id.

## 5. Резервная копия и восстановление

Остановите приложение перед копированием SQLite, чтобы копия была согласованной. Сохраняйте базу в закрытом месте. `.env` содержит Fernet-ключ; держите его копию в отдельном защищённом хранилище, отдельно от DB backup. Потеря ключа делает пароли из базы невосстановимыми.

```bash
sudo systemctl stop ip-roller
sudo install -d -m 0700 /var/backups/ip-roller
sudo sqlite3 /opt/ip-roller/data/ip-roller.db ".backup '/var/backups/ip-roller/ip-roller-$(date +%F-%H%M).db'"
sudo chmod 0600 /var/backups/ip-roller/*
sudo systemctl start ip-roller
```

Сохраните `.env` отдельно в менеджере секретов или зашифрованном хранилище. Для восстановления остановите службу, сохраните текущие файлы, замените DB согласованной копией, верните тот же `CREDENTIALS_ENCRYPTION_KEY`, затем запустите службу и проверьте журналы. Не восстанавливайте БД без соответствующего ключа.

## 6. Обновление

```bash
sudo systemctl stop ip-roller
# Сделайте резервную копию базы и .env по разделу 5.
# Скопируйте новую версию исходников, сохранив .env и data/.
cd /opt/ip-roller
sudo -u iproller .venv/bin/pip install -r requirements.txt
sudo systemctl daemon-reload
sudo systemctl start ip-roller
sudo systemctl status ip-roller --no-pager
sudo journalctl -u ip-roller -n 100 --no-pager
```

Не запускайте несколько Uvicorn workers: каждый процесс восстанавливает аккаунты со статусом `desired_running`, поэтому несколько процессов могут запустить дублирующие задачи. Systemd unit намеренно использует `--workers 1`.

## 7. Операционные заметки

- Страница **Ресурсы** показывает только ресурсы, чьи ID были записаны приложением. Неизвестные IP в проекте reconciler оставляет без изменений.
- Совпавший адрес помечается защищённым. Для явного освобождения откройте страницу ресурсов и подтвердите действие; worker соответствующего аккаунта остановится.
- Аккаунт нельзя удалить, пока в реестре есть активные или защищённые IP. Сначала освободите собственные ресурсы из панели; чужие адреса не трогайте.
- Проверьте в кабинете Selectel все операции, особенно после сетевого тайм-аута. Неопределённые операции блокируют новый запуск при достижении защитного лимита.
- Команды диагностики: `sudo journalctl -u ip-roller -f`, `sudo systemctl restart ip-roller`, `sudo systemctl restart caddy`.
- Не выставляйте Uvicorn напрямую в интернет. TLS, публичный домен и заголовки HTTPS обслуживает Caddy.
