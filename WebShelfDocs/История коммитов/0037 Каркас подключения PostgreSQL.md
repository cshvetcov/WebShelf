# 0037 — Каркас подключения PostgreSQL

- **Хеш:** `a127666`
- **Дата:** 2026-10-31
- **Автор:** Constantine
- **Сообщение:** Добавлен каркас подключения PostgreSQL
- **Изменено файлов:** 6

## Суть изменений

- Добавлен каркас работы с PostgreSQL: класс `Database` (`WebShelf.Classes.DB`), пакет Npgsql.
- `Data` читает ключи БД из `Server.conf` и инициализирует `Database` при старте (`TryInitDatabase`).
- Шаблон конфигурации дополнен параметрами подключения.

## Затронутые файлы

- `WebShelf/Classes/DB/Database.cs` — создан.
- `WebShelf/Classes/Service/Data.cs`, `Program.cs`, `Server.conf.template`, `WebShelf.csproj` (Npgsql) — правки.

---

[[0036 Версия и коммит в логе при старте|← предыдущий коммит]] · [[История коммитов|к списку коммитов]] · [[0038 Исправления каркаса PostgreSQL|следующий коммит →]]
