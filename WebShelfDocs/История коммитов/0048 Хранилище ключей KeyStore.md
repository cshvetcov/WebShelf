# 0048 — Хранилище ключей KeyStore

- **Хеш:** `6cfccdd`
- **Дата:** 2026-11-04
- **Автор:** Constantine
- **Сообщение:** refactor: вынос хранилища ключей из EncryptionService в KeyStore (шаг 3 декомпозиции)
- **Изменено файлов:** 16

## Суть изменений

- Шаг 3 дорожной карты декомпозиции: из `EncryptionService` в новый класс `Classes/Crypto/KeyStore.cs` вынесены зоны «Создание ключа» (`CreateKey`, `CreateKeyBase64`), «InstanceId (HKCU + DPAPI)» (`EnsureInstanceId`, валидация ULID, чтение/запись HKCU) и «Master key (HKCU + DPAPI + кэш)» (`EnsureMasterKey`, `ClearMasterKeyCache`, кэш со sliding TTL 5 мин и absolute max 30 мин, включая внутренний `ClearCachedMasterKey_NoLock` с сохранением семантики блокировок дословно).
- Перенос механический: тела 14 методов перенесены без изменений (проверено автосравнением с HEAD с точностью до пробелов), XML-документация перенесена вместе с кодом. Реестровые имена — persisted-данные рабочих машин — скопированы дословно: путь `HKCU\Software\WebShelf\Encryption`, значения `MasterKey` и `InstanceId`, область DPAPI `CurrentUser`. Правки при переносе — только константа `Class=` в логах перенесённого кода (`WebShelf.Classes.Service.EncryptionService` → `WebShelf.Classes.Crypto.KeyStore`, принцип 6 дорожной карты).
- `EncryptionService` остаётся фасадом: криптографическое ядро (AES-256-CBC + HMAC-SHA256, Encrypt-then-MAC, 8 перегрузок Encrypt/Decrypt) не тронуто и побайтово идентично HEAD (проверено автосравнением); пять методов-делегатов (`CreateKey`, `CreateKeyBase64`, `EnsureInstanceId`, `EnsureMasterKey`, `ClearMasterKeyCache`) сохраняют контракт для всех точек вызова — `Program.Main` (InstanceId при старте), `Data`, `Domain`, `Database` и тесты работают без правок. Статическое состояние (кэш мастер-ключа, блокировки `RegistrySync`/`MasterKeyCacheSync`) переехало в `KeyStore` целиком — двойных кэшей нет. Удаление фасада — шаг 8 дорожной карты.
- Осознанные решения при переносе: константа `MasterKeySizeBytes = 32` осталась в обоих классах (у каждого свой контракт длины ключа; взаимозависимость классов не создаётся); `ClearKeyMaterial` в `KeyStore` — собственная копия с идентичным телом (хранилище ключей не зависит от криптоядра, которое до шага 4 живёт в `EncryptionService`).
- Тесты: 6 методов перенесены из `EncryptionServiceTests` в новый `KeyStoreTests` дословно (создание ключей ×3, валидация длины переданного ключа, фиксированный InstanceId в Debug, стабильность мастер-ключа на Windows); добавлено 7 новых: очистка кэша при пустом кэше и после отказа (любая ОС), платформа без реестра/DPAPI → `null` без исключения (не-Windows), идемпотентность `EnsureInstanceId` в Release на Windows, совпадение/несовпадение переданного ключа (ветки кэша и реестра), round-trip записи и чтения мастер-ключа (критерий шага: записать `EnsureMasterKey` → прочитать), повреждённый DPAPI-блоб → `null` без исключения с сохранением значения (отказ реестра), фасадный контракт делегатов. Тесты, временно подменяющие реестровое значение, работают по схеме бэкап → подмена → `finally`-восстановление: следов на машине не остаётся.
- Изоляция параллелизма xUnit (§5 дорожной карты): `KeyStoreTests` и потребители реестрового мастер-ключа (`DomainTests`, `DatabaseTests`, `DataTests`, `DataConfigMigrationTests`, `AccountEndpointsTests`) объединены в непараллельную коллекцию `MasterKeyRegistry` — новые тесты временно подменяют значение `HKCU\...\MasterKey`, параллельное чтение его потребителями недопустимо. Состав и результат кейсов от сериализации не меняются; остальной набор остаётся параллельным.
- Попутно закрыты остаточные действия шагов 0–2: на страницы 0045–0047 вписаны хеши коммитов владельца (`681344a` — шаг 1, `51e0674` — шаг 0, `ab857f5` — шаг 2), ранее оставленные незаполненными.

## Затронутые файлы

- `WebShelf/Classes/Crypto/KeyStore.cs` — создан: хранилище ключей (665 строк).
- `WebShelf/Classes/Service/EncryptionService.cs` — удалены три вынесенные зоны, добавлены пять делегатов фасада (1230 → 672 строк; криптоядро побайтово идентично HEAD).
- `WebShelf.Tests/KeyStoreTests.cs` — создан: перенесённые и новые тесты хранилища ключей (12 методов), прямые HKCU-хелперы бэкапа/восстановления, константа коллекции `MasterKeyRegistryCollection`.
- `WebShelf.Tests/EncryptionServiceTests.cs` — удалены перенесённые регионы, обновлена сводка класса, добавлен фасадный тест (461 → 383 строк; осталось 22 метода: 21 прежний + 1 фасадный).
- `WebShelf.Tests/DomainTests.cs`, `WebShelf.Tests/DatabaseTests.cs`, `WebShelf.Tests/DataTests.cs`, `WebShelf.Tests/DataConfigMigrationTests.cs`, `WebShelf.Tests/AccountEndpointsTests.cs` — включение в непараллельную коллекцию `[Collection(KeyStoreTests.MasterKeyRegistryCollection)]` (логика тестов не менялась).
- `README.md` — состав покрытия тестами (`KeyStore`), строка `Classes/Crypto/` в структуре репозитория.
- `WebShelfDocs/Требования к коду/Пространства имен.md` — пространство имен `WebShelf.Classes.Crypto`.
- `WebShelfDocs/История коммитов/0045…0047*.md` — заполнение строк «Хеш» (остаточные действия шагов 0–2).
- `WebShelfDocs/История коммитов/История коммитов.md` — запись в списке.

## Проверено

- Полный прогон тестов (Linux, Debian 13 x64, .NET SDK 10.0.403, Debug): 332 тест-кейса — 307 passed, 25 skipped (21 прежний Windows-only/DPAPI + 4 новых Windows-only/Release-only), 0 failed; атрибутов `[Fact]`/`[Theory]` — 224 (было 217: 6 перенесены без изменений, добавлено 7; ни один тест не удалён).
- Сборка Debug и Release успешна; новых предупреждений нет (в Release присутствует только давний CS0219 в `Program.cs`, зафиксированный в дорожной карте как отложенное наблюдение №3).
- Автосравнение переноса с HEAD: 14 методов — без изменений; криптоядро `EncryptionService` (573 строки) — побайтово идентично; реестровые константы — дословно; `KeyStore` не ссылается на `EncryptionService` в коде.
- При применении: обязательный Windows-прогон по протоколу шага (реестр HKCU + DPAPI) — ожидается 332 кейса, 329 passed + 3 skipped (`KeyStoreTests.EnsureMasterKey_PlatformWithoutRegistry…` — не-Windows ветка, `KeyStoreTests.EnsureInstanceId_ReleaseOnWindows…` — Release-only в Debug-прогоне, `DataTests.ReadConfigAsync_MissingConfigFile_ReturnsFalse` — предохранительный, прежний), 0 failed.

---

[[0047 Вынос чистых функций имён AD|← предыдущий коммит]] · [[История коммитов|к списку коммитов]]
