# 0051 — Запись защищённых учётных данных SecureCredentialsWriter

- **Хеш:** `7a9eb92`
- **Дата:** 2026-11-05
- **Автор:** Constantine
- **Сообщение:** refactor: вынос записи защищённых учётных данных из Data в SecureCredentialsWriter и инициализаторов секций в Configuration/Sections (шаг 6 декомпозиции)
- **Изменено файлов:** 13

## Суть изменений

- Шаг 6 дорожной карты декомпозиции (первая половина — чистый перенос; улучшение У1 о симметричном затирании открытых доменных значений выделяется в отдельный коммит 0052 по принципу 10 дорожной карты «изменения поведения и чистые перемещения не смешиваются»): из `Data` в новый класс `Classes/Service/Configuration/SecureCredentialsWriter.cs` вынесен блок записи: `CredentialKeys` (record struct с подписями ключей), три статических набора ключей (домен, БД, TLS), `WriteSecureCredentials` (управляемая перезапись с сохранением комментариев и порядка строк, атомарная замена `tmp` + `File.Replace`) и обёртки `WriteSecureDomainCredentials`/`WriteSecureDbCredentials`.
- Класс инстансный, путь к файлу внедряется конструктором (продолжение улучшения У2, прецедент — `ServerConfigParser` шага 5): `Data` создаёт писателя один раз в конструкторе на своё свойство `ConfigFile` и передаёт инициализаторам секций. `CredentialKeys` вложен в писателя, как был вложен в `Data`. Видимость обёрток поднята с `private` до `internal`: после выноса вызываются инициализаторами секций из других файлов той же сборки.
- **Точка решения о секциях сработала:** `Data` после выноса записи — ~977 строк (> ~550), поэтому инициализаторы секций `TryInitDomain`, `TryInitDatabaseAsync`, `TryInitCertificate` вынесены в `Classes/Service/Configuration/Sections/` (`DomainSection`, `DatabaseSection`, `CertificateSection`) с возвратом результатов вместо мутации состояния `Data`: домен и БД возвращают готовый экземпляр либо `null`, сертификат — через выходной параметр (прецедент `out` — `RoleCacheOptions.Create`). `Data` присваивает результаты своим свойствам в прежнем порядке и агрегирует признаки успеха; порядок сброса состояния при отказе в `ReadConfigAsync` не менялся. Скалярные секции (порт, схема, параметры ролевой модели) остаются в `Data` (единая зона «хранение и инициализация конфигурации», §7 дорожной карты).
- Перенос механический: тела всех 10 перенесённых членов проверены автосравнением с HEAD (с точностью до пробелов и `//`-комментариев). Правки переноса: константа `Class=` в логах (`WebShelf.Classes.Service.Data` → имена новых классов, принцип 6 дорожной карты); обращения к свойствам `Data` заменены параметрами и локальными переменными (`InstanceIdShort` → параметр `instanceIdShort`, `Scheme` → параметр `scheme`, поля `Domain`/`Database`/`TlsCertificate` → локальные переменные); `return false`/`Domain = null` → `return null`; `RequiredDomainKeys` переехал в `DomainSection`; вызовы записи получили префикс писателя; в `Data.cs` удалены ставшие неиспользуемыми `using System.Text;` и `using Npgsql;` (последние пользователи — перенесённый код), добавлен `using …Configuration.Sections;`.
- Тесты: 10 characterization-тестов записи шага 0 переписаны с вызова `Data.WriteSecureCredentials` на прямой вызов `SecureCredentialsWriter` (контракт тот же, ожидания не менялись; файл сохраняет имя `DataWriteSecureCredentialsTests.cs` по прецеденту шага 5 — удаления файлов патчем не выражаются, класс по-прежнему покрывает запись конфигурации Data). Добавлены 4 прямых теста инициализаторов секций (`DataConfigSectionsTests.cs`; ветки, не требующие мастер-ключа: отсутствие/пустой `domainname`, отсутствие `dbhost`, схема http без сертификата — выполняются на любой платформе) и 1 тест новой границы класса (`SecureCredentialsWriter(null!)` → `ArgumentNullException`, прецедент `ServerConfigParser`). Тесты миграции `DataConfigMigrationTests` не менялись — перенос поведения не изменяет.
- Осознанные решения: 1) `CertificateSection.TryInitCertificate` возвращает `bool` + `out X509Certificate2?` — ветка «сертификат не требуется при http» остаётся внутри секции, оркестратор не различает «не нужен» и «ошибка» по косвенным признакам; 2) секции — статические классы (без состояния; прецедент — `AdNames`, `AccountEndpoints`); 3) присваивание `Domain = …`/`Database = …`/`TlsCertificate = …` выполняется в `ReadConfigAsync` сразу после возврата из секции — моменты видимости значений свойств внутри чтения конфигурации сохранены; 4) `SecureCredentialsWriter.TlsCredentialKeys` в вызовах `CertificateSection` квалифицирован полностью — единый стиль ссылок на наборы ключей.
- Метрики: `Data.cs` 1165 → 437 строк (критерий шага «≤ ~550» выполнен); новые классы: `SecureCredentialsWriter.cs` — 270, `DomainSection.cs` — 208, `DatabaseSection.cs` — 235, `CertificateSection.cs` — 212 строк (все ≤ ~500). Атрибутов `[Fact]`/`[Theory]` 238 → 243; тест-кейсов 350 → 355. Порог точки решения зафиксирован: без выноса секций `Data` составил бы ~977 строк.

## Затронутые файлы

- `WebShelf/Classes/Service/Configuration/SecureCredentialsWriter.cs` — создан: запись защищённых учётных данных, инстансный класс с внедрённым путём, `CredentialKeys` и наборы ключей (270 строк).
- `WebShelf/Classes/Service/Configuration/Sections/DomainSection.cs` — создан: инициализатор секции домена, возвращает `Domain?` (208 строк).
- `WebShelf/Classes/Service/Configuration/Sections/DatabaseSection.cs` — создан: инициализатор секции БД, возвращает `Task<Database?>` (235 строк).
- `WebShelf/Classes/Service/Configuration/Sections/CertificateSection.cs` — создан: инициализатор секции TLS-сертификата, `bool` + `out X509Certificate2?` (212 строк).
- `WebShelf/Classes/Service/Data.cs` — удалены блок записи и инициализаторы секций, добавлены свойство `CredentialsWriter` и вызовы секций в `ReadConfigAsync` (1165 → 437 строк; тела проверены автосравнением).
- `WebShelf.Tests/DataWriteSecureCredentialsTests.cs` — 9 тестов записи переписаны на прямой вызов `SecureCredentialsWriter`; добавлен тест конструктора с `null` (410 → 423 строки).
- `WebShelf.Tests/DataConfigSectionsTests.cs` — создан: 4 прямых теста инициализаторов секций (133 строки).
- `README.md` — покрытие тестами (запись `SecureCredentialsWriter` и секции отдельно от миграции), строки `Classes/Service/Configuration/` и `…/Sections/` в структуре репозитория.
- `WebShelfDocs/Требования к коду/Пространства имен.md` — пространства имен `WebShelf.Classes.Service.Configuration` (дополнен) и `WebShelf.Classes.Service.Configuration.Sections` (новый).
- `WebShelfDocs/Решения в проекте/База данных.md` — ссылка `Data.TryInitDatabaseAsync` → `DatabaseSection.TryInitDatabaseAsync`.
- `WebShelfDocs/Решения в проекте/Пользователи.md` — ссылка `Data.TryInitDomain` → `DomainSection.TryInitDomain`.
- `WebShelfDocs/История коммитов/История коммитов.md` — запись в списке.
- `WebShelfDocs/История коммитов/0051 Запись защищённых учётных данных SecureCredentialsWriter.md` — эта страница.

## Проверено

- Полный прогон тестов (Linux, Debian 13 x64, .NET SDK 10.0.403, Debug): 355 тест-кейсов — 330 passed, 25 skipped (прежние Windows-only/DPAPI, новых пропусков нет), 0 failed; атрибутов `[Fact]`/`[Theory]` — 243 (было 238: 9 переписаны без изменения ожиданий, добавлено 5; ни один тест не удалён).
- Сборка Debug и Release успешна; новых предупреждений нет (в Release присутствует только давний CS0219 в `Program.cs` — отложенное наблюдение №3 дорожной карты).
- Автосравнение переноса с HEAD: тела `CredentialKeys`, трёх наборов ключей, `WriteSecureCredentials`, обеих обёрток, `TryInitDomain`, `TryInitDatabaseAsync`, `TryInitCertificate` — дословны (10/10) с точностью до задокументированных механических правок (подстановки возврата результата вместо мутации, параметров вместо свойств, `Class=` в логах).
- Формат `Server.conf` не изменился: characterization-тесты шага 0 (перенос открытых значений с затиранием, сохранение комментариев и порядка, дописывание недостающих ключей, атомарная замена, байтовое сравнение с BOM и завершающим переводом строки, регистронезависимость) зелёные без правки ожиданий — изменена только вызываемая обёртка.
- При применении: обязательный Windows-прогон по протоколу шага (шаг затрагивает запись конфигурации) — ожидается 355 кейсов, 352 passed + 3 skipped (прежние), 0 failed. Рантайм-смоук: старт с существующим `Server.conf` (защищённые значения читаются секциями, файл не переписывается), при желании — старт с открытыми значениями (миграция проходит, открытые затираются — поведение прежнее, У1 в этом коммите не меняет ничего).
- Вторая половина шага 6 (улучшение У1 — симметричное затирание открытых доменных значений при валидных защищённых) — отдельный коммит, страница 0052.

---

[[0050 Парсер Server.conf ServerConfigParser|← предыдущий коммит]] · [[История коммитов|к списку коммитов]]
