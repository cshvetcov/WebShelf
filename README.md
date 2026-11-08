# Патч: баннер согласия на обработку cookie не отображается

Проект: **WebShelf** · Базовый коммит: **e0639eb** («Добавлена политика обработки cookie», ветка main) ·
Дата: 08.11.2026 · Проблема и диагноз — по отчёту «Отчёт о проблеме: баннер согласия на обработку cookie не отображается».

---

## 1. Проблема

После коммита e0639eb баннер согласия не появляется на странице входа `/entry`, хотя:

- в `Server.conf` установлено `cookieconsent=true`;
- в логе старта зафиксировано `BannerEnabled=true`;
- `localStorage` доступен, ключ `ws-cookie-consent` удалён;
- футер со ссылкой на политику cookie отображается корректно;
- запроса к `/Components/Shared/CookieConsent.razor.js` в Network нет —
  JS-модуль баннера никогда не импортируется.

## 2. Корневая причина (подтверждена)

`CookieConsent` размещён в `MainLayout.razor`, который рендерится **статически**:
интерактивная граница, заданная `@rendermode InteractiveServer` на странице
(`Entry.razor`), охватывает только саму страницу и её дочерние компоненты, но
**не layout** (правила распространения режимов рендера Blazor Web App —
learn.microsoft.com/aspnet/core/blazor/components/render-modes). В статическом
рендере JS interop недоступен: в `OnAfterRenderAsync` компонента вызов
`Js.InvokeAsync("import", ...)` бросает `InvalidOperationException`, исключение
перехватывается пустым catch-блоком — `bannerVisible` остаётся `false`, баннер
молча скрыт, DOM-элемент `.ws-cookie-consent` не создаётся.

Воспроизведено на уровне фреймворка в юнит-тестах (см. п. 5): до исправления
рендер `MainLayout` через `HtmlRenderer` завершается «успешно» и молча — без
баннера; после исправления статический рендер обнаруживает запрошенную
интерактивную границу `InteractiveServerRenderMode` для `CookieConsent`.

## 3. Состав изменений

| Файл | Изменение |
| --- | --- |
| `WebShelf/Components/Layout/MainLayout.razor` | **Основное исправление.** Экземпляру `CookieConsent` задаётся режим рендера `@rendermode="ConsentRenderMode"`: `InteractiveServer` при включённом ключе `cookieconsent`, `null` (статический рендер) — при выключенном. Layout остаётся статическим (вариант B отчёта). Компонент пререндерится вместе со страницей и после загрузки `blazor.web.js` активируется в общем серверном circuit — JS interop доступен, баннер показывается |
| `WebShelf/Components/Shared/CookieConsent.razor` | Диагностика (рекомендация 7.2 отчёта): молчаливые catch-блоки `JSDisconnectedException` / `InvalidOperationException` в `OnAfterRenderAsync` и `SaveDecisionAsync` теперь пишут `Log.Debug` с `Class={Class}, Method={Method}` (уровень Debug не засоряет штатный лог с `MinimumLevel.Information`, но доступен при отладке) |
| `WebShelf/Components/Shared/CookieConsent.razor.js` | Согласование с документацией (рекомендация 7.3 отчёта): `hasDecision()` теперь делегирует `getDecision() !== null` — запись с несовпадающей версией `CONSENT_VERSION` больше не считается решением, и при инкременте версии баннер повторно запросит согласие, как обещает `WebShelfDocs/Решения в проекте/Обработка cookie.md` |
| `WebShelf.Tests/MainLayoutCookieConsentTests.cs` | **Новые юнит-тесты** (2): включённый баннер запрашивает интерактивную границу `InteractiveServer` для `CookieConsent`; выключенный баннер рендерится статически без interop и разметки |
| `WebShelf.Tests/SchemaSkeletonParserTests.cs` | **Обязательное исправление упавшего теста** (п. 4 правил AGENTS.md), см. п. 6 |

Почему режим рендера условный (`null` при выключенном ключе), а не всегда
`InteractiveServer`: документация проекта («Обработка cookie.md») фиксирует
поведение «при выключенном баннере компонент не обращается к JS и не создаёт
цепочек interop». Условный режим сохраняет это обещание: при
`cookieconsent=false` (значение по умолчанию) интерактивная граница не
создаётся вовсе.

## 4. Как применить

Вариант 1 — поверх рабочей копии репозитория (коммит e0639eb):

1. Распаковать архив.
2. Скопировать файлы из каталогов `WebShelf/` и `WebShelf.Tests/` архива в
   одноимённые каталоги репозитория (с заменой).
3. Пересобрать решение: `dotnet build WebShelf.slnx -c Debug`.
4. Прогнать тесты: `dotnet test WebShelf.Tests/WebShelf.Tests.csproj -c Debug`.

Вариант 2 — через git:

```bash
git apply cookieconsent-banner-fix-e0639eb.patch
```

Коммитов в репозиторий патч не отправляет (п. 1 правил AGENTS.md).

## 5. Юнит-тесты

Новые тесты `WebShelf.Tests/MainLayoutCookieConsentTests.cs`:

- `Render_BannerEnabled_CookieConsentRequestsInteractiveServer` — при
  `cookieconsent=true` статический рендер `MainLayout` (через `HtmlRenderer`,
  тот же статический SSR, которым Blazor отвечает на документ-запросы)
  запрашивает для `CookieConsent` интерактивную границу: среда без интерактивной
  платформы сообщает об этом исключением, называя компонент
  `WebShelf.Components.Shared.CookieConsent` и режим `InteractiveServerRenderMode`.
  До исправления это исключение не возникает — баннер просто молча не показывается.
- `Render_BannerDisabled_NoInteropAndNoBannerMarkup` — при выключенном ключе
  `MainLayout` рендерится полностью статически: футер и `blazor-error-ui`
  присутствуют, разметка баннера и интерактивные границы (`<!--blazor`) отсутствуют.

JS-логика `CookieConsent.razor.js` юнит-тестами не покрыта: в репозитории нет
инфраструктуры JS-тестирования, её добавление — отдельное архитектурное
решение. Поведение `hasDecision()` проверяется вручную по чек-листу (п. 7).

Результат прогона (Linux, .NET SDK 10.0.403): **491 тест, 0 упало, 477 прошло,
14 пропущено** (пропущенные — Windows-специфичные тесты KeyStore: HKCU/DPAPI).

## 6. Исправлен упавший тест (не связан с задачей)

При базовом прогоне на коммите e0639eb падал
`WebShelf.Tests.SchemaSkeletonParserTests.Loader_MissingFile_ThrowsAndRealSkeletonLoads`:

- **Причина.** Тест (написан в коммите 8fc7ef1, когда файл-каркас
  `db/webshelf_skeleton.sql` не содержал таблиц) утверждает
  `Assert.Empty(skeleton.Manifest.Tables)`. Коммит 2753142 «В каркас БД добавлены
  таблицы для заявок на регистрацию» добавил в каркас таблицы
  `registration_permits` и `registration_requests` — манифест перестал быть
  пустым, устаревшее утверждение начало падать.
- **Исправление.** Вместо `Assert.Empty` — `Assert.NotEmpty` +
  `Assert.Contains` для обеих таблиц (перечень через `Contains`, а не точный
  список: добавление будущих таблиц не должно ломать тест).

## 7. Чек-лист проверки после исправления (ручная проверка на Windows)

| № | Проверка | Ожидаемый результат |
| --- | --- | --- |
| 1 | Лог старта | `BannerEnabled=true` |
| 2 | Network при `/entry` | `GET .../CookieConsent.razor.js` → 200 |
| 3 | DOM | `document.querySelector('.ws-cookie-consent')` ≠ null |
| 4 | UI | Баннер над футером с кнопками «Принять» / «Отклонить» |
| 5 | После «Принять» | Баннер скрыт; `localStorage.ws-cookie-consent` заполнен |
| 6 | После `removeItem` + reload | Баннер снова появляется |
| 7 | `cookieconsent=false` + restart | Баннер не появляется, запроса `CookieConsent.razor.js` нет |

**Важно (рекомендация 7.4 отчёта):** в логе диагностики версия процесса —
`0.1.0-alpha.28, Commit=27531421d6`, тогда как актуальный коммит main — e0639eb.
Перед проверкой убедиться, что запущена сборка именно с кодом актуального
коммита (полная пересборка: `dotnet build`/публикация; сверка `Commit` в строке
«Версия: …» лога старта).
