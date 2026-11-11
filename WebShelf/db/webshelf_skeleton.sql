-- WebShelf: файл-каркас структуры БД (эталон структуры без данных).
-- Версия каркаса: 5
-- Схема: webshelf
--
-- Назначение: DbBootstrapper сравнивает живую схему с этим каркасом при старте
-- и приводит её к каркасу (см. WebShelfDocs/Решения в проекте/База данных.md).
--
-- Правила:
--  * поддерживаются только операторы CREATE SCHEMA, CREATE TABLE,
--    ALTER TABLE ... ADD CONSTRAINT, ALTER TABLE ... ADD COLUMN,
--    CREATE SEQUENCE и CREATE [UNIQUE] INDEX;
--  * идентификаторы квалифицируются схемой webshelf (или опираются на search_path,
--    который устанавливается перед применением);
--  * данные (INSERT/COPY) в каркасе запрещены;
--  * вместо serial/identity используйте явный CREATE SEQUENCE + DEFAULT nextval(...);
--  * файл — часть поставки приложения, а не пользовательский ввод.
--
-- Пример таблицы (добавляйте реальные таблицы по мере появления сущностей):
-- CREATE TABLE webshelf.documents (
--     id          bigint                       NOT NULL,
--     title       text                         NOT NULL,
--     created_at  timestamp with time zone     NOT NULL DEFAULT now(),
--     CONSTRAINT documents_pkey PRIMARY KEY (id)
-- );
--
-- CREATE SEQUENCE webshelf.documents_id_seq AS bigint START WITH 1 INCREMENT BY 1;
--
-- CREATE INDEX documents_title_idx ON webshelf.documents (title);
CREATE SCHEMA IF NOT EXISTS webshelf;

-- ============================================================================
-- Регистрационные пермиты.
--
-- Назначение: коды-разрешения на регистрацию новых пользователей. Пермит
-- выдаётся администратором заранее и предъявляется кандидатом при подаче
-- заявки на регистрацию. Счётчик задаёт остаток доступных регистраций по
-- пермиту: при каждой успешной регистрации уменьшается на 1; пермит со
-- значением счётчика 0 считается исчерпанным и регистрации не подлежит.
--
-- Таблица автономна: ссылки на другие таблицы схемы не устанавливаются.
--
-- Столбцы:
--   id       — суррогатный первичный ключ;
--   permit   — значение пермита (секретный код, уникально в пределах таблицы);
--   counter  — счётчик оставшихся регистраций, допустимый диапазон 0..255
--              (в PostgreSQL нет однобайтового беззнакового типа, поэтому
--              smallint + CHECK).
--
-- ВАЖНО: составные выражения CHECK (с AND/OR) записываются со скобками вокруг
-- каждого операнда — в том виде, в каком их депарирует pg_get_constraintdef.
-- Сравнение ограничений идёт по нормализованному тексту, который схлопывает
-- только смежные пары скобок; форма CHECK (a AND b) без операндных скобок
-- никогда не совпадает с живой схемой и вызывает бесконечный цикл
-- «удалить/добавить» при старте приложения.
-- ============================================================================

CREATE SEQUENCE webshelf.registration_permits_id_seq AS bigint START WITH 1 INCREMENT BY 1;

CREATE TABLE webshelf.registration_permits (
    id       bigint   NOT NULL DEFAULT nextval('webshelf.registration_permits_id_seq'::regclass),
    permit   text     NOT NULL,
    counter  smallint NOT NULL DEFAULT 1,
    CONSTRAINT registration_permits_pkey PRIMARY KEY (id),
    CONSTRAINT registration_permits_permit_key UNIQUE (permit),
    CONSTRAINT registration_permits_counter_range CHECK ((counter >= 0) AND (counter <= 255))
);

-- ============================================================================
-- Заявки на регистрацию.
--
-- Назначение: анкеты кандидатов, подавших заявку на создание учётной записи.
-- Авторизация в приложении выполняется через Windows AD, поэтому таблица
-- хранит данные анкеты и контактные данные кандидата для проверки
-- администратором; учётные записи здесь не создаются и не хранятся.
--
-- Таблица автономна: связи с таблицами пермитов и журнала политик на уровне
-- схемы не устанавливаются; сопоставление заявки с пермитом и редакциями
-- политик выполняется прикладным кодом в момент обработки заявки.
--
-- Столбцы:
--   id                           — суррогатный первичный ключ (служебный
--                                  идентификатор заявки);
--   last_name                    — фамилия кандидата;
--   first_name                   — имя кандидата;
--   patronymic                   — отчество кандидата (обязательное поле
--                                  формы, NULL запрещён);
--   phone                        — контактный телефон в формате маски
--                                  формы «+7 (XXX) XXX-XX-XX» (18 символов,
--                                  до 20 с запасом); уникален — одна заявка
--                                  на номер;
--   email                        — адрес электронной почты, до 254 символов
--                                  (максимум по RFC 5321), хранится в нижнем
--                                  регистре; уникален — одна заявка на адрес;
--   personal_data_policy_version — номер редакции политики обработки
--                                  персональных данных, действовавшей
--                                  в момент подачи заявки (согласие
--                                  привязано к редакции — журнал
--                                  webshelf.policy_versions);
--   cookie_policy_version        — номер редакции политики обработки файлов
--                                  cookie, действовавшей в момент подачи
--                                  заявки (согласие привязано к редакции);
--   submitted_at                 — дата и время подачи заявки (UTC,
--                                  точность до секунды — приложение
--                                  записывает момент, усечённый до целых
--                                  секунд; без DEFAULT: значение обязано
--                                  передаваться явно);
--   ad_object_guid               — objectGUID учётной записи AD, с которой
--                                  связана заявка: NULL — заявка ещё не
--                                  принята администратором, значение —
--                                  принята (одобрена). objectGUID —
--                                  неизменяемый идентификатор объекта AD
--                                  (не переиспользуется и не меняется
--                                  при переименовании учётной записи, в
--                                  отличие от sAMAccountName/UPN/DN) — связь
--                                  «заявка ↔ учётная запись» не теряется;
--                                  UNIQUE — одна учётная запись AD может
--                                  быть связана не более чем с одной
--                                  заявкой (NULL не конфликтует: не
--                                  принятых заявок сколько угодно).
-- ============================================================================

CREATE SEQUENCE webshelf.registration_requests_id_seq AS bigint START WITH 1 INCREMENT BY 1;

CREATE TABLE webshelf.registration_requests (
    id                           bigint                   NOT NULL DEFAULT nextval('webshelf.registration_requests_id_seq'::regclass),
    last_name                    text                     NOT NULL,
    first_name                   text                     NOT NULL,
    patronymic                   text                     NOT NULL,
    phone                        character varying(20)    NOT NULL,
    email                        character varying(254)   NOT NULL,
    personal_data_policy_version integer                  NOT NULL,
    cookie_policy_version        integer                  NOT NULL,
    submitted_at                 timestamp with time zone NOT NULL,
    ad_object_guid               uuid                     NULL,
    CONSTRAINT registration_requests_pkey PRIMARY KEY (id),
    CONSTRAINT registration_requests_email_key UNIQUE (email),
    CONSTRAINT registration_requests_phone_key UNIQUE (phone),
    CONSTRAINT registration_requests_ad_object_guid_key UNIQUE (ad_object_guid)
);

-- Индекс для поиска заявок администратором по фамилии.
CREATE INDEX registration_requests_last_name_idx ON webshelf.registration_requests (last_name);

-- ============================================================================
-- Журнал версий политик обработки данных.
--
-- Назначение: редакции текстов политик обработки файлов cookie и обработки
-- персональных данных. Оформление (оболочка) страниц политик рендерится
-- Razor-компонентами, текст редакции подгружается из этой таблицы.
-- При старте PolicyContentService сравнивает контрольную сумму (SHA-256
-- канонизированного текста) файла поставки (Content/Policies/*.html)
-- с последней строкой журнала той же политики и при изменении добавляет
-- новую редакцию. Журнал append-only: строки никогда не обновляются
-- и не удаляются; возврат текста, совпадающего с любой из существующих
-- редакций, новую строку не создаёт (защита от случайного отката публикации
-- более старой поставкой). Актуальная редакция политики — MAX(version).
-- Дата вступления редакции в силу — момент вставки строки (перезапуск
-- приложения с изменённым текстом). Полное описание — WebShelfDocs/
-- Решения в проекте/Версионирование политик.md.
--
-- Таблица автономна: ссылки на другие таблицы схемы не устанавливаются.
--
-- Столбцы:
--   id             — суррогатный первичный ключ;
--   policy         — код политики: 'cookie' — обработка cookie,
--                    'personal-data' — обработка персональных данных;
--   version        — номер редакции в пределах политики; начинается с 1
--                    и монотонно растёт (CHECK-домен кодов не позволяет
--                    журналу выйти за пределы известных политик);
--   effective_from — дата и время вступления редакции в силу (UTC);
--   content        — канонизированный HTML-текст редакции (UTF-8, LF,
--                    без BOM): фрагмент без оболочки страницы и заголовка h1;
--   content_sha256 — контрольная сумма SHA-256 текста редакции (hex, 64
--                    символа): сравнение при синхронизации и контроль
--                    целостности при чтении;
--   created_at     — техническое время вставки строки.
--
-- ВАЖНО: составные выражения CHECK записываются со скобками вокруг
-- каждого операнда и в той форме, которую возвращает pg_get_constraintdef
-- (см. комментарий к registration_permits_counter_range): сравнение литералов
-- со столбцом text PostgreSQL депарсит с приведением ::text — каркас обязан
-- записывать литералы в этом же виде, иначе контрольная проверка после
-- применения каркаса никогда не сойдётся.
-- ============================================================================

CREATE SEQUENCE webshelf.policy_versions_id_seq AS bigint START WITH 1 INCREMENT BY 1;

CREATE TABLE webshelf.policy_versions (
    id             bigint                   NOT NULL DEFAULT nextval('webshelf.policy_versions_id_seq'::regclass),
    policy         text                     NOT NULL,
    version        integer                  NOT NULL,
    effective_from timestamp with time zone NOT NULL DEFAULT now(),
    content        text                     NOT NULL,
    content_sha256 character varying(64)    NOT NULL,
    created_at     timestamp with time zone NOT NULL DEFAULT now(),
    CONSTRAINT policy_versions_pkey PRIMARY KEY (id),
    CONSTRAINT policy_versions_policy_version_key UNIQUE (policy, version),
    CONSTRAINT policy_versions_policy_domain CHECK (((policy = 'cookie'::text) OR (policy = 'personal-data'::text)))
);

-- Индекс для выборки строк конкретной политики (актуальная редакция, история).
CREATE INDEX policy_versions_policy_idx ON webshelf.policy_versions (policy);
