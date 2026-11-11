-- WebShelf: файл-каркас структуры БД (эталон структуры без данных).
-- Версия каркаса: 4
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
-- хранит только контактные и персональные данные кандидата для проверки
-- администратором; учётные записи здесь не создаются и не хранятся.
--
-- Таблица автономна: связи с таблицей пермитов на уровне схемы не
-- устанавливаются; сопоставление заявки и пермита выполняется прикладным
-- кодом в момент обработки заявки.
--
-- Столбцы:
--   id         — суррогатный первичный ключ;
--   last_name  — фамилия кандидата;
--   first_name — имя кандидата;
--   patronymic — отчество кандидата; допускает NULL (может отсутствовать);
--   phone      — контактный телефон в международном формате
--                (+XXXXXXXXXXX, длина до 20 символов с запасом на разделители);
--   email      — адрес электронной почты, до 254 символов (максимум по
--                RFC 5321); уникален — одна активная заявка на адрес;
--   birth_date — дата рождения кандидата; допускает NULL (необязательна
--                при заполнении формы).
-- ============================================================================

CREATE SEQUENCE webshelf.registration_requests_id_seq AS bigint START WITH 1 INCREMENT BY 1;

CREATE TABLE webshelf.registration_requests (
    id          bigint                  NOT NULL DEFAULT nextval('webshelf.registration_requests_id_seq'::regclass),
    last_name   text                    NOT NULL,
    first_name  text                    NOT NULL,
    patronymic  text                    NULL,
    phone       character varying(20)   NOT NULL,
    email       character varying(254)  NOT NULL,
    birth_date  date                    NULL,
    CONSTRAINT registration_requests_pkey PRIMARY KEY (id),
    CONSTRAINT registration_requests_email_key UNIQUE (email)
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
