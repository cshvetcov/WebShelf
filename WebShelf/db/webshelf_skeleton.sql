-- WebShelf: файл-каркас структуры БД (эталон структуры без данных).
-- Версия каркаса: 3
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
