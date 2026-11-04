using System.DirectoryServices.AccountManagement;
using Serilog;
using WebShelf.Classes.Service;

namespace WebShelf.Classes.DC;

/// <summary>
/// Представляет домен Active Directory и предоставляет методы
/// проверки учётных данных пользователя, а также обеспечения наличия
/// групп безопасности, необходимых для функционирования WebShelf
/// (формирование списка из шаблонов имён, проверка существования
/// и создание от имени сервисной учётной записи).
/// Реализует <see cref="IAdGroupSource"/>: расширенные имена групп и списки
/// прямых групп пользователей для ролевой модели (см. WebShelf.Classes.Security).
/// Используется в браузерном приложении WebShelf для работы
/// с документацией в проектной организации промышленного и гражданского строительства.
/// </summary>
/// <remarks>
/// Сервисный логин и пароль хранятся только в зашифрованном виде (мастер-ключ).
/// Перед использованием для AD-операций значения расшифровываются.
/// </remarks>
internal class Domain : IAdGroupSource
{
    private const string ClassName = "WebShelf.Classes.DC.Domain";

    /// <summary>
    /// Имя домена (FQDN), например: "company.local".
    /// </summary>
    internal string Name { get; }

    /// <summary>
    /// Имя сервисной учётной записи для подключения к Active Directory
    /// в открытом виде (расшифровывается при каждом обращении).
    /// </summary>
    internal string User => GetDecryptedUser();

    /// <summary>
    /// LDAP-путь к корню домена (используется при поиске объектов).
    /// </summary>
    internal string Path { get; }

    /// <summary>
    /// Зашифрованное имя сервисной учётной записи (мастер-ключ).
    /// </summary>
    private readonly string _encryptedUser;

    /// <summary>
    /// Зашифрованный пароль сервисной учётной записи (мастер-ключ).
    /// </summary>
    private readonly string _encryptedPassword;

    /// <summary>
    /// Короткий префикс InstanceId (12 символов, нижний регистр) для имён AD-групп
    /// WebShelf-{id}-*. Передаётся явно — класс не зависит от хранилища Data.
    /// </summary>
    private readonly string _instanceIdShort;

    /// <summary>
    /// Имена групп безопасности, необходимых для функционирования WebShelf.
    /// Формируется при старте приложения методом <see cref="FillRequiredGroupsFromTemplates"/>
    /// из шаблонов, передаваемых вызывающей стороной (строятся по каталогу ролей —
    /// <c>AppRoleCatalog.GetGroupNameTemplates()</c>). До формирования проверка
    /// и создание групп не выполняются.
    /// </summary>
    private readonly List<string> _requiredGroups = [];

    /// <summary>
    /// Заполнитель короткого префикса InstanceId в шаблонах имён групп.
    /// </summary>
    internal const string InstanceIdShortPlaceholder = "{InstanceIdShort}";

    /// <summary>
    /// Сформированный список имен групп безопасности, необходимых для функционирования
    /// (только чтение). Наполняется методом <see cref="FillRequiredGroupsFromTemplates"/>;
    /// до формирования список пуст.
    /// </summary>
    internal IReadOnlyList<string> RequiredGroups => _requiredGroups;

    /// <summary>
    /// Создаёт экземпляр класса <see cref="Domain"/>.
    /// Параметры <paramref name="encryptedUser"/> и <paramref name="encryptedPassword"/>
    /// должны быть уже зашифрованы мастер-ключом (<see cref="EncryptionService"/>).
    /// Перед проверками значения расшифровываются; в поля сохраняются зашифрованные данные.
    /// Принадлежность пользователя к WebShelf проверяется через членство в AD-группе
    /// <c>WebShelf-{InstanceIdShort}-Users</c>.
    /// </summary>
    /// <param name="domain">Имя домена (FQDN).</param>
    /// <param name="instanceIdShort">Короткий префикс InstanceId (12 символов, нижний регистр)
    /// для имён AD-групп WebShelf-{id}-*. Передаётся явно — класс не зависит от хранилища Data.</param>
    /// <param name="encryptedUser">Зашифрованное имя сервисной учётной записи (Base64).</param>
    /// <param name="encryptedPassword">Зашифрованный пароль сервисной учётной записи (Base64).</param>
    /// <exception cref="ArgumentException">
    /// Возникает, если имя домена пустое, либо после расшифровки логин/пароль пустые
    /// или логин не удаётся привести к формату username@domain.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Возникает, если мастер-ключ недоступен или расшифровка не удалась.
    /// </exception>
    internal Domain(string domain, string instanceIdShort, string encryptedUser, string encryptedPassword)
    {
        const string method = ".ctor";

        if (string.IsNullOrWhiteSpace(domain))
            throw new ArgumentException("Имя домена не может быть пустым.", nameof(domain));
        if (string.IsNullOrWhiteSpace(instanceIdShort))
            throw new ArgumentException("Короткий префикс InstanceId не может быть пустым.", nameof(instanceIdShort));
        if (string.IsNullOrWhiteSpace(encryptedUser))
            throw new ArgumentException("Зашифрованное имя пользователя не может быть пустым.", nameof(encryptedUser));
        if (string.IsNullOrWhiteSpace(encryptedPassword))
            throw new ArgumentException("Зашифрованный пароль не может быть пустым.", nameof(encryptedPassword));

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        if (masterKey is null)
        {
            Log.Error(
                "Мастер-ключ недоступен в конструкторе Domain. Class={Class}, Method={Method}",
                ClassName, method);
            throw new InvalidOperationException("Мастер-ключ шифрования недоступен.");
        }

        // Перед проверками расшифровываем
        string plainUser;
        string plainPassword;
        try
        {
            plainUser = EncryptionService.Decrypt(encryptedUser.Trim(), masterKey);
            plainPassword = EncryptionService.Decrypt(encryptedPassword.Trim(), masterKey);
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Не удалось расшифровать учётные данные в конструкторе Domain. Class={Class}, Method={Method}",
                ClassName, method);
            throw new InvalidOperationException("Не удалось расшифровать учётные данные сервисной записи.", ex);
        }

        if (string.IsNullOrWhiteSpace(plainUser))
            throw new ArgumentException("Имя пользователя после расшифровки пустое.", nameof(encryptedUser));
        if (string.IsNullOrWhiteSpace(plainPassword))
            throw new ArgumentException("Пароль после расшифровки пустой.", nameof(encryptedPassword));

        string? userName = NormalizeUserName(plainUser, domain);
        if (string.IsNullOrWhiteSpace(userName))
            throw new ArgumentException($"Имя пользователя '{plainUser}' не удалось привести к формату username@domain.", nameof(encryptedUser));

        Name = domain.Trim();
        _instanceIdShort = instanceIdShort.Trim();

        // Перед записью в поля — шифруем (нормализованный логин и пароль)
        try
        {
            _encryptedUser = EncryptionService.Encrypt(userName.Trim(), masterKey);
            _encryptedPassword = EncryptionService.Encrypt(plainPassword, masterKey);
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Не удалось зашифровать учётные данные перед сохранением. Class={Class}, Method={Method}",
                ClassName, method);
            throw new InvalidOperationException("Не удалось зашифровать учётные данные сервисной записи.", ex);
        }

        // LDAP-путь: DNS-имя домена + DN корня.
        // Формат LDAP://domain/DC=... надёжнее serverless-привязки LDAP://DC=...
        // (иначе ADSI часто возвращает 0x8007054B — «домен не существует»).
        IEnumerable<string> dcParts = Name
            .Split('.', StringSplitOptions.RemoveEmptyEntries)
            .Select(p => $"DC={p}");
        Path = $"LDAP://{Name}/{string.Join(",", dcParts)}";

        Log.Debug(
            "Создан экземпляр Domain. Class={Class}, Method={Method}, Domain={Domain}, User={User}, Path={Path}",
            ClassName, method, Name, "SystemAccount", Path);
    }

    /// <summary>
    /// Возвращает расшифрованное имя сервисной учётной записи.
    /// </summary>
    /// <returns>Логин в формате username@domain.</returns>
    /// <exception cref="InvalidOperationException">Если мастер-ключ недоступен или расшифровка не удалась.</exception>
    internal string GetDecryptedUser()
    {
        const string method = nameof(GetDecryptedUser);

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        if (masterKey is null)
        {
            Log.Error(
                "Мастер-ключ недоступен при расшифровке User. Class={Class}, Method={Method}",
                ClassName, method);
            throw new InvalidOperationException("Мастер-ключ шифрования недоступен.");
        }

        try
        {
            return EncryptionService.Decrypt(_encryptedUser, masterKey);
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка расшифровки User. Class={Class}, Method={Method}",
                ClassName, method);
            throw new InvalidOperationException("Не удалось расшифровать имя сервисной учётной записи.", ex);
        }
    }

    /// <summary>
    /// Возвращает расшифрованный пароль сервисной учётной записи.
    /// </summary>
    /// <returns>Пароль в открытом виде.</returns>
    /// <exception cref="InvalidOperationException">Если мастер-ключ недоступен или расшифровка не удалась.</exception>
    internal string GetDecryptedPassword()
    {
        const string method = nameof(GetDecryptedPassword);

        byte[]? masterKey = EncryptionService.EnsureMasterKey();
        if (masterKey is null)
        {
            Log.Error(
                "Мастер-ключ недоступен при расшифровке Password. Class={Class}, Method={Method}",
                ClassName, method);
            throw new InvalidOperationException("Мастер-ключ шифрования недоступен.");
        }

        try
        {
            return EncryptionService.Decrypt(_encryptedPassword, masterKey);
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка расшифровки Password. Class={Class}, Method={Method}",
                ClassName, method);
            throw new InvalidOperationException("Не удалось расшифровать пароль сервисной учётной записи.", ex);
        }
    }

    /// <summary>
    /// Проверяет учётные данные пользователя в Active Directory.
    /// При <paramref name="checkUsersGroup"/> = <see langword="true"/> дополнительно проверяет
    /// членство в группе <c>WebShelf-{InstanceIdShort}-Users</c>.
    /// Параметры <paramref name="username"/> и <paramref name="password"/> передаются в открытом виде
    /// (как ввёл пользователь или как подготовлены при старте сервиса).
    /// </summary>
    internal bool ValidateAdCredentials(string username, string password, bool checkUsersGroup = true)
    {
        const string method = nameof(ValidateAdCredentials);

        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password))
        {
            Log.Warning(
                "Пустые учётные данные при проверке. Class={Class}, Method={Method}, UsernameEmpty={UsernameEmpty}, PasswordEmpty={PasswordEmpty}",
                ClassName, method,
                string.IsNullOrWhiteSpace(username),
                string.IsNullOrEmpty(password));
            return false;
        }

        string normalizedUser = (NormalizeUserName(username, Name) ?? string.Empty).Trim();
        // В логах не светим реальные имена учётных записей
        string accountLabel = checkUsersGroup ? "UserAccount" : "SystemAccount";

        try
        {
            Log.Debug(
                "Начало проверки учётных данных. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}, CheckUsersGroup={CheckUsersGroup}",
                ClassName, method, Name, accountLabel, checkUsersGroup);

            // Проверка логина/пароля (контекст без сервисной учётки).
            // Signing + Sealing: подпись и шифрование LDAP-канала —
            // защита от перехвата учётных данных при NTLM-fallback.
            using (PrincipalContext authContext = new(ContextType.Domain, Name))
            {
                if (!authContext.ValidateCredentials(
                        normalizedUser,
                        password,
                        ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing))
                {
                    Log.Warning(
                        "Неверные учётные данные. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}",
                        ClassName, method, Name, accountLabel);
                    return false;
                }
            }

            // Без проверки группы — достаточно валидных учётных данных (сервисная учётка)
            if (!checkUsersGroup)
            {
                Log.Information(
                    "Учётные данные подтверждены (без проверки группы Users). Class={Class}, Method={Method}, Domain={Domain}, Username={Username}",
                    ClassName, method, Name, accountLabel);
                return true;
            }

            string usersGroupName = $"WebShelf-{_instanceIdShort}-Users";
            string serviceUser = GetDecryptedUser();
            string servicePassword = GetDecryptedPassword();

            using PrincipalContext context = new(ContextType.Domain, Name, serviceUser, servicePassword);

            int atIndex = normalizedUser.IndexOf('@');
            string samAccountName = (atIndex > 0) ? normalizedUser[..atIndex] : normalizedUser;

            using UserPrincipal? user =
                UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, samAccountName) ??
                UserPrincipal.FindByIdentity(context, IdentityType.UserPrincipalName, normalizedUser);

            if (user is null)
            {
                Log.Warning(
                    "Пользователь не найден в AD после успешной аутентификации. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}",
                    ClassName, method, Name, accountLabel);
                return false;
            }

            using GroupPrincipal? group =
                GroupPrincipal.FindByIdentity(context, IdentityType.SamAccountName, usersGroupName) ??
                GroupPrincipal.FindByIdentity(context, IdentityType.Name, usersGroupName);

            if (group is null)
            {
                Log.Error(
                    "Группа {Group} не найдена в AD. Class={Class}, Method={Method}, Domain={Domain}",
                    usersGroupName, ClassName, method, Name);
                return false;
            }

            bool allowed = user.IsMemberOf(group);

            if (allowed)
            {
                Log.Information(
                    "Учётные данные и членство в группе Users подтверждены. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}",
                    ClassName, method, Name, accountLabel);
            }
            else
            {
                Log.Warning(
                    "Пользователь не состоит в группе {Group}. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}",
                    usersGroupName, ClassName, method, Name, accountLabel);
            }

            return allowed;
        }
        catch (PrincipalServerDownException ex)
        {
            Log.Error(ex,
                "Контроллер домена недоступен при проверке учётных данных. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}",
                ClassName, method, Name, accountLabel);

            throw new InvalidOperationException(
                "Не удалось подключиться к Active Directory.",
                new InvalidOperationException($"Сервер: {Name}", ex));
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка при проверке учётных данных. Class={Class}, Method={Method}, Domain={Domain}, Username={Username}",
                ClassName, method, Name, accountLabel);

            throw new InvalidOperationException(
                "Ошибка при проверке учётных данных в Active Directory.", ex);
        }
    }

    /// <summary>
    /// Подставляет в шаблон имени группы короткий префикс InstanceId вместо
    /// заполнителя <see cref="InstanceIdShortPlaceholder"/>. Замена выполняется
    /// для всех вхождений заполнителя и без учёта его регистра; шаблон без
    /// заполнителя возвращается без изменений (пробелы по краям обрезаются).
    /// Метод выполняет только подстановку: обнаружение опечаток в заполнителе
    /// выполняет <see cref="FillRequiredGroupsFromTemplates"/>.
    /// </summary>
    /// <param name="template">Шаблон имени группы, например WebShelf-{InstanceIdShort}-Administrator.</param>
    /// <param name="instanceIdShort">Короткий префикс InstanceId (12 символов, нижний регистр).</param>
    /// <returns>Имя группы с выполненной подстановкой.</returns>
    /// <exception cref="ArgumentException">Если шаблон или префикс пустые.</exception>
    internal static string ExpandGroupTemplate(string template, string instanceIdShort)
    {
        if (string.IsNullOrWhiteSpace(template))
            throw new ArgumentException("Шаблон имени группы не может быть пустым.", nameof(template));
        if (string.IsNullOrWhiteSpace(instanceIdShort))
            throw new ArgumentException("Короткий префикс InstanceId не может быть пустым.", nameof(instanceIdShort));

        return template.Trim().Replace(InstanceIdShortPlaceholder, instanceIdShort, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Формирует список групп безопасности, необходимых для функционирования WebShelf
    /// (<see cref="RequiredGroups"/>), из списка шаблонов имен: заполнитель
    /// <see cref="InstanceIdShortPlaceholder"/> в каждом шаблоне заменяется коротким
    /// префиксом InstanceId текущего экземпляра.
    /// Например: WebShelf-{InstanceIdShort}-Administrator → WebShelf-000000000000-Administrator.
    /// </summary>
    /// <param name="templates">Список шаблонов имен групп.</param>
    /// <returns>
    /// <see langword="true"/>, если список сформирован (в том числе из пустого списка
    /// шаблонов); <see langword="false"/> — если список шаблонов не задан или содержит
    /// пустые имена. Шаблоны с некорректным заполнителем пропускаются и на результат
    /// не влияют.
    /// </returns>
    /// <remarks>
    /// Предыдущее содержимое списка полностью заменяется. Дубликаты имен
    /// (без учёта регистра) отбрасываются. Шаблон, совсем не содержащий заполнителя,
    /// используется как имя группы без изменений, без предупреждений в логе.
    /// Шаблон с некорректным заполнителем (опечатка — например {InstanseIdShort} —
    /// либо лишняя или незакрытая фигурная скобка) в список не добавляется,
    /// в лог пишется предупреждение.
    /// Вызывается при старте приложения до <see cref="EnsureRequiredGroupsExist"/>.
    /// </remarks>
    internal bool FillRequiredGroupsFromTemplates(IEnumerable<string> templates)
    {
        const string method = nameof(FillRequiredGroupsFromTemplates);

        if (templates is null)
        {
            Log.Error(
                "Список шаблонов имен групп не задан. Class={Class}, Method={Method}",
                ClassName, method);
            return false;
        }

        try
        {
            List<string> groupNames = [];

            foreach (string template in templates)
            {
                // Пустой шаблон — ошибка формирования списка: состав групп неизвестен
                if (string.IsNullOrWhiteSpace(template))
                {
                    Log.Error(
                        "Список шаблонов содержит пустое имя группы. Class={Class}, Method={Method}",
                        ClassName, method);
                    return false;
                }

                string trimmed = template.Trim();
                string groupName = ExpandGroupTemplate(trimmed, _instanceIdShort);

                if (groupName.Contains('{') || groupName.Contains('}'))
                {
                    // После подстановки остались фигурные скобки — заполнитель написан
                    // с опечаткой (например, {InstanseIdShort}) либо искажён. Имя не
                    // привязано к экземпляру, поэтому в список групп его не включаем
                    Log.Warning(
                        "Шаблон {Template} содержит некорректный заполнитель (ожидается {Placeholder}); имя в список групп не добавлено. Class={Class}, Method={Method}",
                        trimmed, InstanceIdShortPlaceholder, ClassName, method);
                    continue;
                }

                // Шаблон корректен: либо содержал заполнитель (заменён), либо совсем
                // без заполнителя — такое имя используется как есть, без предупреждения
                groupNames.Add(groupName);
            }

            // Дубликаты (без учёта регистра) убираем: повторная проверка одной группы бессмысленна
            _requiredGroups.Clear();
            _requiredGroups.AddRange(groupNames.Distinct(StringComparer.OrdinalIgnoreCase));

            Log.Information(
                "Список групп безопасности сформирован из шаблонов. Count={Count}. Class={Class}, Method={Method}",
                _requiredGroups.Count, ClassName, method);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(
                ex,
                "Ошибка формирования списка групп из шаблонов. Class={Class}, Method={Method}",
                ClassName, method);
            return false;
        }
    }

    /// <summary>
    /// Обеспечивает наличие в домене групп безопасности, необходимых для
    /// функционирования WebShelf: проверяет существование каждой группы из списка
    /// (<see cref="_requiredGroups"/>) и создаёт отсутствующие.
    /// Проверка и создание выполняются от имени сервисной учётной записи,
    /// заданной в конфигурационном файле Server.conf.
    /// </summary>
    /// <remarks>
    /// Список групп формируется при старте приложения методом
    /// <see cref="FillRequiredGroupsFromTemplates"/> из шаблонов каталога ролей.
    /// Пустой список считается корректным состоянием — метод сразу возвращает
    /// <see langword="true"/> без обращения к AD.
    /// Группы создаются как группы безопасности, локальные в домене (Domain Local),
    /// с уникальным в домене именем (sAMAccountName); описание связывает группу
    /// с экземпляром WebShelf.
    /// </remarks>
    /// <returns>
    /// <see langword="true"/>, если все группы уже существуют или успешно созданы
    /// (в том числе при пустом списке); <see langword="false"/> — если список содержит
    /// пустые имена либо возникла ошибка при проверке или создании группы.
    /// </returns>
    internal bool EnsureRequiredGroupsExist()
    {
        const string method = nameof(EnsureRequiredGroupsExist);

        // Пустые имена в списке — ошибка его заполнения: требуемый состав групп
        // неизвестен, продолжать нельзя
        if (_requiredGroups.Any(string.IsNullOrWhiteSpace))
        {
            Log.Error(
                "Список групп безопасности содержит пустое имя. Class={Class}, Method={Method}",
                ClassName, method);
            return false;
        }

        // Дубликаты (без учёта регистра) убираем: повторная проверка одной группы бессмысленна
        List<string> requiredGroups = _requiredGroups
            .Select(name => name.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (requiredGroups.Count == 0)
        {
            Log.Information(
                "Список групп безопасности пуст — проверка и создание не требуются. Class={Class}, Method={Method}",
                ClassName, method);
            return true;
        }

        try
        {
            string serviceUser = GetDecryptedUser();
            string servicePassword = GetDecryptedPassword();

            // Работа с объектами AD — от имени сервисной учётной записи из конфигурации;
            // реальное имя учётной записи в логах не фигурирует
            using PrincipalContext context = new(ContextType.Domain, Name, serviceUser, servicePassword);

            foreach (string groupName in requiredGroups)
            {
                // Ищем по sAMAccountName и по имени (регистр не важен) —
                // так же ищется группа Users в ValidateAdCredentials
                using GroupPrincipal? existingGroup =
                    GroupPrincipal.FindByIdentity(context, IdentityType.SamAccountName, groupName) ??
                    GroupPrincipal.FindByIdentity(context, IdentityType.Name, groupName);

                if (existingGroup is not null)
                {
                    Log.Debug(
                        "Группа {Group} уже существует. Class={Class}, Method={Method}, Domain={Domain}",
                        groupName, ClassName, method, Name);
                    continue;
                }

                try
                {
                    // Доменно-локальная (Domain Local) группа безопасности.
                    // В перечислении GroupScope нет члена DomainLocal: доменно-локальная
                    // область представлена членом Local — при ContextType.Domain
                    // создаётся именно Domain Local группа (поддерживается в AD DS).
                    // Описание связывает группу с экземпляром WebShelf
                    using GroupPrincipal newGroup = new GroupPrincipal(context, groupName)
                    {
                        IsSecurityGroup = true,
                        GroupScope = GroupScope.Local,
                        Description = $"Группа безопасности WebShelf (экземпляр {_instanceIdShort})"
                    };
                    newGroup.Save();
                }
                catch (PrincipalExistsException ex)
                {
                    // Группа создана параллельно между проверкой и сохранением —
                    // считаем её существующей
                    Log.Warning(
                        ex,
                        "Группа {Group} уже существует (создана параллельно). Class={Class}, Method={Method}, Domain={Domain}",
                        groupName, ClassName, method, Name);
                    continue;
                }

                Log.Information(
                    "Создана группа безопасности {Group}. Class={Class}, Method={Method}, Domain={Domain}",
                    groupName, ClassName, method, Name);
            }

            Log.Information(
                "Все группы безопасности ({Count} шт.) существуют или созданы. Class={Class}, Method={Method}, Domain={Domain}",
                requiredGroups.Count, ClassName, method, Name);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(
                ex,
                "Ошибка при проверке или создании групп безопасности AD. Class={Class}, Method={Method}, Domain={Domain}",
                ClassName, method, Name);
            return false;
        }
    }

    /// <summary>
    /// Возвращает расширенное имя группы WebShelf по суффиксу: имя строится
    /// напрямую из <paramref name="suffix"/> и короткого префикса InstanceId
    /// текущего экземпляра, без обращения к AD. Реализация <see cref="IAdGroupSource"/>
    /// для резолвера ролей.
    /// </summary>
    /// <param name="suffix">Суффикс группы: "Users" либо суффикс ролевой группы.</param>
    /// <returns>Имя вида WebShelf-{InstanceIdShort}-{suffix}; <see langword="null"/> при ошибке.</returns>
    internal string? GetExpandedGroupName(string suffix)
    {
        const string method = nameof(GetExpandedGroupName);

        try
        {
            if (string.IsNullOrWhiteSpace(suffix))
            {
                Log.Warning(
                    "Пустой суффикс группы при построении имени. Class={Class}, Method={Method}",
                    ClassName, method);
                return null;
            }

            return $"WebShelf-{_instanceIdShort}-{suffix.Trim()}";
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Ошибка при построении имени группы. Class={Class}, Method={Method}", ClassName, method);
            return null;
        }
    }

    /// <summary>
    /// Возвращает прямые группы, в которых состоит пользователь
    /// (вложенные группы не учитываются — аналогично проверке группы Users при входе).
    /// Для каждой группы берётся sAMAccountName, при его отсутствии — Name.
    /// Реализация <see cref="IAdGroupSource"/> для резолвера ролей.
    /// </summary>
    /// <param name="samAccountName">Имя учётной записи (sAMAccountName, без доменной части).</param>
    /// <returns>
    /// Список имён групп. Пустой список — пользователь найден, но не состоит ни в одной
    /// группе (в том числе пользователь удалён из AD); <see langword="null"/> — ошибка
    /// обращения к AD (резолвер в этом случае не меняет известное состояние).
    /// </returns>
    internal IReadOnlyList<string>? GetUserGroupNames(string samAccountName)
    {
        const string method = nameof(GetUserGroupNames);

        try
        {
            if (string.IsNullOrWhiteSpace(samAccountName))
            {
                Log.Warning(
                    "Пустое имя пользователя при получении групп. Class={Class}, Method={Method}",
                    ClassName, method);
                return null;
            }

            string serviceUser = GetDecryptedUser();
            string servicePassword = GetDecryptedPassword();

            // Работа с объектами AD — от имени сервисной учётной записи;
            // реальное имя учётной записи в логах не фигурирует
            using PrincipalContext context = new(ContextType.Domain, Name, serviceUser, servicePassword);

            using UserPrincipal? user =
                UserPrincipal.FindByIdentity(context, IdentityType.SamAccountName, samAccountName.Trim()) ??
                UserPrincipal.FindByIdentity(context, IdentityType.UserPrincipalName, $"{samAccountName.Trim()}@{Name}");

            if (user is null)
            {
                // Пользователь удалён из AD: считаем, что он не состоит ни в одной группе
                // (пустой список), а не ошибкой — с точки зрения ролевой модели это
                // потеря всех групп, включая Users
                Log.Warning(
                    "Пользователь не найден в AD при получении групп: возвращён пустой список. Class={Class}, Method={Method}",
                    ClassName, method);
                return [];
            }

            // GetGroups() — только прямые группы, в порядке выдачи AD
            using PrincipalSearchResult<Principal> result = user.GetGroups();

            List<string> groupNames = [];

            foreach (Principal group in result)
            {
                using Principal current = group;

                // sAMAccountName — каноническое имя группы; у некоторых объектов AD
                // оно пустое — тогда берём Name
                string? name = current.SamAccountName;
                if (string.IsNullOrWhiteSpace(name))
                {
                    name = current.Name;
                }

                if (!string.IsNullOrWhiteSpace(name))
                {
                    groupNames.Add(name);
                }
            }

            Log.Debug(
                "Прямые группы пользователя получены. Count={Count}. Class={Class}, Method={Method}",
                groupNames.Count, ClassName, method);

            return groupNames;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка при получении групп пользователя. Class={Class}, Method={Method}",
                ClassName, method);
            return null;
        }
    }

    /// <summary>
    /// Возвращает sAMAccountName участников группы (прямых членов, без вложенных групп).
    /// Используется при старте для проверки требования наличия минимум одного администратора.
    /// </summary>
    /// <param name="groupName">Имя группы (sAMAccountName или Name, регистр не важен).</param>
    /// <returns>
    /// Список имён учётных записей; пустой список — в группе нет участников;
    /// <see langword="null"/> — группа не найдена или ошибка обращения к AD.
    /// </returns>
    internal List<string>? GetGroupMemberNames(string groupName)
    {
        const string method = nameof(GetGroupMemberNames);

        try
        {
            if (string.IsNullOrWhiteSpace(groupName))
            {
                Log.Warning(
                    "Пустое имя группы при получении участников. Class={Class}, Method={Method}",
                    ClassName, method);
                return null;
            }

            string serviceUser = GetDecryptedUser();
            string servicePassword = GetDecryptedPassword();

            using PrincipalContext context = new(ContextType.Domain, Name, serviceUser, servicePassword);

            using GroupPrincipal? group =
                GroupPrincipal.FindByIdentity(context, IdentityType.SamAccountName, groupName.Trim()) ??
                GroupPrincipal.FindByIdentity(context, IdentityType.Name, groupName.Trim());

            if (group is null)
            {
                Log.Warning(
                    "Группа {Group} не найдена при получении участников. Class={Class}, Method={Method}",
                    groupName, ClassName, method);
                return null;
            }

            using PrincipalSearchResult<Principal> members = group.GetMembers();

            List<string> names = [];

            foreach (Principal member in members)
            {
                using Principal current = member;

                // Учитываются только пользователи: группы внутри группы не считаются
                // участниками (прямое членство)
                if (current is UserPrincipal && !string.IsNullOrWhiteSpace(current.SamAccountName))
                {
                    names.Add(current.SamAccountName);
                }
            }

            Log.Debug(
                "Участники группы получены. Group={Group}, Count={Count}. Class={Class}, Method={Method}",
                groupName, names.Count, ClassName, method);

            return names;
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка при получении участников группы. Class={Class}, Method={Method}",
                ClassName, method);
            return null;
        }
    }

    /// <summary>
    /// Приводит имя пользователя к формату <c>username@domainname</c>.
    /// Имя домена передаётся явно — класс не зависит от хранилища Data.
    /// </summary>
    internal static string? NormalizeUserName(string userName, string domainName)
    {
        const string method = nameof(NormalizeUserName);

        try
        {
            if (string.IsNullOrWhiteSpace(userName))
            {
                WarnInvalid("Не задано имя пользователя.");
                return null;
            }

            string domain = domainName.Trim();
            if (domain.Length == 0)
            {
                WarnInvalid("Не задано имя домена.");
                return null;
            }

            string user = userName.Trim();

            // Нет разделителей — просто добавляем домен.
            if (user.IndexOfAny(['@', '\\']) < 0) return $"{user}@{domain}";

            // Формат UPN: user@domain
            if (user.Contains('@'))
            {
                if (user.IndexOf('@') == user.LastIndexOf('@') &&
                    user.EndsWith($"@{domain}", StringComparison.OrdinalIgnoreCase) &&
                    user.IndexOf('@') > 0 &&
                    user.IndexOf('@') < user.Length - 1)
                {
                    return user;
                }
                WarnInvalid("Некорректное имя пользователя.");
                return null;
            }

            // Формат DOMAIN\user
            int slashIndex = user.IndexOf('\\');
            if (slashIndex <= 0 || slashIndex >= user.Length - 1)
            {
                WarnInvalid("Некорректное имя пользователя.");
                return null;
            }

            string bareUser = user[(slashIndex + 1)..].Trim();
            if (bareUser.Length == 0)
            {
                WarnInvalid("Некорректное имя пользователя.");
                return null;
            }

            return $"{bareUser}@{domain}";
        }
        catch (Exception ex)
        {
            Log.Error(ex,
                "Ошибка при нормализации имени пользователя. Class={Class}, Method={Method}, UserName={UserName}",
                ClassName, method, "UserAccount");
            return null;
        }

        void WarnInvalid(string reason) =>
            Log.Warning(
                "{Reason} Class={Class}, Method={Method}, UserName={UserName}",
                reason, ClassName, method, "UserAccount");
    }
}
