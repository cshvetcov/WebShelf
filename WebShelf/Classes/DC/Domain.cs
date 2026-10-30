using System.DirectoryServices.AccountManagement;
using Serilog;
using WebShelf.Classes.Service;

namespace WebShelf.Classes.DC;

/// <summary>
/// Представляет домен Active Directory и предоставляет метод
/// проверки учётных данных пользователя.
/// Используется в браузерном приложении WebShelf для работы
/// с документацией в проектной организации промышленного и гражданского строительства.
/// </summary>
/// <remarks>
/// Сервисный логин и пароль хранятся только в зашифрованном виде (мастер-ключ).
/// Перед использованием для AD-операций значения расшифровываются.
/// </remarks>
internal class Domain
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
    /// Создаёт экземпляр класса <see cref="Domain"/>.
    /// Параметры <paramref name="encryptedUser"/> и <paramref name="encryptedPassword"/>
    /// должны быть уже зашифрованы мастер-ключом (<see cref="EncryptionService"/>).
    /// Перед проверками значения расшифровываются; в поля сохраняются зашифрованные данные.
    /// Принадлежность пользователя к WebShelf проверяется через членство в AD-группе
    /// <c>WebShelf-{InstanceIdShort}-Users</c>.
    /// </summary>
    /// <param name="domain">Имя домена (FQDN).</param>
    /// <param name="encryptedUser">Зашифрованное имя сервисной учётной записи (Base64).</param>
    /// <param name="encryptedPassword">Зашифрованный пароль сервисной учётной записи (Base64).</param>
    /// <exception cref="ArgumentException">
    /// Возникает, если имя домена пустое, либо после расшифровки логин/пароль пустые
    /// или логин не удаётся привести к формату username@domain.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    /// Возникает, если мастер-ключ недоступен или расшифровка не удалась.
    /// </exception>
    internal Domain(string domain, string encryptedUser, string encryptedPassword)
    {
        const string method = ".ctor";

        if (string.IsNullOrWhiteSpace(domain))
            throw new ArgumentException("Имя домена не может быть пустым.", nameof(domain));
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

            string usersGroupName = $"WebShelf-{Data.InstanceIdShort}-Users";
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
    /// Приводит имя пользователя к формату <c>username@domainname</c>.
    /// Имя домена передаётся явно — класс не зависит от статического хранилища Data.
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
