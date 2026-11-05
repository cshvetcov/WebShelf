using System.DirectoryServices.AccountManagement;
using Serilog;

namespace WebShelf.Classes.DC;

/// <summary>
/// Управляет группами безопасности Active Directory, необходимыми для
/// функционирования WebShelf: формирует список групп из шаблонов имён
/// (<see cref="FillRequiredGroupsFromTemplates"/>) и обеспечивает их наличие
/// в домене — проверяет существование каждой группы и создаёт отсутствующие
/// от имени сервисной учётной записи (<see cref="EnsureRequiredGroupsExist"/>).
/// Контекст подключения к AD (имя домена, доступ к сервисной учётной записи)
/// и короткий префикс InstanceId передаются явно через конструктор — класс
/// не зависит от <see cref="Domain"/> и хранилища Data.
/// Используется в браузерном приложении WebShelf для работы
/// с документацией в проектной организации промышленного и гражданского строительства.
/// </summary>
/// <remarks>
/// Класс выделен из <see cref="Domain"/> механическим переносом (шаг 7 дорожной
/// карты декомпозиции): Domain остаётся зоной «сервисные учётные данные,
/// валидация AD, запросы членства». Расширенные имена групп для ролевой модели
/// по-прежнему строит <see cref="Domain"/> (реализация <see cref="IAdGroupSource"/>,
/// контракт не изменился); в шаблонах имён используется заполнитель
/// <see cref="AdNames.InstanceIdShortPlaceholder"/>.
/// </remarks>
internal sealed class AdGroupManager
{
    private const string ClassName = "WebShelf.Classes.DC.AdGroupManager";

    /// <summary>
    /// Имя домена (FQDN), например: "company.local". Передаётся явно —
    /// класс не зависит от <see cref="Domain"/>.
    /// </summary>
    private readonly string _domainName;

    /// <summary>
    /// Короткий префикс InstanceId (12 символов, нижний регистр) для имён AD-групп
    /// WebShelf-{id}-*. Передаётся явно — класс не зависит от хранилища Data.
    /// </summary>
    private readonly string _instanceIdShort;

    /// <summary>
    /// Возвращает расшифрованное имя сервисной учётной записи для подключения
    /// к Active Directory. Передан явно (делегат <see cref="Domain.GetDecryptedUser"/>):
    /// учётные данные расшифровываются при каждом обращении, как в <see cref="Domain"/>.
    /// </summary>
    private readonly Func<string> _getServiceUser;

    /// <summary>
    /// Возвращает расшифрованный пароль сервисной учётной записи. Передан явно
    /// (делегат <see cref="Domain.GetDecryptedPassword"/>).
    /// </summary>
    private readonly Func<string> _getServicePassword;

    /// <summary>
    /// Имена групп безопасности, необходимых для функционирования WebShelf.
    /// Формируется при старте приложения методом <see cref="FillRequiredGroupsFromTemplates"/>
    /// из шаблонов, передаваемых вызывающей стороной (группа доступа Users — суффикс
    /// <see cref="Domain.UsersGroupSuffix"/>, ролевые группы — <c>RoleCatalog.BuildGroupNameTemplates()</c>).
    /// До формирования проверка и создание групп не выполняются.
    /// </summary>
    private readonly List<string> _requiredGroups = [];

    /// <summary>
    /// Сформированный список имен групп безопасности, необходимых для функционирования
    /// (только чтение). Наполняется методом <see cref="FillRequiredGroupsFromTemplates"/>;
    /// до формирования список пуст.
    /// </summary>
    internal IReadOnlyList<string> RequiredGroups => _requiredGroups;

    /// <summary>
    /// Создаёт экземпляр класса <see cref="AdGroupManager"/>. Контекст подключения
    /// к AD передаётся явно: имя домена, делегаты расшифровки сервисной учётной
    /// записи и короткий префикс InstanceId — «полдомена» (<see cref="Domain"/> целиком)
    /// класс не получает. Конструктор не выполняет обращений к AD, реестру и DPAPI
    /// и не пишет в лог.
    /// </summary>
    /// <param name="domainName">Имя домена (FQDN).</param>
    /// <param name="instanceIdShort">Короткий префикс InstanceId (12 символов, нижний регистр)
    /// для имён AD-групп WebShelf-{id}-*.</param>
    /// <param name="getServiceUser">Делегат расшифровки имени сервисной учётной записи
    /// (<see cref="Domain.GetDecryptedUser"/>).</param>
    /// <param name="getServicePassword">Делегат расшифровки пароля сервисной учётной записи
    /// (<see cref="Domain.GetDecryptedPassword"/>).</param>
    /// <exception cref="ArgumentException">
    /// Возникает, если имя домена или короткий префикс InstanceId пустые.
    /// </exception>
    /// <exception cref="ArgumentNullException">
    /// Возникает, если делегаты получения учётных данных не заданы.
    /// </exception>
    internal AdGroupManager(string domainName, string instanceIdShort, Func<string> getServiceUser, Func<string> getServicePassword)
    {
        if (string.IsNullOrWhiteSpace(domainName))
            throw new ArgumentException("Имя домена не может быть пустым.", nameof(domainName));
        if (string.IsNullOrWhiteSpace(instanceIdShort))
            throw new ArgumentException("Короткий префикс InstanceId не может быть пустым.", nameof(instanceIdShort));
        ArgumentNullException.ThrowIfNull(getServiceUser);
        ArgumentNullException.ThrowIfNull(getServicePassword);

        _domainName = domainName.Trim();
        _instanceIdShort = instanceIdShort.Trim();
        _getServiceUser = getServiceUser;
        _getServicePassword = getServicePassword;
    }

    /// <summary>
    /// Формирует список групп безопасности, необходимых для функционирования WebShelf
    /// (<see cref="RequiredGroups"/>), из списка шаблонов имен: заполнитель
    /// <see cref="AdNames.InstanceIdShortPlaceholder"/> в каждом шаблоне заменяется коротким
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
                string groupName = AdNames.ExpandGroupTemplate(trimmed, _instanceIdShort);

                if (groupName.Contains('{') || groupName.Contains('}'))
                {
                    // После подстановки остались фигурные скобки — заполнитель написан
                    // с опечаткой (например, {InstanseIdShort}) либо искажён. Имя не
                    // привязано к экземпляру, поэтому в список групп его не включаем
                    Log.Warning(
                        "Шаблон {Template} содержит некорректный заполнитель (ожидается {Placeholder}); имя в список групп не добавлено. Class={Class}, Method={Method}",
                        trimmed, AdNames.InstanceIdShortPlaceholder, ClassName, method);
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
            string serviceUser = _getServiceUser();
            string servicePassword = _getServicePassword();

            // Работа с объектами AD — от имени сервисной учётной записи из конфигурации;
            // реальное имя учётной записи в логах не фигурирует
            using PrincipalContext context = new(ContextType.Domain, _domainName, serviceUser, servicePassword);

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
                        groupName, ClassName, method, _domainName);
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
                        groupName, ClassName, method, _domainName);
                    continue;
                }

                Log.Information(
                    "Создана группа безопасности {Group}. Class={Class}, Method={Method}, Domain={Domain}",
                    groupName, ClassName, method, _domainName);
            }

            Log.Information(
                "Все группы безопасности ({Count} шт.) существуют или созданы. Class={Class}, Method={Method}, Domain={Domain}",
                requiredGroups.Count, ClassName, method, _domainName);

            return true;
        }
        catch (Exception ex)
        {
            Log.Error(
                ex,
                "Ошибка при проверке или создании групп безопасности AD. Class={Class}, Method={Method}, Domain={Domain}",
                ClassName, method, _domainName);
            return false;
        }
    }
}
