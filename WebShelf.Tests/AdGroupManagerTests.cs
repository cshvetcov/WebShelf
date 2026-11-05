using WebShelf.Classes.DC;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты класса <see cref="AdGroupManager"/>: валидация аргументов конструктора,
/// формирование списка необходимых групп безопасности из шаблонов имён
/// (подстановка заполнителя {InstanceIdShort}, отбраковка шаблонов с опечаткой)
/// и обеспечение существования групп (пустой список, недоступность AD).
/// Кейсы формирования списка перенесены из DomainTests без изменения
/// проверяемого поведения: после выноса из Domain конструктору менеджера
/// не нужны мастер-ключ и DPAPI — тесты выполняются на любой платформе
/// (прецедент — AdNamesTests шага 2). Ветки живого AD (группа существует,
/// создана, создана параллельно) юнит-тестами не покрываются: проверка и
/// создание выполняются через PrincipalContext/GroupPrincipal, которые без
/// изменения производственного кода не подменяются; эти ветки закрываются
/// рантайм-смоуком на Windows.
/// </summary>
public class AdGroupManagerTests
{
    /// <summary>
    /// Создаёт менеджер групп с тестовым контекстом AD: домен, короткий префикс
    /// InstanceId и делегаты сервисной учётной записи с фиктивными значениями
    /// (в тестах без обращения к AD не расшифровываются).
    /// </summary>
    private static AdGroupManager CreateManager()
    {
        AdGroupManager manager = new(
            "company.local",
            "abcdef012345",
            () => "svc_webshelf@company.local",
            () => "TestPassword123!");

        return manager;
    }

    #region Конструктор

    /// <summary>
    /// Конструктор отклоняет пустое имя домена.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_EmptyDomain_ThrowsArgumentException(string? domainName)
    {
        Assert.Throws<ArgumentException>(() =>
            new AdGroupManager(domainName!, "abcdef012345", () => "user", () => "password"));
    }

    /// <summary>
    /// Конструктор отклоняет пустой короткий префикс InstanceId.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_EmptyInstanceIdShort_ThrowsArgumentException(string? instanceIdShort)
    {
        Assert.Throws<ArgumentException>(() =>
            new AdGroupManager("company.local", instanceIdShort!, () => "user", () => "password"));
    }

    /// <summary>
    /// Конструктор отклоняет незаданные делегаты получения сервисной учётной записи
    /// (новая публичная граница класса — fail-fast, прецедент ServerConfigParser
    /// и SecureCredentialsWriter).
    /// </summary>
    [Fact]
    public void Constructor_NullCredentialDelegates_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new AdGroupManager("company.local", "abcdef012345", null!, () => "password"));
        Assert.Throws<ArgumentNullException>(() =>
            new AdGroupManager("company.local", "abcdef012345", () => "user", null!));
    }

    #endregion

    #region FillRequiredGroupsFromTemplates

    /// <summary>
    /// Список групп формируется из шаблонов: заполнитель заменяется коротким
    /// префиксом InstanceId, пробелы обрезаются, регистр заполнителя не важен.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_SubstitutesInstanceIdShort()
    {
        AdGroupManager manager = CreateManager();

        string[] templates =
        [
            "WebShelf-{InstanceIdShort}-Users",
            " WebShelf-{InstanceIdShort}-Administrator ",
            "WebShelf-{INSTANCEIDSHORT}-Guest"
        ];

        Assert.True(manager.FillRequiredGroupsFromTemplates(templates));
        Assert.Equal(3, manager.RequiredGroups.Count);
        Assert.Contains("WebShelf-abcdef012345-Users", manager.RequiredGroups);
        Assert.Contains("WebShelf-abcdef012345-Administrator", manager.RequiredGroups);
        Assert.Contains("WebShelf-abcdef012345-Guest", manager.RequiredGroups);
    }

    /// <summary>
    /// Дубликаты шаблонов (без учёта регистра) дают одну группу в списке.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_DuplicateTemplates_Deduplicated()
    {
        AdGroupManager manager = CreateManager();

        string[] templates = ["WebShelf-{InstanceIdShort}-Users", "webshelf-{InstanceIdShort}-users"];

        Assert.True(manager.FillRequiredGroupsFromTemplates(templates));
        Assert.Single(manager.RequiredGroups);
    }

    /// <summary>
    /// Пустой список шаблонов — корректное состояние: список групп остаётся пустым.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_EmptyTemplates_ListStaysEmpty()
    {
        AdGroupManager manager = CreateManager();

        Assert.True(manager.FillRequiredGroupsFromTemplates(Array.Empty<string>()));
        Assert.Empty(manager.RequiredGroups);
    }

    /// <summary>
    /// Список шаблонов с пустым именем отклоняется, список групп не заполняется.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_InvalidTemplate_ReturnsFalse()
    {
        AdGroupManager manager = CreateManager();

        string[] templates = ["WebShelf-{InstanceIdShort}-Users", "   "];

        Assert.False(manager.FillRequiredGroupsFromTemplates(templates));
        Assert.Empty(manager.RequiredGroups);
    }

    /// <summary>
    /// Шаблон, совсем не содержащий заполнителя, используется как имя группы
    /// без изменений и попадает в список наряду с шаблонами с заполнителем.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_TemplateWithoutPlaceholder_UsedAsIs()
    {
        AdGroupManager manager = CreateManager();

        string[] templates = ["WebShelf-{InstanceIdShort}-Users", "WebShelf-Common-Group"];

        Assert.True(manager.FillRequiredGroupsFromTemplates(templates));
        Assert.Equal(2, manager.RequiredGroups.Count);
        Assert.Contains("WebShelf-abcdef012345-Users", manager.RequiredGroups);
        Assert.Contains("WebShelf-Common-Group", manager.RequiredGroups);
    }

    /// <summary>
    /// Шаблон с некорректным заполнителем (опечатка, незакрытая скобка, лишний
    /// заполнитель) в список групп не добавляется: в лог пишется предупреждение,
    /// формирование списка продолжается.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_InvalidPlaceholder_TemplateSkipped()
    {
        AdGroupManager manager = CreateManager();

        string[] templates =
        [
            "WebShelf-{InstanceIdShort}-Users",         // корректный шаблон
            "WebShelf-{InstanseIdShort}-Administrator", // опечатка в заполнителе
            "WebShelf-{InstanceIdShort-Manager",        // незакрытый заполнитель
            "WebShelf-{InstanceIdShort}-{Role}"         // второй заполнитель некорректен
        ];

        Assert.True(manager.FillRequiredGroupsFromTemplates(templates));
        Assert.Single(manager.RequiredGroups);
        Assert.Contains("WebShelf-abcdef012345-Users", manager.RequiredGroups);
    }

    /// <summary>
    /// Список шаблонов, состоящий только из шаблонов с опечаткой в заполнителе,
    /// не считается ошибкой: метод возвращает true, список групп остаётся пустым
    /// (по каждому шаблону пишется предупреждение).
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_AllTemplatesWithTypo_ListStaysEmpty()
    {
        AdGroupManager manager = CreateManager();

        string[] templates =
        [
            "WebShelf-{InstanseIdShort}-Administrator", // опечатка в заполнителе
            "WebShelf-{InstanceIdShort-Manager"         // незакрытый заполнитель
        ];

        Assert.True(manager.FillRequiredGroupsFromTemplates(templates));
        Assert.Empty(manager.RequiredGroups);
    }

    /// <summary>
    /// Смешанный список шаблонов: корректные шаблоны и шаблон без заполнителя
    /// попадают в список, шаблон с опечаткой пропускается, дубликаты убираются.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_MixedTemplates_OnlyValidAdded()
    {
        AdGroupManager manager = CreateManager();

        string[] templates =
        [
            "WebShelf-{InstanceIdShort}-Users",         // корректный шаблон
            "WebShelf-Common-Group",                    // без заполнителя
            "WebShelf-{InstanseIdShort}-Administrator", // опечатка — пропускается
            "webshelf-{InstanceIdShort}-USERS"          // дубликат первого
        ];

        Assert.True(manager.FillRequiredGroupsFromTemplates(templates));
        Assert.Equal(2, manager.RequiredGroups.Count);
        Assert.Contains("WebShelf-abcdef012345-Users", manager.RequiredGroups);
        Assert.Contains("WebShelf-Common-Group", manager.RequiredGroups);
    }

    /// <summary>
    /// Незаданный список шаблонов отклоняется, список групп не заполняется.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_NullTemplates_ReturnsFalse()
    {
        AdGroupManager manager = CreateManager();

        Assert.False(manager.FillRequiredGroupsFromTemplates(null!));
        Assert.Empty(manager.RequiredGroups);
    }

    /// <summary>
    /// Повторное формирование полностью заменяет предыдущее содержимое списка
    /// (документированное поведение): групп первого списка в результате нет.
    /// </summary>
    [Fact]
    public void FillRequiredGroupsFromTemplates_RepeatedFill_ReplacesPreviousList()
    {
        AdGroupManager manager = CreateManager();

        string[] firstTemplates = ["WebShelf-{InstanceIdShort}-Users"];
        string[] secondTemplates =
        [
            "WebShelf-{InstanceIdShort}-Administrator",
            "WebShelf-{InstanceIdShort}-Director"
        ];

        Assert.True(manager.FillRequiredGroupsFromTemplates(firstTemplates));
        Assert.True(manager.FillRequiredGroupsFromTemplates(secondTemplates));
        Assert.Equal(2, manager.RequiredGroups.Count);
        Assert.DoesNotContain("WebShelf-abcdef012345-Users", manager.RequiredGroups);
        Assert.Contains("WebShelf-abcdef012345-Administrator", manager.RequiredGroups);
        Assert.Contains("WebShelf-abcdef012345-Director", manager.RequiredGroups);
    }

    #endregion

    #region EnsureRequiredGroupsExist

    /// <summary>
    /// EnsureRequiredGroupsExist при пустом списке групп возвращает true
    /// без обращения к AD (учётные данные даже не запрашиваются).
    /// Список групп в настоящее время пуст — это корректное состояние.
    /// </summary>
    [Fact]
    public void EnsureRequiredGroupsExist_EmptyList_ReturnsTrue()
    {
        AdGroupManager manager = CreateManager();

        // Пустой список: метод завершается успешно до любых сетевых операций
        Assert.True(manager.EnsureRequiredGroupsExist());
    }

    /// <summary>
    /// Отказный сценарий дорожной карты («AD недоступен»): при непустом списке
    /// групп и недоступном контроллере домена метод возвращает false — исключение
    /// подключения попадает в общий обработчик и логируется, приложение
    /// останавливается по решению вызывающей стороны.
    /// На Windows подключение к несуществующему домену завершается исключением
    /// контроллера домена, на остальных ОС PrincipalContext выбрасывает
    /// PlatformNotSupportedException — обе ветки дают один и тот же результат.
    /// </summary>
    [Fact]
    public void EnsureRequiredGroupsExist_NonEmptyList_AdUnavailable_ReturnsFalse()
    {
        AdGroupManager manager = CreateManager();

        string[] templates = ["WebShelf-{InstanceIdShort}-Users"];

        Assert.True(manager.FillRequiredGroupsFromTemplates(templates));
        Assert.False(manager.EnsureRequiredGroupsExist());
    }

    #endregion
}
