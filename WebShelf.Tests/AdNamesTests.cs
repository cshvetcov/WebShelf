using WebShelf.Classes.DC;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты чистых функций имён AD (<see cref="AdNames"/>): нормализация имени
/// пользователя к формату username@domain и подстановка короткого префикса
/// InstanceId в шаблон имени группы. Кейсы перенесены из DomainTests без
/// изменения проверяемого поведения; дополнены граничными случаями.
/// </summary>
public class AdNamesTests
{
    #region NormalizeUserName

    /// <summary>
    /// Имя без разделителей дополняется доменом.
    /// </summary>
    [Theory]
    [InlineData("ivanov", "company.local", "ivanov@company.local")]
    [InlineData("IVANOV", "company.local", "IVANOV@company.local")]
    [InlineData(" ivanov ", "company.local", "ivanov@company.local")]
    [InlineData("ivanov", " company.local ", "ivanov@company.local")]
    [InlineData("o'connor", "company.local", "o'connor@company.local")]
    public void NormalizeUserName_BareName_AppendsDomain(string userName, string domainName, string expected)
    {
        string? result = AdNames.NormalizeUserName(userName, domainName);

        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Формат DOMAIN\user приводится к username@domain.
    /// </summary>
    [Theory]
    [InlineData("DOMAIN\\ivanov", "company.local", "ivanov@company.local")]
    [InlineData("COMPANY\\ivanov", "company.local", "ivanov@company.local")]
    [InlineData("DOMAIN\\ ivanov", "company.local", "ivanov@company.local")]
    [InlineData(" ivanov\\ ", "company.local", null)]
    public void NormalizeUserName_DownLevelLogon_ConvertsToUpn(string userName, string domainName, string? expected)
    {
        string? result = AdNames.NormalizeUserName(userName, domainName);

        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Корректный UPN для целевого домена возвращается без изменений
    /// (регистр доменной части не важен).
    /// </summary>
    [Theory]
    [InlineData("ivanov@company.local", "company.local", "ivanov@company.local")]
    [InlineData("ivanov@COMPANY.LOCAL", "company.local", "ivanov@COMPANY.LOCAL")]
    [InlineData(" ivanov@company.local ", "company.local", "ivanov@company.local")]
    public void NormalizeUserName_ValidUpn_ReturnedUnchanged(string userName, string domainName, string expected)
    {
        string? result = AdNames.NormalizeUserName(userName, domainName);

        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Некорректные имена пользователей отклоняются (возвращается null).
    /// </summary>
    [Theory]
    [InlineData(null, "company.local")]                  // имя не задано
    [InlineData("", "company.local")]                    // пустое имя
    [InlineData("   ", "company.local")]                 // имя из пробелов
    [InlineData("ivanov", null)]                         // домен не задан
    [InlineData("ivanov", "")]                           // пустой домен
    [InlineData("ivanov", "   ")]                        // домен из пробелов
    [InlineData("@company.local", "company.local")]      // пустая часть имени
    [InlineData("user@", "company.local")]               // пустая доменная часть
    [InlineData("a@b@company.local", "company.local")]   // два разделителя @
    [InlineData("user@other.local", "company.local")]    // чужой домен
    [InlineData("\\ivanov", "company.local")]            // слэш в начале
    [InlineData("ivanov\\", "company.local")]            // слэш в конце
    public void NormalizeUserName_InvalidInput_ReturnsNull(string? userName, string? domainName)
    {
        string? result = AdNames.NormalizeUserName(userName!, domainName!);

        Assert.Null(result);
    }

    /// <summary>
    /// UPN, введённый в другом регистре, но совпадающий с доменом без учёта регистра,
    /// принимается (сравнение доменной части нечувствительно к регистру).
    /// </summary>
    [Fact]
    public void NormalizeUserName_UpnCaseInsensitiveDomain_Accepted()
    {
        string? result = AdNames.NormalizeUserName("Ivanov@Company.Local", "COMPANY.LOCAL");

        Assert.Equal("Ivanov@Company.Local", result);
    }

    /// <summary>
    /// Регистр домена, переданного параметром, сохраняется в результате
    /// при добавлении домена к имени без разделителей.
    /// </summary>
    [Fact]
    public void NormalizeUserName_BareName_DomainCasePreserved()
    {
        string? result = AdNames.NormalizeUserName("ivanov", "COMPANY.LOCAL");

        Assert.Equal("ivanov@COMPANY.LOCAL", result);
    }

    /// <summary>
    /// Внутренние пробелы имени без разделителей не отклоняются:
    /// имя дополняется доменом как есть (фиксация фактического поведения).
    /// </summary>
    [Fact]
    public void NormalizeUserName_SpaceInsideName_NotRejected()
    {
        string? result = AdNames.NormalizeUserName("ivan petrov", "company.local");

        Assert.Equal("ivan petrov@company.local", result);
    }

    #endregion

    #region ExpandGroupTemplate

    /// <summary>
    /// Заполнитель {InstanceIdShort} заменяется коротким префиксом InstanceId
    /// во всех вхождениях; регистр заполнителя не важен, пробелы по краям шаблона
    /// обрезаются, шаблон без заполнителя возвращается без изменений.
    /// </summary>
    [Theory]
    [InlineData("WebShelf-{InstanceIdShort}-Administrator", "000000000000", "WebShelf-000000000000-Administrator")]
    [InlineData("WebShelf-{InstanceIdShort}-Users", "abcdef012345", "WebShelf-abcdef012345-Users")]
    [InlineData("WebShelf-{instanceidshort}-Users", "abcdef012345", "WebShelf-abcdef012345-Users")]
    [InlineData(" WebShelf-{InstanceIdShort}-Users ", "abcdef012345", "WebShelf-abcdef012345-Users")]
    [InlineData("WebShelf-{InstanceIdShort}-{InstanceIdShort}-X", "ab12", "WebShelf-ab12-ab12-X")]
    [InlineData("{InstanceIdShort}", "abcdef012345", "abcdef012345")]
    [InlineData("WebShelf-Fixed-Group", "abcdef012345", "WebShelf-Fixed-Group")]
    public void ExpandGroupTemplate_ValidTemplate_SubstitutesInstanceIdShort(
        string template, string instanceIdShort, string expected)
    {
        string result = AdNames.ExpandGroupTemplate(template, instanceIdShort);

        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Метод выполняет только подстановку и не отклоняет шаблон с опечаткой:
    /// некорректный заполнитель (опечатка, незакрытая или лишняя фигурная скобка)
    /// проходит в результат без изменений, корректные вхождения при этом заменяются.
    /// Отбраковка таких шаблонов выполняется в FillRequiredGroupsFromTemplates.
    /// </summary>
    [Theory]
    [InlineData("WebShelf-{InstanseIdShort}-Administrator", "abcdef012345", "WebShelf-{InstanseIdShort}-Administrator")]
    [InlineData("WebShelf-{InstanceIdShort-Manager", "abcdef012345", "WebShelf-{InstanceIdShort-Manager")]
    [InlineData("WebShelf-Users}", "abcdef012345", "WebShelf-Users}")]
    [InlineData("WebShelf-{InstanceIdShort}-{Role}", "abcdef012345", "WebShelf-abcdef012345-{Role}")]
    public void ExpandGroupTemplate_InvalidPlaceholder_NotRejected(
        string template, string instanceIdShort, string expected)
    {
        string result = AdNames.ExpandGroupTemplate(template, instanceIdShort);

        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Пустой шаблон имени группы отклоняется.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ExpandGroupTemplate_EmptyTemplate_ThrowsArgumentException(string? template)
    {
        Assert.Throws<ArgumentException>(() =>
            AdNames.ExpandGroupTemplate(template!, "abcdef012345"));
    }

    /// <summary>
    /// Пустой короткий префикс InstanceId отклоняется.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void ExpandGroupTemplate_EmptyInstanceIdShort_ThrowsArgumentException(string? instanceIdShort)
    {
        Assert.Throws<ArgumentException>(() =>
            AdNames.ExpandGroupTemplate("WebShelf-{InstanceIdShort}-Users", instanceIdShort!));
    }

    /// <summary>
    /// Спецсимволы в шаблоне не интерпретируются: подстановка выполняется
    /// буквальной заменой заполнителя.
    /// </summary>
    [Theory]
    [InlineData("WebShelf-{InstanceIdShort}-$1-Users", "WebShelf-abcdef012345-$1-Users")]
    [InlineData("%%{InstanceIdShort}%%", "%%abcdef012345%%")]
    public void ExpandGroupTemplate_SpecialCharacters_ReplacedLiterally(string template, string expected)
    {
        string result = AdNames.ExpandGroupTemplate(template, "abcdef012345");

        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Заполнитель с пробелами внутри ({ InstanceIdShort }) не распознаётся
    /// и остаётся в результате без изменений.
    /// </summary>
    [Fact]
    public void ExpandGroupTemplate_InnerSpacesInPlaceholder_NotReplaced()
    {
        string result = AdNames.ExpandGroupTemplate("WebShelf-{ InstanceIdShort }-Users", "abcdef012345");

        Assert.Equal("WebShelf-{ InstanceIdShort }-Users", result);
    }

    /// <summary>
    /// Значение префикса подставляется как есть, без обрезки пробелов:
    /// обрезка — обязанность вызывающего кода (фиксация фактического поведения).
    /// </summary>
    [Fact]
    public void ExpandGroupTemplate_InstanceIdShort_UsedAsIs()
    {
        string result = AdNames.ExpandGroupTemplate("WebShelf-{InstanceIdShort}-Users", " abcdef012345 ");

        Assert.Equal("WebShelf- abcdef012345 -Users", result);
    }

    #endregion
}
