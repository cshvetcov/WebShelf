using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты каталога политик обработки данных (PolicyCatalog): известные коды,
/// соответствие «код — файл — заголовки» и реакция на неизвестный код.
/// </summary>
public class PolicyCatalogTests
{
    /// <summary>
    /// Каталог находит обе известные политики: cookie и personal-data —
    /// с корректными файлами поставки и непустыми заголовками.
    /// </summary>
    [Fact]
    public void TryFind_KnownCodes_ReturnsDefinitionsWithFiles()
    {
        PolicyDefinition? cookie = PolicyCatalog.TryFind(PolicyCatalog.CookiePolicyCode);
        PolicyDefinition? personalData = PolicyCatalog.TryFind(PolicyCatalog.PersonalDataPolicyCode);

        Assert.NotNull(cookie);
        Assert.Equal(PolicyCatalog.CookiePolicyCode, cookie.Code);
        Assert.Equal("cookie-policy.html", cookie.FileName);
        Assert.False(string.IsNullOrWhiteSpace(cookie.DocumentTitle));
        Assert.False(string.IsNullOrWhiteSpace(cookie.TitlebarText));

        Assert.NotNull(personalData);
        Assert.Equal(PolicyCatalog.PersonalDataPolicyCode, personalData.Code);
        Assert.Equal("personal-data-policy.html", personalData.FileName);
        Assert.False(string.IsNullOrWhiteSpace(personalData.DocumentTitle));
        Assert.False(string.IsNullOrWhiteSpace(personalData.TitlebarText));
    }

    /// <summary>
    /// Каталог возвращает null для неизвестного кода (страница архива
    /// показывает резервное сообщение).
    /// </summary>
    [Fact]
    public void TryFind_UnknownCode_ReturnsNull()
    {
        PolicyDefinition? definition = PolicyCatalog.TryFind("marketing");

        Assert.Null(definition);
    }

    /// <summary>
    /// Каталог выбрасывает ArgumentNullException для null-кода.
    /// </summary>
    [Fact]
    public void TryFind_NullCode_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => PolicyCatalog.TryFind(null!));
    }

    /// <summary>
    /// Состав каталога — ровно две политики с уникальными кодами и файлами:
    /// коды совпадают с доменом CHECK-ограничения каркаса БД.
    /// </summary>
    [Fact]
    public void Policies_ContainExactlyTwoPoliciesWithUniqueCodesAndFiles()
    {
        Assert.Equal(2, PolicyCatalog.Policies.Count);

        Assert.Equal(2, PolicyCatalog.Policies.Select(definition => definition.Code).Distinct().Count());
        Assert.Equal(2, PolicyCatalog.Policies.Select(definition => definition.FileName).Distinct().Count());
    }

    /// <summary>
    /// Ссылочные свойства Cookie/PersonalData указывают на те же описания,
    /// что и список Policies (единый источник соответствия).
    /// </summary>
    [Fact]
    public void CookieAndPersonalData_AreSameInstancesAsCatalogEntries()
    {
        Assert.Contains(PolicyCatalog.Cookie, PolicyCatalog.Policies);
        Assert.Contains(PolicyCatalog.PersonalData, PolicyCatalog.Policies);
    }
}
