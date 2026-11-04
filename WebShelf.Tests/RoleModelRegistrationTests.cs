using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using WebShelf.Classes.DC;
using WebShelf.Classes.Security;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты регистраций ролевой модели в корне композиции (Program.cs): набор
/// сервисов из блока «Ролевая модель» должен полностью собираться контейнером
/// DI (ValidateOnBuild — та же проверка, которую WebApplicationBuilder выполняет
/// при Build в Development). Регрессия: Program.cs регистрировал потребителей
/// IAdGroupSource (резолвер, провайдер состояния, фоновый опрос), но не сам
/// источник — сборка хоста завершалась AggregateException «Unable to resolve
/// service for type IAdGroupSource» и приложение не запускалось.
/// Состав регистраций повторяет Program.cs; при изменении набора сервисов там
/// обновите список здесь.
/// </summary>
public class RoleModelRegistrationTests
{
    /// <summary>
    /// Регистрации блока «Ролевая модель» из Program.cs собираются контейнером
    /// полностью: валидация при сборке не находит неразрешимых зависимостей,
    /// синглтоны и scoped-провайдер состояния разрешаются из контейнера.
    /// Вместо Domain (требует живого AD) источник групп подменяется фейком.
    /// </summary>
    [Fact]
    public void RoleModelRegistrations_OnBuild_AllServicesResolved()
    {
        ServiceCollection services = new();

        // Тот же набор регистраций, что в Program.cs (блок «Ролевая модель»);
        // IHttpContextAccessor регистрируется там же, выше по коду
        RoleTestFakes.FakeAdGroupSource ad = new();
        services.AddHttpContextAccessor();
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<IAdGroupSource>(ad);
        services.AddSingleton(
            RoleCacheOptions.FromTimeSpans(TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(30)));
        services.AddSingleton<RoleResolver>();
        services.AddSingleton<RoleChangeNotifier>();
        services.AddScoped<AuthenticationStateProvider, AppAuthenticationStateProvider>();
        services.AddHostedService<RoleRefreshService>();

        // ValidateOnBuild + ValidateScopes: при неразрешимой зависимости
        // (как с отсутствующим IAdGroupSource) BuildServiceProvider выбрасывает
        // исключение и тест проваливается
        using ServiceProvider provider = services.BuildServiceProvider(
            new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });

        // Синглтоны резолвера и фоновой службы разрешаются напрямую
        Assert.IsType<RoleResolver>(provider.GetRequiredService<RoleResolver>());
        Assert.IsType<RoleRefreshService>(provider.GetRequiredService<IHostedService>());

        // Scoped-провайдер состояния аутентификации — в пределах скоупа
        using IServiceScope scope = provider.CreateScope();
        AuthenticationStateProvider stateProvider =
            scope.ServiceProvider.GetRequiredService<AuthenticationStateProvider>();
        Assert.IsType<AppAuthenticationStateProvider>(stateProvider);
    }
}
