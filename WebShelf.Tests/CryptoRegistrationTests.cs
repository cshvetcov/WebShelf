using Microsoft.Extensions.DependencyInjection;
using WebShelf.Classes.Crypto;
using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты регистраций криптографических сервисов в корне композиции
/// (Program.cs, шаг 8 декомпозиции — улучшение У3): KeyStore и CryptoEngine
/// регистрируются как готовые singleton-экземпляры, созданные в Main до
/// сборки хоста — Data и инициализаторы секций используют их при чтении
/// Server.conf, когда DI-контейнер ещё не существует, а потребители из DI
/// получают те же экземпляры. Состав регистраций повторяет Program.cs;
/// при изменении набора сервисов там обновите список здесь.
/// </summary>
public class CryptoRegistrationTests
{
    /// <summary>
    /// Готовые экземпляры KeyStore и CryptoEngine разрешаются из контейнера
    /// как singleton'ы: повторные разрешения (в том числе из скоупа) дают
    /// те же экземпляры, Data разрешается из контейнера без неразрешимых
    /// зависимостей (ValidateOnBuild — та же проверка, которую
    /// WebApplicationBuilder выполняет при Build в Development).
    /// Подмена хранилища ключей фейком (улучшение У3) исключает обращение
    /// к реестру и DPAPI.
    /// </summary>
    [Fact]
    public void CryptoServices_RegisteredAsReadySingletons_ResolveSameInstance()
    {
        KeyStore keyStore = new CryptoTestFakes.FakeKeyStore();
        CryptoEngine cryptoEngine = new CryptoEngine();

        ServiceCollection services = new();

        // Тот же способ регистрации, что в Program.cs: готовые экземпляры
        services.AddSingleton(keyStore);
        services.AddSingleton(cryptoEngine);
        services.AddSingleton(new Data(keyStore, cryptoEngine));

        // ValidateOnBuild + ValidateScopes: при неразрешимой зависимости
        // BuildServiceProvider выбрасывает исключение и тест проваливается
        using ServiceProvider provider = services.BuildServiceProvider(
            new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });

        Assert.Same(keyStore, provider.GetRequiredService<KeyStore>());
        Assert.Same(cryptoEngine, provider.GetRequiredService<CryptoEngine>());
        Assert.IsType<Data>(provider.GetRequiredService<Data>());

        // Singleton: один и тот же экземпляр и в пределах скоупа
        using IServiceScope scope = provider.CreateScope();
        Assert.Same(keyStore, scope.ServiceProvider.GetRequiredService<KeyStore>());
        Assert.Same(cryptoEngine, scope.ServiceProvider.GetRequiredService<CryptoEngine>());
    }
}
