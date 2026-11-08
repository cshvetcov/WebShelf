using System.Globalization;
using Npgsql;
using WebShelf.Classes.DB;

namespace WebShelf.Classes.Service;

/// <summary>
/// Проверка регистрационных пермитов в базе данных: пермит пригоден для подачи
/// заявки на регистрацию, если он найден в таблице <c>webshelf.registration_permits</c>
/// и его счётчик оставшихся регистраций больше нуля.
/// </summary>
/// <remarks>
/// Сервис только читает состояние и не уменьшает счётчик: уменьшение выполняется
/// при успешной регистрации, а не при проверке (см. WebShelfDocs/Решения в проекте/
/// База данных.md). Значение пермита — секретный код: в логи не попадает
/// ни при каких условиях (правило маскировки Логирование.md).
/// Экземпляр создаётся в Program.Main рядом с Database и регистрируется в DI
/// готовым singleton-экземпляром (как Data и KeyStore).
/// </remarks>
internal sealed class RegistrationPermitChecker(Database database)
{
    private const string ClassName = "WebShelf.Classes.Service.RegistrationPermitChecker";

    /// <summary>
    /// Проверяет пермит по базе данных: поиск точного совпадения в таблице
    /// <c>webshelf.registration_permits</c> и проверка счётчика регистраций.
    /// Пустое значение или значение из одних пробелов трактуется как ненайденное.
    /// </summary>
    /// <param name="permit">Введённое значение пермита (обрезается по краям).</param>
    /// <param name="cancellationToken">Токен отмены.</param>
    /// <returns>Результат проверки; никогда не <see langword="null"/>.</returns>
    internal async Task<RegistrationPermitCheckResult> CheckAsync(
        string permit,
        CancellationToken cancellationToken = default)
    {
        const string method = nameof(CheckAsync);

        string normalizedPermit = permit.Trim();
        if (normalizedPermit.Length == 0)
        {
            Log.Debug("Проверка пермита: введено пустое значение. Class={Class}, Method={Method}",
                ClassName, method);
            return RegistrationPermitCheckResult.FromCounter(null);
        }

        // Параметризованный запрос: значение пермита никогда не конкатенируется в SQL
        await using NpgsqlConnection connection = await database.OpenConnectionAsync(cancellationToken);
        await using NpgsqlCommand command = connection.CreateCommand();
        command.CommandText = "SELECT counter FROM webshelf.registration_permits WHERE permit = @permit";
        command.Parameters.AddWithValue("permit", normalizedPermit);

        object? rawCounter = await command.ExecuteScalarAsync(cancellationToken);
        int? counter = rawCounter is null
            ? null
            : Convert.ToInt32(rawCounter, CultureInfo.InvariantCulture);

        RegistrationPermitCheckResult result = RegistrationPermitCheckResult.FromCounter(counter);

        if (result.IsUsable)
        {
            Log.Information(
                "Пермит прошёл проверку: счётчик регистраций больше нуля. Counter={Counter}. Class={Class}, Method={Method}",
                result.Counter, ClassName, method);
        }
        else
        {
            Log.Warning(
                "Пермит не прошёл проверку. Status={PermitStatus}. Class={Class}, Method={Method}",
                result.Status, ClassName, method);
        }

        return result;
    }
}
