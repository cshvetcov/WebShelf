namespace WebShelf.Classes.Service;

/// <summary>
/// Сводка редакции политики для блока «История редакций» (без полного текста):
/// номер, дата вступления в силу и контрольная сумма.
/// </summary>
/// <param name="Version">Номер редакции в пределах политики (начиная с 1).</param>
/// <param name="EffectiveFrom">Дата и время вступления редакции в силу (UTC).</param>
/// <param name="ContentSha256">Контрольная сумма SHA-256 текста редакции (hex, 64 символа).</param>
/// <remarks>
/// Record объявлен public (при общем internal-стиле проекта): объект передаётся
/// в публичный параметр Razor-компонента PolicyDocument — публичные параметры
/// компонента не могут принимать internal-типы.
/// </remarks>
public sealed record PolicyVersionSummary(int Version, DateTimeOffset EffectiveFrom, string ContentSha256);
