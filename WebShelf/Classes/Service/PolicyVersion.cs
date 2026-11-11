namespace WebShelf.Classes.Service;

/// <summary>
/// Редакция политики обработки данных — отображаемая строка журнала
/// <c>webshelf.policy_versions</c>: полный текст с метаданными редакции
/// (номер, дата вступления в силу, контрольная сумма).
/// </summary>
/// <param name="Version">Номер редакции в пределах политики (начиная с 1).</param>
/// <param name="EffectiveFrom">Дата и время вступления редакции в силу (UTC).</param>
/// <param name="Content">Канонизированный HTML-текст редакции: фрагмент без оболочки страницы.</param>
/// <param name="ContentSha256">Контрольная сумма SHA-256 текста редакции (hex, 64 символа).</param>
/// <remarks>
/// Record объявлен public (при общем internal-стиле проекта): объект передаётся
/// в публичный параметр Razor-компонента PolicyDocument — публичные параметры
/// компонента не могут принимать internal-типы.
/// </remarks>
public sealed record PolicyVersion(int Version, DateTimeOffset EffectiveFrom, string Content, string ContentSha256);
