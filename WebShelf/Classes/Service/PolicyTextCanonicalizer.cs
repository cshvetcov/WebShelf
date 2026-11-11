using System.Security.Cryptography;
using System.Text;

namespace WebShelf.Classes.Service;

/// <summary>
/// Канонизация текста политики и вычисление контрольной суммы редакции.
/// Приводит текст к единому виду независимо от способа записи файла
/// (BOM, CRLF/LF): BOM отбрасывается, переводы строк нормализуются к LF.
/// Канонизация идемпотентна — повторное применение результата не меняет его,
/// поэтому контрольная сумма строки журнала может пересчитываться из
/// хранимого текста без отдельной нормализации хранения.
/// Контрольная сумма — SHA-256 от байтов UTF-8 канонизированного текста
/// (hex, нижний регистр, 64 символа).
/// </summary>
internal static class PolicyTextCanonicalizer
{
    /// <summary>
    /// Канонизирует текст политики: отбрасывает BOM и приводит переводы
    /// строк Windows (CRLF) к LF.
    /// </summary>
    /// <param name="text">Исходный текст (например, содержимое файла поставки).</param>
    /// <returns>Канонизированный текст.</returns>
    /// <exception cref="ArgumentNullException">
    /// Возникает, если <paramref name="text"/> равен <see langword="null"/>.
    /// </exception>
    internal static string Canonicalize(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        // Сравнение с BOM — посимвольное (порядковое): перегрузка char не имеет
        // параметра StringComparison, эквивалентна Ordinal по построению
        string withoutBom = text.Length > 0 && text[0] == '\uFEFF' ? text[1..] : text;

        return withoutBom.Replace("\r\n", "\n", StringComparison.Ordinal);
    }

    /// <summary>
    /// Вычисляет контрольную сумму SHA-256 текста (hex, нижний регистр).
    /// </summary>
    /// <param name="text">Текст в кодировке UTF-8 (канонизированный).</param>
    /// <returns>Контрольная сумма: 64 hex-символа.</returns>
    /// <exception cref="ArgumentNullException">
    /// Возникает, если <paramref name="text"/> равен <see langword="null"/>.
    /// </exception>
    internal static string ComputeSha256(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        byte[] bytes = Encoding.UTF8.GetBytes(text);
        byte[] hash = SHA256.HashData(bytes);

        return Convert.ToHexStringLower(hash);
    }
}
