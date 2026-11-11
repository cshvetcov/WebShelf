using System.Text.RegularExpressions;
using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты канонизации текста политики и контрольной суммы редакции
/// (PolicyTextCanonicalizer): BOM и CRLF нормализуются, канонизация
/// идемпотентна, SHA-256 — детерминированный hex-нижний регистр.
/// </summary>
public class PolicyTextCanonicalizerTests
{
    /// <summary>
    /// Канонизация отбрасывает BOM в начале текста.
    /// </summary>
    [Fact]
    public void Canonicalize_TextWithBom_StripsBom()
    {
        string text = "\uFEFF<h2>1. Общие положения</h2>";

        string canonical = PolicyTextCanonicalizer.Canonicalize(text);

        Assert.Equal("<h2>1. Общие положения</h2>", canonical);
    }

    /// <summary>
    /// Канонизация приводит переводы строк Windows (CRLF) к LF.
    /// </summary>
    [Fact]
    public void Canonicalize_TextWithCrLf_ConvertsToLf()
    {
        string text = "первая строка\r\nвторая строка\r\nтретья строка";

        string canonical = PolicyTextCanonicalizer.Canonicalize(text);

        Assert.Equal("первая строка\nвторая строка\nтретья строка", canonical);
    }

    /// <summary>
    /// Канонизация не затрагивает тексты без BOM и с LF.
    /// </summary>
    [Fact]
    public void Canonicalize_AlreadyCanonicalText_ReturnsUnchanged()
    {
        string text = "<h2>1. Общие положения</h2>\n<p>Текст редакции.</p>\n";

        string canonical = PolicyTextCanonicalizer.Canonicalize(text);

        Assert.Equal(text, canonical);
    }

    /// <summary>
    /// Канонизация идемпотентна: повторное применение результата
    /// не меняет текст (контрольная сумма хранимой строки пересчитывается
    /// тем же путём).
    /// </summary>
    [Fact]
    public void Canonicalize_Twice_ReturnsSameResult()
    {
        string text = "\uFEFFстрока 1\r\nстрока 2";

        string firstPass = PolicyTextCanonicalizer.Canonicalize(text);
        string secondPass = PolicyTextCanonicalizer.Canonicalize(firstPass);

        Assert.Equal(firstPass, secondPass);
    }

    /// <summary>
    /// Контрольная сумма — 64 hex-символа нижнего регистра.
    /// </summary>
    [Fact]
    public void ComputeSha256_ReturnsLowercaseHexOf64Characters()
    {
        string hash = PolicyTextCanonicalizer.ComputeSha256("Текст политики обработки cookie.");

        Assert.Matches(new Regex("^[0-9a-f]{64}$", RegexOptions.None, TimeSpan.FromSeconds(1)), hash);
    }

    /// <summary>
    /// Контрольная сумма детерминирована: одинаковый текст — одинаковая сумма.
    /// </summary>
    [Fact]
    public void ComputeSha256_SameText_ReturnsSameHash()
    {
        string first = PolicyTextCanonicalizer.ComputeSha256("одинаковый текст");
        string second = PolicyTextCanonicalizer.ComputeSha256("одинаковый текст");

        Assert.Equal(first, second);
    }

    /// <summary>
    /// Контрольная сумма различается для разных текстов.
    /// </summary>
    [Fact]
    public void ComputeSha256_DifferentTexts_ReturnDifferentHashes()
    {
        string first = PolicyTextCanonicalizer.ComputeSha256("текст первой редакции");
        string second = PolicyTextCanonicalizer.ComputeSha256("текст второй редакции");

        Assert.NotEqual(first, second);
    }

    /// <summary>
    /// Канонизация одного текста в разных записях файла (BOM/CRLF против LF)
    /// даёт одну контрольную сумму — цель канонизации.
    /// </summary>
    [Fact]
    public void ComputeSha256_CanonicalizedEquivalentTexts_ReturnSameHash()
    {
        string windowsText = "\uFEFFраздел\r\nперевод строки\r\n";
        string linuxText = "раздел\nперевод строки\n";

        string windowsHash = PolicyTextCanonicalizer.ComputeSha256(PolicyTextCanonicalizer.Canonicalize(windowsText));
        string linuxHash = PolicyTextCanonicalizer.ComputeSha256(PolicyTextCanonicalizer.Canonicalize(linuxText));

        Assert.Equal(windowsHash, linuxHash);
    }

    /// <summary>
    /// Канонизация null-текста выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void Canonicalize_NullText_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => PolicyTextCanonicalizer.Canonicalize(null!));
    }

    /// <summary>
    /// Контрольная сумма null-текста выбрасывает ArgumentNullException.
    /// </summary>
    [Fact]
    public void ComputeSha256_NullText_ThrowsArgumentNullException()
    {
        Assert.Throws<ArgumentNullException>(() => PolicyTextCanonicalizer.ComputeSha256(null!));
    }
}
