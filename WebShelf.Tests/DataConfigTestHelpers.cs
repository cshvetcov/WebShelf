using System.Text;

namespace WebShelf.Tests;

/// <summary>
/// Вспомогательные средства characterization-тестов конфигурации
/// (шаг 0 дорожной карты декомпозиции): уникальные временные каталоги
/// и запись файлов Server.conf с точным контролем байтового содержимого.
/// </summary>
internal static class DataConfigTestHelpers
{
    /// <summary>
    /// Создаёт уникальный временный каталог для одного теста.
    /// Уникальность пути снимает зависимость от параллелизма xUnit:
    /// каждый тест работает со своим физическим файлом.
    /// Удаление каталога — обязанность вызывающего теста (блок finally).
    /// </summary>
    /// <returns>Полный путь к созданному каталогу.</returns>
    internal static string CreateTempDirectory()
    {
        string directory = Path.Combine(
            Path.GetTempPath(),
            "WebShelfStep0Tests",
            Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(directory);

        return directory;
    }

    /// <summary>
    /// Пишет строки файла конфигурации в кодировке UTF-8 без BOM
    /// с завершающим переводом строки после последней строки.
    /// Управление BOM важно для characterization-тестов: производственный
    /// <see cref="System.IO.File.WriteAllLines(string, string[], System.Text.Encoding)"/>
    /// с <c>Encoding.UTF8</c> BOM записывает, а входной файл теста
    /// должен быть предсказуемым без него.
    /// </summary>
    /// <param name="path">Полный путь к файлу.</param>
    /// <param name="lines">Строки файла.</param>
    internal static void WriteUtf8NoBom(string path, params string[] lines)
    {
        string content = string.Join("\n", lines) + "\n";
        File.WriteAllBytes(path, Encoding.UTF8.GetBytes(content));
    }

    /// <summary>
    /// Пишет файл конфигурации с BOM (EF BB BF) в начале — имитирует
    /// файлы, созданные редакторами Windows или самой записью конфигурации.
    /// </summary>
    /// <param name="path">Полный путь к файлу.</param>
    /// <param name="lines">Строки файла (первая строка идёт сразу после BOM).</param>
    internal static void WriteUtf8WithBom(string path, params string[] lines)
    {
        string content = string.Join("\n", lines) + "\n";
        byte[] body = Encoding.UTF8.GetBytes(content);

        byte[] withBom = new byte[body.Length + 3];
        withBom[0] = 0xEF;
        withBom[1] = 0xBB;
        withBom[2] = 0xBF;
        body.CopyTo(withBom, 3);

        File.WriteAllBytes(path, withBom);
    }

    /// <summary>
    /// Собирает ожидаемое байтовое содержимое файла после
    /// <see cref="System.IO.File.WriteAllLines(string, string[], System.Text.Encoding)"/>:
    /// BOM (EF BB BF), строки, разделённые системным переводом строки,
    /// завершающий перевод строки после последней строки.
    /// </summary>
    /// <param name="lines">Ожидаемые строки результата.</param>
    /// <returns>Ожидаемые байты файла.</returns>
    internal static byte[] ExpectedWriteAllLinesBytes(params string[] lines)
    {
        string content = string.Join(Environment.NewLine, lines) + Environment.NewLine;

        byte[] body = Encoding.UTF8.GetBytes(content);

        byte[] withBom = new byte[body.Length + 3];
        withBom[0] = 0xEF;
        withBom[1] = 0xBB;
        withBom[2] = 0xBF;
        body.CopyTo(withBom, 3);

        return withBom;
    }
}
