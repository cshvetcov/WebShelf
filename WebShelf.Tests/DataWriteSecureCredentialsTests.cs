using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Characterization-тесты записи защищённых учётных данных
/// (<see cref="Data.WriteSecureCredentials"/>, шаг 0 дорожной карты
/// декомпозиции). Фиксируют фактическое поведение процедуры записи
/// до её выноса в отдельный класс (шаг 6): перенос открытых значений
/// в защищённые с затиранием открытых, сохранение комментариев и порядка
/// посторонних строк, дописывание отсутствующих ключей, атомарную замену
/// файла и точный байтовый формат результата.
/// Метод принимает уже зашифрованные значения и криптографию не вызывает,
/// поэтому тесты платформонезависимы. Каждый тест работает со своим
/// временным файлом через конструктор <see cref="Data"/> с внедрённым
/// путём (улучшение У2).
/// </summary>
public class DataWriteSecureCredentialsTests
{
    /// <summary>
    /// Доменная пара: существующие открытые значения затираются,
    /// защищённые заменяются переданными, прочие строки сохраняются.
    /// Сценарий (а) шага 0 дорожной карты.
    /// </summary>
    [Fact]
    public void DomainPair_PlainValues_WipedSecureReplaced()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "domainname=contoso.local",
                "domainuser=svc-plain",
                "domainpass=plain-secret",
                "sdomainuser=STALE-OLD-VALUE",
                "sdomainpass=STALE-OLD-VALUE");

            Data data = new Data(path);

            bool result = data.WriteSecureCredentials(
                Data.DomainCredentialKeys, "ENC-USER", "ENC-PASS");

            Assert.True(result);

            string[] lines = File.ReadAllLines(path);
            Assert.Contains("sdomainuser=ENC-USER", lines);
            Assert.Contains("sdomainpass=ENC-PASS", lines);
            Assert.Contains("domainuser=", lines);
            Assert.Contains("domainpass=", lines);
            Assert.Contains("domainname=contoso.local", lines);
            Assert.DoesNotContain("domainuser=svc-plain", lines);
            Assert.DoesNotContain("domainpass=plain-secret", lines);
            Assert.DoesNotContain("sdomainuser=STALE-OLD-VALUE", lines);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Комментарии, пустые строки и посторонние ключи сохраняются
    /// на своих местах. Сценарий (б) шага 0 дорожной карты.
    /// </summary>
    [Fact]
    public void CommentsAndUnrelatedLines_PreservedInPlace()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "# Настройки сети",
                "scheme=http",
                "port=38080",
                "",
                "   ",
                "строка без знака равенства",
                "# Ещё комментарий",
                "domainuser=svc-plain",
                "domainpass=plain-secret");

            Data data = new Data(path);

            bool result = data.WriteSecureCredentials(
                Data.DomainCredentialKeys, "ENC-USER", "ENC-PASS");

            Assert.True(result);

            // Существующие ключи заменяются на месте: порядок и все
            // посторонние строки (комментарии, пустые, некорректные) неизменны
            string[] expected =
            [
                "# Настройки сети",
                "scheme=http",
                "port=38080",
                "",
                "   ",
                "строка без знака равенства",
                "# Ещё комментарий",
                "domainuser=",
                "domainpass=",
                "sdomainuser=ENC-USER",
                "sdomainpass=ENC-PASS",
            ];
            Assert.Equal(expected, File.ReadAllLines(path));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Отсутствующие ключи дописываются в конец файла в каноническом
    /// порядке: защищённые, затем открытые (пустыми). Сценарий (в) шага 0
    /// дорожной карты: после любой записи все четыре ключа пары
    /// присутствуют в файле.
    /// </summary>
    [Fact]
    public void MissingKeys_AppendedAtEndInCanonicalOrder()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "scheme=http");

            Data data = new Data(path);

            bool result = data.WriteSecureCredentials(
                Data.DomainCredentialKeys, "ENC-USER", "ENC-PASS");

            Assert.True(result);

            string[] expected =
            [
                "scheme=http",
                "sdomainuser=ENC-USER",
                "sdomainpass=ENC-PASS",
                "domainuser=",
                "domainpass=",
            ];
            Assert.Equal(expected, File.ReadAllLines(path));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Пара БД: та же процедура обслуживает sdbuser/sdbpass и затирает
    /// dbuser/dbpass. Сценарий (г) шага 0 дорожной карты — все три пары.
    /// </summary>
    [Fact]
    public void DatabasePair_PlainValues_WipedSecureReplaced()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "dbhost=127.0.0.1",
                "dbuser=svc-db-plain",
                "dbpass=db-plain-secret",
                "sdbuser=STALE",
                "sdbpass=STALE");

            Data data = new Data(path);

            bool result = data.WriteSecureCredentials(
                Data.DatabaseCredentialKeys, "ENC-DB-USER", "ENC-DB-PASS");

            Assert.True(result);

            string[] lines = File.ReadAllLines(path);
            Assert.Contains("sdbuser=ENC-DB-USER", lines);
            Assert.Contains("sdbpass=ENC-DB-PASS", lines);
            Assert.Contains("dbuser=", lines);
            Assert.Contains("dbpass=", lines);
            Assert.DoesNotContain("dbuser=svc-db-plain", lines);
            Assert.DoesNotContain("dbpass=db-plain-secret", lines);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Пара TLS без «пользовательской» половины: записывается только
    /// scertpass, затирается certpass; ключей имени (certuser/scertuser)
    /// процедура не создаёт. Сценарий (г) шага 0 дорожной карты.
    /// </summary>
    [Fact]
    public void TlsPair_WithoutUserHalf_WritesOnlyPassKeys()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "certpath=C:\\certs\\webshelf.pfx",
                "certpass=plain-cert-secret");

            Data data = new Data(path);

            bool result = data.WriteSecureCredentials(
                Data.TlsCredentialKeys, encryptedUser: null, "ENC-CERT-PASS");

            Assert.True(result);

            string[] expected =
            [
                "certpath=C:\\certs\\webshelf.pfx",
                "certpass=",
                "scertpass=ENC-CERT-PASS",
            ];
            Assert.Equal(expected, File.ReadAllLines(path));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Отсутствующий файл конфигурации — отказ (false) без создания
    /// временного файла. Сценарий (д) шага 0 дорожной карты.
    /// </summary>
    [Fact]
    public void MissingConfigFile_ReturnsFalseWithoutTmpFile()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");

            Data data = new Data(path);

            bool result = data.WriteSecureCredentials(
                Data.DomainCredentialKeys, "ENC-USER", "ENC-PASS");

            Assert.False(result);
            Assert.False(File.Exists(path));
            Assert.False(File.Exists(path + ".tmp"));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// После успешной записи временный файл .tmp не остаётся:
    /// File.Replace подменяет конфиг атомарно. Сценарий (е) шага 0
    /// дорожной карты.
    /// </summary>
    [Fact]
    public void SuccessfulWrite_NoTmpFileLeftBehind()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "domainuser=svc-plain",
                "domainpass=plain-secret");

            Data data = new Data(path);

            bool result = data.WriteSecureCredentials(
                Data.DomainCredentialKeys, "ENC-USER", "ENC-PASS");

            Assert.True(result);
            Assert.True(File.Exists(path));
            Assert.False(File.Exists(path + ".tmp"));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Отказ записи (временный файл .tmp невозможно создать — по этому пути
    /// существует каталог) возвращает false, а не исключение наружу;
    /// исходный файл остаётся нетронутым. Фиксация поведения при ошибках
    /// файловой системы, упомянутого в шаге 0 дорожной карты
    /// (отказ → false, а не исключение).
    /// </summary>
    [Fact]
    public void WriteFailure_ReturnsFalseOriginalFileIntact()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "domainuser=svc-plain",
                "domainpass=plain-secret");

            // Каталог на месте временного файла: File.WriteAllLines откажет
            // в создании .tmp — детерминированный отказ записи на любой платформе
            Directory.CreateDirectory(path + ".tmp");

            Data data = new Data(path);

            bool result = data.WriteSecureCredentials(
                Data.DomainCredentialKeys, "ENC-USER", "ENC-PASS");

            Assert.False(result);

            // Исходный файл не повреждён: содержимое прежнее
            string[] expected =
            [
                "domainuser=svc-plain",
                "domainpass=plain-secret",
            ];
            Assert.Equal(expected, File.ReadAllLines(path));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Байтовое сравнение результата записи: UTF-8 c BOM, системный
    /// перевод строки между строками, завершающий перевод строки после
    /// последней строки. Зафиксировано, чтобы шаг 6 не изменил хвост
    /// файла незаметно (File.WriteAllLines добавляет перевод строки
    /// после каждой строки, включая последнюю).
    /// </summary>
    [Fact]
    public void WrittenFile_ByteExactContent_WithBomAndTrailingNewline()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "# Конфигурация",
                "scheme=http");

            Data data = new Data(path);

            bool result = data.WriteSecureCredentials(
                Data.DomainCredentialKeys, "ENC-USER", "ENC-PASS");

            Assert.True(result);

            byte[] expected = DataConfigTestHelpers.ExpectedWriteAllLinesBytes(
                "# Конфигурация",
                "scheme=http",
                "sdomainuser=ENC-USER",
                "sdomainpass=ENC-PASS",
                "domainuser=",
                "domainpass=");

            Assert.Equal(expected, File.ReadAllBytes(path));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    /// <summary>
    /// Ключи в файле сопоставляются без учёта регистра и переписываются
    /// каноническими именами: строки вида SDOMAINUSER=… / DomainPass=…
    /// заменяются на sdomainuser=/sdomainpass=.
    /// </summary>
    [Fact]
    public void MixedCaseKeys_RewrittenWithCanonicalNames()
    {
        string directory = DataConfigTestHelpers.CreateTempDirectory();
        try
        {
            string path = Path.Combine(directory, "Server.conf");
            DataConfigTestHelpers.WriteUtf8NoBom(path,
                "SDOMAINUSER=stale",
                "SdomainPass=stale",
                "DomainUser=svc-plain",
                "DomainPass=plain-secret");

            Data data = new Data(path);

            bool result = data.WriteSecureCredentials(
                Data.DomainCredentialKeys, "ENC-USER", "ENC-PASS");

            Assert.True(result);

            string[] lines = File.ReadAllLines(path);
            Assert.Contains("sdomainuser=ENC-USER", lines);
            Assert.Contains("sdomainpass=ENC-PASS", lines);
            Assert.Contains("domainuser=", lines);
            Assert.Contains("domainpass=", lines);
            Assert.Equal(4, lines.Length);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
