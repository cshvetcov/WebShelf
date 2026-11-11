using System.Text.RegularExpressions;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты файлов-текстов политик в поставке (WebShelf/Content/Policies):
/// страницы политик — часть поставки, фрагменты обязаны соответствовать тем же
/// правилам, что и прежние статичные страницы (WebShelfDocs/Решения в проекте/
/// Версионирование политик.md): без скриптов (CSP script-src 'self'),
/// с пометками для оператора, с правовым основанием (152-ФЗ) и без элементов
/// оболочки (оболочку рендерит PolicyDocument.razor, дата редакции — из журнала).
/// </summary>
public class PolicyContentFilesTests
{
    /// <summary>
    /// Имена файлов текстов политик в поставке.
    /// </summary>
    private static readonly string[] PolicyFileNames = ["cookie-policy.html", "personal-data-policy.html"];

    /// <summary>
    /// Каталог Content/Policies проекта WebShelf: ищется от каталога сборки
    /// вверх до корня решения (WebShelf.slnx) — файлы не копируются в вывод
    /// сборки тестов.
    /// </summary>
    private static string PoliciesDirectory
    {
        get
        {
            DirectoryInfo? directory = new(AppContext.BaseDirectory);

            while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "WebShelf.slnx")))
            {
                directory = directory.Parent;
            }

            return directory is null
                ? throw new InvalidOperationException(
                    $"Корень решения не найден от {AppContext.BaseDirectory}: тест требует запуска из дерева репозитория.")
                : Path.Combine(directory.FullName, "WebShelf", "Content", "Policies");
        }
    }

    /// <summary>Читает файл текста политики (UTF-8).</summary>
    private static async Task<string> ReadPolicyTextAsync(string fileName)
    {
        string path = Path.Combine(PoliciesDirectory, fileName);
        Assert.True(File.Exists(path), $"Файл текста политики не найден: {path}");

        return await File.ReadAllTextAsync(path);
    }

    /// <summary>
    /// Файлы обеих политик существуют в поставке (Content/Policies).
    /// </summary>
    [Fact]
    public void PolicyFiles_ExistInDeliveryDirectory()
    {
        foreach (string fileName in PolicyFileNames)
        {
            Assert.True(
                File.Exists(Path.Combine(PoliciesDirectory, fileName)),
                $"Файл текста политики не найден: {fileName}");
        }
    }

    /// <summary>
    /// Тексты не содержат скриптов: CSP приложения (script-src 'self')
    /// запрещает встроенные теги script. HTML-комментарии-документации,
    /// в которых теги упомянуты как текст, исключаются из проверки
    /// (тот же приём, что у прежних тестов статичных страниц).
    /// </summary>
    [Fact]
    public async Task PolicyFiles_NoScripts()
    {
        foreach (string fileName in PolicyFileNames)
        {
            string text = await ReadPolicyTextAsync(fileName);

            string withoutComments = Regex.Replace(text, @"<!--.*?-->", string.Empty, RegexOptions.Singleline);

            Assert.DoesNotContain("<script", withoutComments, StringComparison.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// Тексты содержат пометки «ЗАПОЛНИТЬ ПРИ РАЗВЁРТЫВАНИИ» и классы
    /// ws-fill-hint: оператор обязан заполнить реквизиты при развёртывании
    /// (реквизиты — неотъемлемая часть текста политики).
    /// </summary>
    [Fact]
    public async Task PolicyFiles_ContainFillOnDeploymentPlaceholders()
    {
        foreach (string fileName in PolicyFileNames)
        {
            string text = await ReadPolicyTextAsync(fileName);

            Assert.Contains("ЗАПОЛНИТЬ ПРИ РАЗВЁРТЫВАНИИ", text);
            Assert.Contains("ws-fill-hint", text);
        }
    }

    /// <summary>
    /// Тексты ссылаются на 152-ФЗ — правовое основание обработки
    /// (тексты переносятся из прежних статичных страниц без правки).
    /// </summary>
    [Fact]
    public async Task PolicyFiles_ReferencePersonalDataLaw()
    {
        foreach (string fileName in PolicyFileNames)
        {
            string text = await ReadPolicyTextAsync(fileName);

            Assert.Contains("152-ФЗ", text);
        }
    }

    /// <summary>
    /// Тексты — фрагменты без оболочки документа: без html/body/head/h1
    /// (заголовок h1, дата редакции и оболочка рендерятся PolicyDocument.razor);
    /// текст начинается с секции h2.
    /// </summary>
    [Fact]
    public async Task PolicyFiles_AreFragmentsWithoutShellMarkup()
    {
        foreach (string fileName in PolicyFileNames)
        {
            string text = await ReadPolicyTextAsync(fileName);

            Assert.DoesNotContain("<html", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("<head", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("<body", text, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("<h1", text, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("<h2>", text);
        }
    }

    /// <summary>
    /// Тексты не содержат строку даты редакции и кнопку возврата — оба
    /// элемента рендерятся шаблоном из журнала (дата — метаданные редакции).
    /// </summary>
    [Fact]
    public async Task PolicyFiles_HaveNoDateLineOrBackLink()
    {
        foreach (string fileName in PolicyFileNames)
        {
            string text = await ReadPolicyTextAsync(fileName);

            Assert.DoesNotContain("ws-policy-date", text);
            Assert.DoesNotContain("ws-policy-back", text);
            Assert.DoesNotContain("Редакция от", text);
        }
    }

    /// <summary>
    /// Текст политики персональных данных ссылается на политику обработки
    /// cookie (взаимные ссылки политик сохранены в текстах).
    /// </summary>
    [Fact]
    public async Task PersonalDataFile_ReferencesCookiePolicy()
    {
        string text = await ReadPolicyTextAsync("personal-data-policy.html");

        Assert.Contains("/cookie-policy.html", text);
    }
}
