using WebShelf.Classes.Service;
using Xunit;

namespace WebShelf.Tests;

/// <summary>
/// Тесты решения окна «Активация разрешения» по результату проверки пермита
/// (PermitCheckOutcome). Ключевое правило: блокировка с обратным отсчётом
/// включается уже после первой неудачной попытки (неверный или исчерпанный
/// пермит) — поведение как при неверной паре логин/пароль на форме входа,
/// но с первой попытки, а не с пятой. Красное сообщение о неверном пермите
/// не показывается: таймер включается сразу и заменяет его (оранжевый блок
/// с обратным отсчётом под кнопкой). Пустой ввод и ошибки сервера дают
/// только сообщение без блокировки; пригодный пермит — без сообщения.
/// Тесты чистые — без БД и интерфейса.
/// </summary>
public class PermitCheckOutcomeTests
{
    /// <summary>
    /// Пригодный пермит (найден в БД, счётчик больше нуля): ошибки нет,
    /// блокировка не включается — открывается окно подачи заявки.
    /// </summary>
    [Fact]
    public void FromResult_UsablePermit_NoMessageNoLockout()
    {
        RegistrationPermitCheckResult result = RegistrationPermitCheckResult.FromCounter(3);

        PermitCheckOutcome outcome = PermitCheckOutcome.FromResult(result);

        Assert.Null(outcome.ErrorMessage);
        Assert.False(outcome.StartLockout);
    }

    /// <summary>
    /// Пермит не найден в БД (первая же неудачная попытка): блокировка
    /// с обратным отсчётом включается, красное сообщение не показывается —
    /// таймер включается сразу и сам объясняет причину.
    /// </summary>
    [Fact]
    public void FromResult_PermitNotFound_LockoutWithoutMessageAfterFirstAttempt()
    {
        RegistrationPermitCheckResult result = RegistrationPermitCheckResult.FromCounter(null);

        PermitCheckOutcome outcome = PermitCheckOutcome.FromResult(result);

        Assert.Null(outcome.ErrorMessage);
        Assert.True(outcome.StartLockout);
    }

    /// <summary>
    /// Пермит найден, но счётчик регистраций исчерпан (нуль): блокировка
    /// с обратным отсчётом после первой попытки, без красного сообщения.
    /// </summary>
    [Fact]
    public void FromResult_PermitExhausted_LockoutWithoutMessageAfterFirstAttempt()
    {
        RegistrationPermitCheckResult result = RegistrationPermitCheckResult.FromCounter(0);

        PermitCheckOutcome outcome = PermitCheckOutcome.FromResult(result);

        Assert.Null(outcome.ErrorMessage);
        Assert.True(outcome.StartLockout);
    }

    /// <summary>
    /// Пустой ввод: сообщение без блокировки и без обращения к БД —
    /// как пустая пара логин/пароль на форме входа (required не пропускает
    /// пустую отправку до проверки).
    /// </summary>
    [Fact]
    public void FromEmptyInput_MessageWithoutLockout()
    {
        PermitCheckOutcome outcome = PermitCheckOutcome.FromEmptyInput();

        Assert.Equal(PermitCheckOutcome.EmptyPermitMessage, outcome.ErrorMessage);
        Assert.False(outcome.StartLockout);
    }

    /// <summary>
    /// Ошибка сервера при проверке (БД недоступна и т.п.): сообщение без
    /// блокировки — ошибка не списывается на пользователя, повторная
    /// попытка возможна сразу.
    /// </summary>
    [Fact]
    public void FromServerError_MessageWithoutLockout()
    {
        PermitCheckOutcome outcome = PermitCheckOutcome.FromServerError();

        Assert.Equal(PermitCheckOutcome.ServerErrorMessage, outcome.ErrorMessage);
        Assert.False(outcome.StartLockout);
    }
}
