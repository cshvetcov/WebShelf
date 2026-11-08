/**
 * CookieConsent.razor.js — хранение решения пользователя о согласии
 * на обработку файлов cookie (JS-isolation, ES-модуль).
 *
 * Решение хранится в localStorage браузера (ключ ws-cookie-consent) и
 * не передаётся на сервер. Запись не является cookie: при очистке данных
 * сайта в браузере решение удаляется вместе с ними — это же способ отзыва
 * согласия (баннер спросит решение заново).
 *
 * API (вызывается из Blazor через JS interop):
 *   hasDecision() — есть ли действующее сохранённое решение (boolean):
 *     запись с несовпадающей версией CONSENT_VERSION не учитывается
 *   saveDecision(accepted) — записать решение (boolean)
 *   getDecision() — прочитать решение: null | { accepted, date, version }
 *   resetDecision() — удалить решение (принудительный повторный запрос)
 */

/** Ключ localStorage. */
const STORAGE_KEY = "ws-cookie-consent";

/**
 * Версия формата записи согласия. Увеличивается при изменении состава
 * обрабатываемых cookie (например, добавлении аналитических): сохранённое
 * решение со старой версией считается отсутствующим, и баннер повторно
 * запрашивает согласие.
 */
const CONSENT_VERSION = 1;

/**
 * Читает сырую запись из localStorage; при недоступном хранилище
 * (запрещены cookie/сайт-данные, приватный режим с ограничениями)
 * возвращает null без исключения.
 * @returns {string|null} Сырая запись или null.
 */
function readRaw() {
    try {
        return localStorage.getItem(STORAGE_KEY);
    } catch (e) {
        // Хранилище недоступно — решения нет
        return null;
    }
}

/**
 * Записывает сырую запись в localStorage; при недоступном хранилище
 * молча пропускает запись (баннер в этом сеансе больше не показывается).
 * @param {string} value Строка для записи.
 */
function writeRaw(value) {
    try {
        localStorage.setItem(STORAGE_KEY, value);
    } catch (e) {
        // Хранилище недоступно — решение сохраняется только в памяти сеанса
    }
}

/**
 * Проверяет наличие действующего сохранённого решения о согласии.
 * Делегирует getDecision(): запись с несовпадающей версией
 * CONSENT_VERSION (повреждённая или оставшаяся от старой версии формата)
 * решением не считается — баннер запросит согласие заново, как описано
 * в WebShelfDocs/Решения в проекте/Обработка cookie.md.
 * @returns {boolean} true, если действующее решение сохранено.
 */
export function hasDecision() {
    return getDecision() !== null;
}

/**
 * Записывает решение пользователя о согласии.
 * @param {boolean} accepted - true — согласие дано; false — отклонено.
 */
export function saveDecision(accepted) {
    writeRaw(JSON.stringify({
        version: CONSENT_VERSION,
        accepted: accepted === true,
        date: new Date().toISOString()
    }));
}

/**
 * Возвращает сохранённое решение.
 * @returns {Object|null} { accepted: boolean, date: string, version: number }
 *   или null, если решения нет / запись повреждена / версия не совпадает.
 */
export function getDecision() {
    const raw = readRaw();
    if (raw === null) {
        return null;
    }

    try {
        const decision = JSON.parse(raw);
        if (decision === null || typeof decision !== "object" || decision.version !== CONSENT_VERSION) {
            return null;
        }

        return decision;
    } catch (e) {
        // Повреждённая запись — решения нет
        return null;
    }
}

/**
 * Удаляет сохранённое решение (отзыв согласия): при следующем входе
 * баннер запросит решение заново.
 */
export function resetDecision() {
    try {
        localStorage.removeItem(STORAGE_KEY);
    } catch (e) {
        // Хранилище недоступно — удалять нечего
    }
}
