/**
 * RibbonMenu.razor.js — JS-модуль ленточного меню WebShelf (колокация с RibbonMenu.razor).
 * Логика переключения вкладок ленточного меню; функционал кнопок намеренно
 * не реализован (только визуальный каркас).
 *
 * Подключается через JS-isolation Blazor:
 *   await Js.InvokeAsync<IJSObjectReference>("import", "./Components/Shared/RibbonMenu.razor.js");
 *
 * Экспортируемое API:
 *   init(rootElementId)
 *   dispose(rootElementId)
 *   setPageBackground(enabled)
 *   logout()
 *
 * Состояние (instances) живёт на уровне модуля: ES-модуль с одним и тем же URL
 * вычисляется браузером один раз, поэтому все импортирующие компоненты страницы
 * работают с общим реестром — как прежний глобальный window.WebShelfRibbon.
 */

/** @type {Map<string, { root: HTMLElement, onTabClick: Function }>} */
const instances = new Map();

/**
 * Инициализирует переключение вкладок для корневого элемента ленты.
 * @param {string} rootId - id корневого .ws-ribbon
 */
export function init(rootId) {
    if (!rootId || instances.has(rootId)) {
        return;
    }

    const root = document.getElementById(rootId);
    if (!root) {
        return;
    }

    /**
     * Обработчик клика по вкладке.
     * @param {MouseEvent} e
     */
    function onTabClick(e) {
        const tab = e.target.closest(".ws-ribbon-tab");
        if (!tab || !root.contains(tab)) {
            return;
        }

        const tabId = tab.getAttribute("data-tab");
        if (!tabId) {
            return;
        }

        root.querySelectorAll(".ws-ribbon-tab").forEach(function (t) {
            t.classList.remove("is-active");
            t.setAttribute("aria-selected", "false");
        });
        root.querySelectorAll(".ws-ribbon-panel").forEach(function (p) {
            p.classList.remove("is-active");
        });

        tab.classList.add("is-active");
        tab.setAttribute("aria-selected", "true");

        const panel = root.querySelector('.ws-ribbon-panel[data-panel="' + tabId + '"]');
        if (panel) {
            panel.classList.add("is-active");
        }
    }

    root.addEventListener("click", onTabClick);
    instances.set(rootId, { root: root, onTabClick: onTabClick });
}

/**
 * Освобождает обработчики для указанной ленты.
 * @param {string} rootId
 */
export function dispose(rootId) {
    const inst = instances.get(rootId);
    if (!inst) {
        return;
    }
    inst.root.removeEventListener("click", inst.onTabClick);
    instances.delete(rootId);
}

/**
 * Добавляет или снимает класс фона страницы для ленты.
 * @param {boolean} enabled
 */
export function setPageBackground(enabled) {
    if (enabled) {
        document.body.classList.add("ws-ribbon-page");
    } else {
        document.body.classList.remove("ws-ribbon-page");
    }
}

/**
 * Выход из системы.
 * 1) fetch POST /account/logout с redirect:manual и antiforgery-токеном
 *    (meta[name="ws-antiforgery-token"], см. App.razor) — сервер сбрасывает
 *    cookie (Set-Cookie), браузер НЕ следует за 302 (иначе Blazor/circuit
 *    ломает документ). Выход выполняется только по POST — защита от logout-CSRF.
 * 2) location.replace('/entry') — гарантированный переход на окно входа.
 */
export function logout() {
    var done = false;
    function goEntry() {
        if (done) {
            return;
        }
        done = true;
        window.location.replace("/entry");
    }

    try {
        var token = "";
        var meta = document.querySelector('meta[name="ws-antiforgery-token"]');
        if (meta) {
            token = meta.getAttribute("content") || "";
        }

        var headers = { "X-Requested-With": "XMLHttpRequest" };
        if (token) {
            headers["RequestVerificationToken"] = token;
        }

        fetch("/account/logout", {
            method: "POST",
            credentials: "same-origin",
            redirect: "manual",
            cache: "no-store",
            headers: headers
        }).then(goEntry, goEntry);
    } catch (e) {
        goEntry();
    }

    // Страховка, если fetch завис
    setTimeout(goEntry, 2000);
}
