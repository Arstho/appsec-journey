# Блок 2 — Конспект. XSS (Cross-Site Scripting)

**Дата:** 2026-09-30
**Статус:** пройдено

---

## 1. Что такое XSS

**XSS (Cross-Site Scripting)** — класс уязвимостей, при котором злоумышленник заставляет браузер жертвы выполнить JavaScript, написанный атакующим, в контексте уязвимого сайта.

**Ключевая идея:** браузер не различает, кто автор скрипта — сайт или атакующий. Если код попал в HTML и выглядит как валидный `<script>`, `onerror`, `javascript:` URL — браузер выполнит его.

**Что даёт атакующему XSS:**
- Доступ к cookies (если не `HttpOnly`)
- Доступ к `localStorage` / `sessionStorage`
- Полный контроль над DOM
- Возможность делать API-запросы от имени жертвы
- Возможность изменить UI (фейковые формы, фишинг)
- Кейлоггер на странице
- Криптомайнер

**OWASP Top 10:** XSS входит в **A03:2021 Injection**.

---

## 2. Три типа XSS

### 2.1. Reflected XSS
- Payload не хранится на сервере, а «отражается» в ответе.
- Нужен клик жертвы по специально составленной ссылке.
- Сервер вставляет пользовательский ввод в HTML без экранирования.
- Типичные места: поиск, страницы ошибок, фильтры.

**Пример:**
```js
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`<h1>Результаты поиска: ${query}</h1>`);
});
```
Эксплуатация: `/search?q=<img src=x onerror=alert(1)>`

### 2.2. Stored XSS
- Payload сохраняется в БД или ином хранилище на сервере.
- Срабатывает у **всех**, кто откроет страницу с этим контентом.
- Не нужна ссылка — жертвы приходят сами.
- Может быть «червячным» (Samy worm в MySpace, TweetDeck 2014).
- Типичные места: комментарии, посты, профили, имена файлов.

### 2.3. DOM-based XSS
- Уязвимость **на клиенте**, сервер отдаёт чистый HTML.
- JS читает данные из **source** и передаёт в **sink** без санитизации.
- Сервер может годами не знать о дыре.
- Сканеры DAST часто не находят — нужен SAST или ручной аудит.

**Source (источники недоверенных данных):**
- `location.href`, `location.hash`, `location.search`
- `document.URL`, `document.documentURI`, `document.referrer`
- `window.name`
- `postMessage` (`event.data`)
- `localStorage`, `sessionStorage`, `IndexedDB`
- `history.state`

**Sink (опасные приёмники):**
- `element.innerHTML`, `element.outerHTML`
- `document.write()`, `document.writeln()`
- `eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)`
- `element.setAttribute('onclick', ...)`
- `location.href = 'javascript:...'`
- jQuery: `.html()`, `$()`, `.append()`
- React: `dangerouslySetInnerHTML`

**Правило:** XSS-баг = недоверенный source **без санитизации** попадает в опасный sink.

---

## 3. React: где защищает, где нет

### React экранирует внутри `{}`
```jsx
<h1>Привет, {name}!</h1>
// <name> = "<script>alert(1)</script>"
// → <h1>Привет, &lt;script&gt;alert(1)&lt;/script&gt;!</h1>
```

**Экранирование (escaping)** — замена специальных HTML-символов на сущности:
`&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`, `'` → `&#x27;`.

### Где React НЕ защищает
1. `dangerouslySetInnerHTML` — сознательное отключение экранирования.
2. Прямые DOM-манипуляции через `ref.current.innerHTML`.
3. `eval`, `new Function`, `setTimeout(string)`.
4. Вставка URL в `href` / `src` без проверки схемы (`javascript:`).
5. Сторонние библиотеки, которые делают `innerHTML` внутри.

**Аксиома:** `dangerouslySetInnerHTML` — не фикс, а **причина** проблемы. Это крайняя мера, только с DOMPurify.

---

## 4. DOMPurify — санитизация HTML

**Санитизация** — удаление/нейтрализация опасных частей входных данных (в отличие от экранирования, которое **всё** превращает в текст).

**DOMPurify** — JS-библиотека, работает в браузере и Node.js (через `jsdom`).

### Принцип работы
1. Парсит строку в DOM.
2. Проходит по элементам и атрибутам.
3. Сверяет с **белым списком** (allow-list).
4. Удаляет всё, чего нет в белом списке.

**Почему allow-list, а не deny-list:**
- Чёрный список бесконечен (новые теги, атрибуты, quirks).
- Белый список конечен: явно перечисли, что разрешено.

### Пример правильной настройки
```jsx
import DOMPurify from 'dompurify';

const SANITIZE_CONFIG = {
  ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li'],
  ALLOWED_ATTR: ['href', 'title'],
  ALLOWED_URI_REGEXP: /^(?:https?|mailto|tel):/i,
};

function SafeComment({ text }) {
  const clean = DOMPurify.sanitize(text, SANITIZE_CONFIG);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

### Что DOMPurify НЕ защищает
- Неправильный **контекст** (санитизировал HTML, вставил в атрибут).
- CSS-инъекции (нужна опция `FORBID_ATTR: ['style']`).
- JS-контекст (`eval`, `new Function`).
- Бизнес-логику (ссылка на `evil.example` безопасна технически, но = фишинг).
- Санитизацию **на бэке** — её надо делать отдельно.

---

## 5. CSP как второй слой

**CSP (Content Security Policy)** — HTTP-заголовок, ограничивающий источники контента.

### Пример строгого CSP
```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-<random>' 'strict-dynamic';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  connect-src 'self' https://api.example.com;
  font-src 'self';
  object-src 'none';
  base-uri 'self';
  frame-ancestors 'none';
  form-action 'self';
  upgrade-insecure-requests;
```

**nonce** — одноразовый случайный токен, генерируется для каждого ответа.
**`'strict-dynamic'`** — доверяет скриптам, загруженным доверенными скриптами.

### Что CSP НЕ делает
- Не мешает краже данных через разрешённые скрипты (заражённая CDN-библиотека).
- Не мешает DOM-based XSS, если инлайн-скрипт уже прошёл.
- Не заменяет экранирование и санитизацию.

### Ключевой нюанс
- `'unsafe-inline'` в `script-src` = CSP почти бесполезен.
- **`<script>` через `innerHTML` / `dangerouslySetInnerHTML` не выполняется** — это спецификация HTML, защита самого DOM API.
- **А `<img onerror>`, `<svg onload>`, `<iframe srcdoc>`, `<a href="javascript:">` — выполняются**, если `'unsafe-inline'` разрешён (это inline-обработчики событий).

---

## 6. Словарь терминов

- **XSS** — Cross-Site Scripting.
- **Reflected XSS** — payload отражается сервером в ответе.
- **Stored XSS** — payload хранится на сервере.
- **DOM-based XSS** — уязвимость в клиентском JS.
- **Source** — источник недоверенных данных (`location.hash`, `postMessage`…).
- **Sink** — опасный приёмник (`innerHTML`, `eval`, `document.write`…).
- **Экранирование (escaping)** — замена специальных символов на сущности.
- **Санитизация (sanitization)** — удаление опасных частей.
- **DOMPurify** — JS-библиотека санитизации HTML.
- **Allow-list** — разрешено только перечисленное.
- **Deny-list** — запрещено перечисленное.
- **CSP** — Content Security Policy.
- **nonce** — одноразовый токен для CSP.
- **`dangerouslySetInnerHTML`** — React-проп для сырого HTML.
- **mXSS** — mutation XSS.
- **PII** — Personally Identifiable Information.
