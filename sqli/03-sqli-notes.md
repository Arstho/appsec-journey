# Блок 3. SQL-инъекции (SQLi)

## 1. Что это

SQLi — уязвимость, при которой пользовательский ввод попадает в SQL-запрос
как КОД, а не как ДАННЫЕ. Возникает при конкатенации (склейке строк):

    const sql = `SELECT * FROM users WHERE email = '${email}'`;

Если email = `admin' --`, запрос ломается и выполняется не то, что задумал разработчик.

## 2. Почему опасно

- Утечка всей БД (UNION, blind extraction).
- Обход логина (`' OR '1'='1' --`).
- Модификация/удаление данных (UPDATE, DELETE, DROP TABLE).
- RCE через БД (MySQL INTO OUTFILE, MSSQL xp_cmdshell).
- DoS (SLEEP, BENCHMARK).
- #1 в OWASP Top 10 2021 (A03: Injection).

## 3. Термины

- **SQL** — язык запросов к реляционным БД.
- **Конкатенация** — склейка строк.
- **Prepared statement** — параметризованный запрос (`?`, `$1`, `:v`).
- **Placeholder** — метка в шаблоне запроса, куда подставляется значение.
- **ORM** — библиотека-обёртка над БД (Sequelize, TypeORM, Prisma, SQLAlchemy).
- **WAF** — Web Application Firewall.
- **RCE** — Remote Code Execution.
- **Blind SQLi** — результат не виден, но поведение меняется.
- **Second-order SQLi** — payload срабатывает при следующем запросе.

## 4. Виды SQLi

### In-band (результат виден в ответе)
- **Union-based** — `UNION SELECT` объединяет свой запрос с оригинальным.
- **Error-based** — данные вытаскиваются через текст ошибки БД.

### Blind (результат не виден)
- **Boolean-based** — ответ различается по «да/нет».
- **Time-based** — ответ различается по времени (SLEEP).

### Out-of-band
- Эксфильтрация через DNS/HTTP наружу (когда ничего не видно и не отличить).

### Second-order
- Payload сохраняется в БД, срабатывает позже в другом запросе.

### NoSQL Injection
- Не SQL, но та же идея. MongoDB: `{ "$ne": null }` обходит аутентификацию.

## 5. Классические payload'ы

### Обход логина
    admin' --
    ' OR '1'='1' --
    ' OR 1=1 --
    admin'/*

### UNION SELECT
    -1 UNION SELECT username, password FROM users
    -1 UNION SELECT NULL, username, password FROM users

### Time-based
    ' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a', SLEEP(5), 0)--

### DROP TABLE
    1; DROP TABLE users; --

## 6. Почему prepared statements работают

1. Приложение отправляет БД ШАБЛОН: `SELECT ... WHERE email = ?`.
2. БД парсит шаблон ОДИН РАЗ, строит план. `?` — метка.
3. Значение уходит ОТДЕЛЬНО и подставляется как ДАННЫЕ.
4. Структура запроса уже зафиксирована — значение её изменить не может.

## 7. Что prepared statements НЕ защищают

Идентификаторы (имена таблиц, столбцов), ORDER BY, LIMIT — их нельзя параметризовать.
Решение: белый список.

    const ALLOWED_SORT = ['id', 'name', 'price'];
    const sort = ALLOWED_SORT.includes(req.query.sort) ? req.query.sort : 'id';
    db.query(`SELECT * FROM products ORDER BY ${sort}`, []);

## 8. ORM не всегда спасает

Ломается при использовании escape hatch'ей:
- `sequelize.query(`... ${email}`)` — сырой SQL с конкатенацией.
- `sequelize.literal(...)`.
- Динамический ORDER BY.

## 9. Как защищаться (defense in depth)

1. **Prepared statements** — основная защита.
2. **Принцип наименьших привилегий** — у пользователя БД только нужные права.
   Никаких DROP, FILE, xp_cmdshell.
3. **Валидация типов** — `parseInt(id, 10)`, whitelist для enum'ов.
4. **Не показывать ошибки БД** — только generic-ответ, логи на сервере.
5. **WAF** — как дополнительный слой, не как основная защита.
6. **SAST/DAST** — регулярные сканы.
