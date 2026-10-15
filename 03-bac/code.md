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
