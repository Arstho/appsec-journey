# Сценарий: FoodDelivery (учебный)

## Архитектура
- Frontend: React SPA, app.fooddelivery.example
- Backend: Node.js/Express, api.fooddelivery.example
- DB: PostgreSQL (users, orders, payments)
- Auth: JWT в localStorage
- Payments: Stripe

## Известные факты
- GET /api/orders/:id — авторизация только на фронте
- .env закоммичен в ветку feature/payments, удалён через git reset --hard
- lodash@4.17.11 в зависимостях

## Задача
Составить модель угроз по STRIDE + CIA.
