# Threat Model: FoodDelivery
Дата: 2026-09-29  
Версия: 1.0

# АКТИВЫ:  
 - A1. PII пользователей (email, телефон, адрес)  
 - A2. Платёжные токены Stripe  
 - A3. JWT-секрет  
 - A4. Сервис заказа еды  
 - A5. Репутация бренда  

# УГРОЗЫ (STRIDE):
 - T1. Spoofing: подделка JWT при утечке секрета
 - T2. Tampering: подмена ID в /api/orders/:id
 - T3. Repudiation: отсутствие логов заказов
 - T4. Information Disclosure: чтение чужих заказов (IDOR/BOLA)
 - T5. DoS: спам-запросы на /api/orders
 - T6. Elevation of Privilege: изменение чужого заказа

# УЯЗВИМОСТИ:
 - V1. Авторизация только на фронте для /api/orders/:id
 - V2. .env в git-истории
 - V3. lodash@4.17.11 с CVE-2021-23337 (prototype pollution)
 - V4. JWT в localStorage (доступен через XSS)

# РИСКИ:
 - R1. IDOR → утечка PII → штраф GDPR 4% годового оборота
 - R2. .env → компромат Stripe key → финансовое мошенничество
 - R3. Уязвимая lodash → RCE через prototype pollution
 - R4. JWT в localStorage → угон сессии при XSS

# МЕРЫ:
 - M1. Server-side авторизация в каждом эндпоинте
 - M2. Ротация секретов + git filter-repo + gitleaks в CI
 - M3. npm audit + Dependabot → обновить lodash
 - M4. httpOnly + Secure + SameSite cookie для JWT
