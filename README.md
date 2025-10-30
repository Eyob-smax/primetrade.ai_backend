<h1 align="center">Backend Developer (Intern) – Project Assignment for primetrade.ai</h1>

<h2>🚀 Overview</h2>
<p>
  This project is a secure, scalable backend system built with <b>NestJS, PostgreSQL, Prisma ORM, and Redis for scalability</b>, featuring RESTful APIs with JWT <b>(access and refresh token) authentication and role-based access(ADMIN and USER)</b>. It includes a basic React frontend for interacting with the APIs and testing CRUD.
</p>

<h2>🧩 Table of Contents</h2>
<ul>
  <li>Project Objective</li>
  <li>Features</li>
  <li>Tech Stack</li>
  <li>Database Models</li>
  <li>Architecture</li>
  <li>Setup Instructions</li>
  <li>API Documentation</li>
  <li>Frontend UI</li>
  <li>Security & Scalability Notes</li>
</ul>

<h2>⚙️ Features</h2>
<ul>
 <li><b>Backend</b>
  <ul>
    <li>User registration and login with hashed passwords (bcrypt): Protects user credentials by storing only non-reversible hashes, preventing data leaks if the database is compromised.</li>
    <li>JWT authentication (access & refresh tokens): Uses short-lived tokens for verification and longer-lived refresh tokens for session continuity, reducing unauthorized access risks.</li>
    <li>Secure token handling with refresh/revocation (stored in DB in refresh tokens table): Enables forced logout and session control by tracking issued tokens, blocking reused or stolen tokens.</li>
    <li>Role-based access control (USER & ADMIN): Restricts sensitive API routes to users with specific roles, helping enforce business rules and data protection.</li>
    <li>CRUD APIs for Product entity: Lets clients manage products (create, read, update, delete) and demonstrates RESTful API principles.</li>
    <li>Full request validation (using class-transformer and Pipes), and error responses (with interceptors/utilities): Prevents bad or malicious data and ensures consistent, clear error handling for developers and users.</li>
    <li>API documentation using Swagger and Postman: Makes endpoints discoverable and easy to test for other developers or reviewers.</li>
    <li>Redis caching for performance: Speeds up repeated data requests by storing results in fast memory, reducing API latency and server load.</li>
  </ul>
</li>

  <li><b>Frontend</b>
    <ul>
      <li>Built with React.js</li>
      <li>Register and login forms</li>
      <li>Dashboard with JWT-protected CRUD operations</li>
      <li>Protected routes for admins(RBAC)</li>
    </ul>
  </li>
</ul>

<h2>🧱 Tech Stack</h2>
<table>
  <tr><th>Purpose</th><th>Tech</th></tr>
  <tr><td>Framework</td><td>NestJS</td></tr>
  <tr><td>ORM</td><td>Prisma</td></tr>
  <tr><td>DB</td><td>PostgreSQL</td></tr>
  <tr><td>Auth</td><td>JWT (access & refresh)</td></tr>
  <tr><td>Caching</td><td>Redis</td></tr>
  <tr><td>Frontend</td><td>React.js and Shadcn</td></tr>
  <tr><td>Docs</td><td>Postman</td></tr>
</table>

<h2>🗃️ Database Models (Prisma)</h2>
<pre>
<code>
model User {
  user_id         Int      @id @default(autoincrement())
  name            String
  email           String   @unique
  hashed_password String
  role            Role     @default(USER)
  tokens          RefreshToken[]
  createdAt       DateTime @default(now())
  updatedAt       DateTime @updatedAt
  audit_logs      AuditLog[]
}

model Product {
id Int @id @default(autoincrement())
product_name String
description String
price String
in_stock Int
status TaskStatus @default(PENDING)
image_url String?
createdAt DateTime @default(now())
updatedAt DateTime @updatedAt
}

model RefreshToken {
token_id Int @id @default(autoincrement())
user_id Int
token String
expires_at DateTime
revoked Boolean @default(false)
user User @relation(fields: [user_id], references: [user_id], onDelete: Cascade, onUpdate: Cascade)
}

model AuditLog {
id Int @id @default(autoincrement())
user_id Int
action String
createdAt DateTime @default(now())
ipAddress String?
user User @relation(fields: [user_id], references: [user_id])
}

enum Role {
USER
ADMIN
}
enum TaskStatus {
PENDING
IN_PROGRESS
DONE
}
</code>

</pre>

<h2>🏗️ Architecture</h2>
<pre>
<code>
nestjs-backend/
├── src/
│   ├── auth/
│   ├── user/
│   ├── product/
│   ├── redis/
│   ├── database/
│   ├── common/
│   │   └── interceptors/
│   │   └── utils/
│   │   └── pipe/
│   │   └── guards/
│   │   └── decorators/
│   └── main.ts
│   └── app.module.ts
├── prisma/
│   └── schema.prisma
├── .env
├── package.json
└── README.md
frontend/
├── src/
│   ├── pages/
│   ├── components/
│   └── data/
│   └── hooks/
├── package.json
└── README.md
</code>
</pre>

<h2>🧰 Setup Instructions</h2>
<ol>
  <li><b>Clone the repository</b>
    <pre><code>git clone https://github.com/Eyob-smax/primetrade.ai.git
cd backend or cd frontend
</code></pre>
  </li>
  <li><b>Configure environment variables</b>
    <pre><code>cp .env 
# Fill:
  All neccessay env files
</code></pre>

  </li>
  <li><b>Install dependencies</b>
    <pre><code>npm install</code></pre>
  </li>
  <li><b>Run prisma migrations</b>
    <pre><code>npx prisma migrate dev</code></pre>
  </li>
  <li><b>Start the backend</b>
    <pre><code>npm run start:dev</code></pre>
  </li>
</ol>
<p><b>Frontend (if included):</b></p>
<ol>
  <li>Install and run frontend
    <pre><code>cd frontend
npm install
npm run dev
</code></pre>
  </li>
</ol>

<h2>📡 API Documentation</h2>
<ul>
  <li><b>Swagger</b>: Available at <a href="https://documenter.getpostman.com/view/40287469/2sB3WnxNAn"><code>Postman documentation link</code></a> while server is running</li>
  <li><b>Postman</b>: Collection file in <a href="https://.postman.co/workspace/My-Workspace~54cf7d5f-39b3-429c-8e08-e9a565944e2d/collection/40287469-c1ace104-6cb8-4372-878e-d67ad364da4c?action=share&creator=40287469"><code>Postman collections link</code></a></li>
</ul>

<h2>🧠 Frontend UI</h2>
<ul>
  <li>Register/login (with JWT token management)</li>
  <li>JWT-protected dashboard to view and manage products</li>
  <li>User-specific and admin flows</li>
  <li>Shows API messages/errors for each action</li>
</ul>

<h2>🔐 Security &amp; Scalability</h2>
<ul>
  <li>Bcrypt password hashing: Passwords are never stored directly; hashing with unique salt for each password prevents recovery even if database is leaked.</li>
  <li>JWT access & refresh tokens: Enables stateless, secure authentication and smooth token renewal workflow without forcing user re-login.</li>
  <li>Revocable tokens (DB/Redis): Refresh tokens are stored, invalidated, and rotated for secure logout and session management.</li>
  <li>Redis cache: High-speed memory store reduces database load and accelerates repeated product queries.</li>
  <li>Input validation: All data is checked for type and format, blocking malicious or malformed input at the API layer.</li>
  <li>Modular codebase: Cleanly separates features, making new modules easy to add and supporting enterprise growth.</li>
  <li>Scalable infrastructure: Ready for Docker, microservices, and multiple server deployment to handle high traffic.</li>
</ul>

<p align="center">
  <i>Built with NestJS, Prisma, PostgreSQL, Redis, and React for primetrade.ai assignment.</i>
</p>
