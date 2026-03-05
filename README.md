# mongo-auth-toolkit

A comprehensive authentication toolkit for Node.js backend services supporting Google OAuth, email/password authentication, and extensible user models with CRUD callbacks.

> ⚠️ **Under Development**: This project is currently under active development. APIs and features may change without notice.

## Features
- Google OAuth 2.0 authentication
- Email/password authentication
- Extensible user models
- CRUD callbacks
- TypeScript support

## Installation

```
npm install mongo-auth-toolkit
```

## Usage

```typescript
import { AuthService } from 'mongo-auth-toolkit';

const authService = new AuthService();
// ...use authService methods
```

## Scripts
- `npm run build` — Build the project
- `npm run dev` — Development mode (watch)
- `npm run lint` — Lint the code
- `npm test` — Run tests

## Publishing
This package uses [npm trusted publishing](https://docs.npmjs.com/trusted-publishers) via GitHub Actions. See `.github/workflows/publish.yaml`.

## License
MIT
