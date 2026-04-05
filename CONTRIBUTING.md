# Contributing to SyslogStudio

Thank you for your interest in contributing!

## Development Setup

### Prerequisites

- [Go](https://go.dev/dl/) 1.23+
- [Node.js](https://nodejs.org/) 18+
- [Wails CLI](https://wails.io/docs/gettingstarted/installation) v2

### Getting Started

```bash
git clone https://github.com/Wasabules/SyslogStudio.git
cd SyslogStudio
cd frontend && npm install && cd ..
wails dev
```

## Workflow

1. Fork the repository
2. Create a feature branch from `main` (`git checkout -b feature/my-feature`)
3. Make your changes
4. Run checks before committing:
   ```bash
   go vet ./...
   go test -race ./...
   cd frontend && npx svelte-check --tsconfig ./tsconfig.json && npm run build
   ```
5. Commit with a clear message (e.g., `feat: add date range filter`, `fix: UDP race condition`)
6. Push and open a Pull Request against `main`

## Code Style

- **Go**: follow standard `gofmt` formatting. Use `log/slog` for logging.
- **TypeScript**: strict mode enabled. Use `$_('key')` from svelte-i18n for all UI strings.
- **CSS**: use CSS custom properties (`var(--bg-primary)`, etc.) for theming. No hardcoded colors.

## i18n

All user-facing strings must be in both `frontend/src/lib/i18n/en.json` and `fr.json`. Use the `$_('section.key')` pattern in Svelte components.

## Adding a Wails Binding

1. Add the exported method to `app.go`
2. Run `wails dev` or `wails generate module` to regenerate `frontend/wailsjs/`
3. Add a typed wrapper in `frontend/src/lib/api.ts`
4. Import from `lib/api.ts` in components (never directly from `wailsjs/`)

## Reporting Issues

Open an issue on GitHub with:
- Steps to reproduce
- Expected vs actual behavior
- OS and version
