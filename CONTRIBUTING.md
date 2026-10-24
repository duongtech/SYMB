# Contributing to SYMB

We welcome contributions from reverse engineers, security researchers, and AI tool builders worldwide.

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/duongtech/SYMB.git
   cd SYMB
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Run dev server:
   ```bash
   npm run dev
   ```

## Pull Request Guidelines

- Ensure all TypeScript code compiles with 0 errors (`npm run build`).
- New MCP tools must define input/output contracts using Zod.
- Include unit tests for symbolic solvers.
