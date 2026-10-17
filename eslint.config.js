// ESLint flat config: recommended JavaScript rules and type-aware TypeScript rules.
import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['node_modules/', 'reports/'] },

  js.configs.recommended,
  // Type-aware rules (they read tsconfig.json), e.g. no-floating-promises: a missing `await` lets a check
  // finish before its request did, and a test can pass without having tested anything.
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/consistent-type-imports': 'error',
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },

  // node:test files: describe() and it() return promises that the test runner itself awaits.
  { files: ['tests/**/*.test.ts'], rules: { '@typescript-eslint/no-floating-promises': 'off' } },
  { files: ['eslint.config.js'], ...tseslint.configs.disableTypeChecked },

  // Last: turn off every rule that would fight with Prettier's formatting.
  prettier,
);
