import js from '@eslint/js';
import tsPlugin from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';
import globals from 'globals';

// Keep the existing browser/Node global-name and writability footprint. The
// directly declared globals version is the same one ESLint 8 previously used.
export default [
  { ignores: ['**/dist/**', '**/node_modules/**', '**/*.cjs', 'tests/vectors/gen/**', '**/.*'] },
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.browser, ...globals.node },
    },
    rules: {
      ...js.configs.recommended.rules,
      // These were enabled by the previous eslint:recommended preset and are
      // still supported rules. Preserve them when adopting the newer preset.
      'no-extra-semi': 'error',
      'no-inner-declarations': ['error', 'functions', { blockScopedFunctions: 'disallow' }],
      'no-mixed-spaces-and-tabs': 'error',
      // ESLint 9 relaxed these defaults. Keep the previous block-function and
      // constant-loop checks, including while (true), during the format migration.
      'no-constant-condition': ['error', { checkLoops: 'all' }],
    },
  },
  {
    files: ['**/*.ts'],
    languageOptions: { parser: tsParser },
    plugins: { '@typescript-eslint': tsPlugin },
    rules: {
      ...tsPlugin.configs['eslint-recommended'].overrides[0].rules,
      ...tsPlugin.configs.recommended.rules,
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    },
  },
  {
    files: ['src/pake/**/*.ts'],
    rules: {
      'no-restricted-syntax': [
        'error',
        {
          selector: 'TSAsExpression > TSUnknownKeyword',
          message: '`as unknown as` is banned in src/pake — build wire messages via protocol factories from public DTOs, never launder a Password into a Hex field.',
        },
        {
          selector: 'TSTypeAssertion',
          message: 'Angle-bracket type assertions are banned in src/pake; use `expr as T` branding only.',
        },
      ],
    },
  },
];
