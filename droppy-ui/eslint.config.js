import tseslint from 'typescript-eslint'
import { globalIgnores } from 'eslint/config'
import importPlugin from 'eslint-plugin-import'
import simpleImportSort from 'eslint-plugin-simple-import-sort'

export default tseslint.config([
  globalIgnores(['dist']),
  {
    files: ['**/*.{ts,tsx}'],
    plugins: {
      'import': importPlugin,
      'simple-import-sort': simpleImportSort,
    },
    extends: [
      'eslint:recommended',
      'plugin:import/recommended',
      'plugin:import/typescript',
      'plugin:react-hooks/recommended',
      'plugin:@typescript-eslint/recommended',
      'plugin:@typescript-eslint/strict',
    ],
    settings: {
      'import/parsers': {
        '@typescript-eslint/parser': ['.ts', '.tsx'],
      },
      'import/resolver': {
        typescript: {
          alwaysTryTypes: true,
          project: './tsconfig.json',
        },
      },
      react: {
        version: 'detect',
      },
    },
    rules: {
      // Import rules
      'import/no-unresolved': 'error',
      'import/named': 'error',
      'import/namespace': 'error',
      'import/default': 'error',
      'import/export': 'error',
      'import/order': ['error', {
        'groups': [
          'builtin',
          'external',
          'internal',
          'parent',
          'sibling',
          'index',
          'object',
          'type'
        ],
        'pathGroups': [
          {
            pattern: 'react',
            group: 'external',
            position: 'before',
          },
        ],
        'pathGroupsExcludedImportTypes': ['react'],
        'newlines-between': 'always',
        'alphabetize': {
          order: 'asc',
          caseInsensitive: true,
        },
      }],
      'simple-import-sort/imports': 'error',
      'simple-import-sort/exports': 'error',
      'import/first': 'error',
      'import/newline-after-import': 'error',
      'import/no-duplicates': 'error',
      'import/no-absolute-path': 'error',
      'import/no-self-import': 'error',
      'import/no-cycle': 'error',
      'import/no-useless-path-segments': 'error',
      'import/no-mutable-exports': 'error',
      'import/no-unused-modules': 'error',

      // Code structure rules
      'max-lines': ['warn', { max: 300, skipBlankLines: true, skipComments: true }],
      'max-lines-per-function': ['warn', { max: 50, skipBlankLines: true, skipComments: true }],
      'max-params': ['warn', 4],
      'max-depth': ['warn', 4],
      'complexity': ['warn', 10],
      'max-len': ['warn', { code: 100, ignoreUrls: true }],
      'no-multiple-empty-lines': ['error', { max: 1, maxEOF: 1 }],
      'padding-line-between-statements': [
        'error',
        { blankLine: 'always', prev: '*', next: 'return' },
        { blankLine: 'always', prev: ['const', 'let', 'var'], next: '*' },
        { blankLine: 'any', prev: ['const', 'let', 'var'], next: ['const', 'let', 'var'] },
      ],
      'lines-between-class-members': ['error', 'always', { exceptAfterSingleLine: true }],
      'no-var': 'error',
      'prefer-const': 'error',
      'object-shorthand': 'error',
      'no-else-return': 'error',
      'no-lonely-if': 'error',
      'no-unneeded-ternary': 'error',
      'no-nested-ternary': 'warn',
      'no-unused-vars': ['error', { 
        args: 'after-used', 
        ignoreRestSiblings: true,
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_',
      }],
      'no-use-before-define': ['error', {
        functions: false,
        classes: true,
        variables: true,
      }],
      'camelcase': ['error', {
        properties: 'always',
        ignoreImports: false,
      }],
      'no-array-constructor': 'error',
      'no-multi-assign': 'error',
      'no-underscore-dangle': 'error',
      'no-useless-computed-key': 'error',
      'no-useless-constructor': 'error',
      'no-useless-rename': 'error',
      'prefer-template': 'error',
      'no-console': 'warn',
      'no-debugger': 'warn',
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-param-reassign': 'error',
      'prefer-arrow-callback': 'error',
      'arrow-body-style': ['error', 'as-needed'],
    },
  },
])
