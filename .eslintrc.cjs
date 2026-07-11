/* eslint config — enforces invariant #1: no unsafe type assertions inside src/pake,
   so a Password can never be laundered into a WireMsg via `as unknown as`. */
module.exports = {
  root: true,
  parser: "@typescript-eslint/parser",
  parserOptions: { ecmaVersion: 2022, sourceType: "module" },
  plugins: ["@typescript-eslint"],
  extends: ["eslint:recommended", "plugin:@typescript-eslint/recommended"],
  env: { browser: true, es2022: true, node: true },
  ignorePatterns: ["dist", "node_modules", "*.cjs", "tests/vectors/gen/**"],
  rules: {
    "@typescript-eslint/no-explicit-any": "off",
    "@typescript-eslint/no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
  },
  overrides: [
    {
      // The password-stays-home barrier (invariant #1): ban the specific unsafe
      // laundering pattern `as unknown as X` inside the crypto core. Normal
      // branding assertions (`bytes as Hex`) stay legal; the double-assertion that
      // would smuggle a Password into a Hex-typed wire field is what we forbid.
      files: ["src/pake/**/*.ts"],
      rules: {
        "no-restricted-syntax": [
          "error",
          {
            selector: "TSAsExpression > TSUnknownKeyword",
            message:
              "`as unknown as` is banned in src/pake — build wire messages via protocol factories from public DTOs, never launder a Password into a Hex field.",
          },
          {
            selector: "TSTypeAssertion",
            message:
              "Angle-bracket type assertions are banned in src/pake; use `expr as T` branding only.",
          },
        ],
      },
    },
  ],
};
