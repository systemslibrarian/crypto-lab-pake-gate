import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    globals: false,
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/main.ts", "src/**/*.d.ts"],
      reporter: ["text-summary", "text", "html"],
      // Enforce a high floor on the CRYPTO CORE only (below current ~92%/83% so it
      // gates regressions without being brittle). The teaching UI is measured but not
      // gated — it is exercised structurally by the jsdom + runner tests.
      //
      // Those headline numbers moved when vitest went 2 -> 4 without the code
      // changing: v8 coverage is now remapped through the AST, so the statement and
      // branch denominators are the source's, not the transpiled bundle's. The floor
      // below is unchanged; tests/encoding.test.ts was added to clear it.
      thresholds: {
        "src/pake/**/*.ts": {
          statements: 90,
          branches: 78,
          functions: 90,
          lines: 90,
        },
      },
    },
  },
});
