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
      // Enforce a high floor on the CRYPTO CORE only (below current ~93%/82% so it
      // gates regressions without being brittle). The teaching UI is measured but not
      // gated — it is exercised structurally by the jsdom + runner tests.
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
