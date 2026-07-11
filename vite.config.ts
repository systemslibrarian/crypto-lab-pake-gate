import { defineConfig } from "vite";

// Static site for GitHub Pages. Relative base so asset URLs resolve under
// https://<user>.github.io/crypto-lab-pake-gate/.
export default defineConfig({
  base: "./",
  build: {
    target: "es2022",
    outDir: "dist",
  },
});
