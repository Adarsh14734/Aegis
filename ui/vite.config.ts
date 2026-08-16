import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri serves the built assets from a file:// origin, so relative paths only.
export default defineConfig({
  plugins: [react()],
  base: "./",
  build: { outDir: "dist", emptyOutDir: true, target: "safari15" },
  server: { port: 5173, strictPort: true },
  clearScreen: false,
});
