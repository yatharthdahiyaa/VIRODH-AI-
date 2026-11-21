import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `npm run dev` proxies backend paths to the Node server (port 3000). `npm run build` → dist/, served by Node.
const backend = "http://127.0.0.1:3000";
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: Object.fromEntries(
      ["/auth", "/bff", "/api", "/v1", "/lab", "/static", "/docs", "/openapi.json", "/readyz", "/healthz"].map((p) => [
        p,
        { target: backend, changeOrigin: false },
      ]),
    ),
  },
  build: { outDir: "dist", sourcemap: false, chunkSizeWarningLimit: 900 },
});
