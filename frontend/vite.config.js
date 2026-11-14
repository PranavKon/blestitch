import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In dev, forward /api/* to the FastAPI backend on :8000 so there is no CORS
// dance and the frontend code can just call fetch("/api/...").
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
});
