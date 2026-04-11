import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Base URL is injected by the CI pipeline for GitHub Pages deployment.
// Locally it defaults to '/' so `npm run dev` works without configuration.
export default defineConfig({
  plugins: [react()],
  base: process.env.VITE_BASE_URL || '/',
  build: {
    outDir: 'build', // match the workflow's publish_dir: dashboard/build
  },
});
