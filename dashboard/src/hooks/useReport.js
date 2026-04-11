import { useState, useEffect } from 'react';

/**
 * Fetches a JSON report file from the /reports/ directory.
 * Works both locally (Vite dev server) and on GitHub Pages (static files).
 */
export function useReport(filename) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  useEffect(() => {
    // import.meta.env.BASE_URL reflects the `base` set in vite.config.js
    fetch(`${import.meta.env.BASE_URL}reports/${filename}`)
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status} — ${filename} not found`);
        return res.json();
      })
      .then(setData)
      .catch(setError)
      .finally(() => setLoading(false));
  }, [filename]);

  return { data, loading, error };
}
