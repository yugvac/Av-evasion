/* SentinelLab — API Service (VirusTotal-style) */

const API = '/api';

export const api = {
    // Upload & scan
    scanFile: async (file) => {
        const form = new FormData();
        form.append('file', file);
        const res = await fetch(`${API}/scan`, { method: 'POST', body: form });
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || 'Upload failed');
        return res.json();
    },

    // Get result by hash
    getResult: async (sha256) => {
        const res = await fetch(`${API}/scan/${sha256}?_=${Date.now()}`);
        if (!res.ok) throw new Error('Not found');
        return res.json();
    },

    // Search by hash or filename
    search: async (query) => {
        const res = await fetch(`${API}/search?q=${encodeURIComponent(query)}`);
        if (!res.ok) throw new Error('Search failed');
        return res.json();
    },

    // Scan history
    getHistory: async (limit = 50, offset = 0) => {
        const res = await fetch(`${API}/history?limit=${limit}&offset=${offset}`);
        if (!res.ok) throw new Error('Failed to load history');
        return res.json();
    },

    // Dashboard stats
    getStats: async () => {
        const res = await fetch(`${API}/stats`);
        if (!res.ok) throw new Error('Failed to load stats');
        return res.json();
    },
};

export default api;
