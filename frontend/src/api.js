import axios from 'axios';

const defaultApiBase = (typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'))
    ? 'http://localhost:5001/api'
    : '/api';

export const API_BASE_URL = import.meta.env.VITE_API_URL || defaultApiBase;
export const api = axios.create({baseURL: API_BASE_URL});
api.interceptors.request.use(c=>{const t=localStorage.getItem('token');if(t)c.headers.Authorization=`Bearer ${t}`;return c})
api.interceptors.response.use(
    response => response,
    error => {
        const url = error.config?.url || '';
        if (error.response?.status === 401 && !url.startsWith('/auth/')) {
            localStorage.removeItem('token');
            localStorage.removeItem('user');
            window.location.reload();
        }
        return Promise.reject(error);
    }
);
