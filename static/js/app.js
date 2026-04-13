/**
 * Spotalytics - Custom JavaScript
 * Global utilities and helper functions
 */

// Global utilities object
window.SpotifyDataTool = {
    /**
     * Format a number with commas
     */
    formatNumber(num) {
        return num.toLocaleString();
    },

    /**
     * Format date to human-readable string
     */
    formatDate(dateString) {
        if (!dateString || dateString === 'Unknown') return 'Unknown';
        try {
            const date = new Date(dateString);
            return date.toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'short',
                day: 'numeric'
            });
        } catch {
            return dateString;
        }
    },

    /**
     * Format milliseconds to minutes
     */
    msToMinutes(ms) {
        return (ms / 60000).toFixed(1);
    },

    /**
     * Format milliseconds to hours
     */
    msToHours(ms) {
        return (ms / 3600000).toFixed(1);
    },

    /**
     * Truncate string to specified length
     */
    truncate(str, maxLength = 50) {
        if (str.length <= maxLength) return str;
        return str.slice(0, maxLength) + '...';
    },

    /**
     * Debounce function
     */
    debounce(func, wait = 300) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    /**
     * Show toast notification
     */
    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `fixed bottom-4 right-4 px-6 py-3 rounded-lg shadow-lg text-white z-50 transition-opacity duration-300`;

        const colors = {
            info: 'bg-blue-500',
            success: 'bg-green-500',
            error: 'bg-red-500',
            warning: 'bg-yellow-500'
        };

        toast.classList.add(colors[type] || colors.info);
        toast.textContent = message;

        document.body.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    },

    /**
     * Copy text to clipboard
     */
    async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            this.showToast('Copied to clipboard!', 'success');
        } catch (err) {
            this.showToast('Failed to copy', 'error');
            console.error('Copy failed:', err);
        }
    },

    /**
     * Fetch with error handling
     */
    async fetchAPI(url, options = {}) {
        try {
            const response = await fetch(url, options);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return await response.json();
        } catch (error) {
            console.error('API fetch error:', error);
            this.showToast('Failed to fetch data', 'error');
            throw error;
        }
    },

    /**
     * Create Chart.js default configuration
     */
    getChartDefaults() {
        return {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    padding: 12,
                    titleFont: {
                        size: 14,
                        weight: 'bold'
                    },
                    bodyFont: {
                        size: 13
                    },
                    cornerRadius: 4
                }
            }
        };
    }
};

// HTMX event listeners
document.body.addEventListener('htmx:beforeRequest', (event) => {
    console.log('HTMX request:', event.detail.path);
});

document.body.addEventListener('htmx:afterRequest', (event) => {
    if (!event.detail.successful) {
        console.error('HTMX request failed:', event.detail);
        window.SpotifyDataTool.showToast('Request failed', 'error');
    }
});

document.body.addEventListener('htmx:responseError', (event) => {
    console.error('HTMX response error:', event.detail);
    window.SpotifyDataTool.showToast('Server error occurred', 'error');
});

// Log when page is ready
document.addEventListener('DOMContentLoaded', () => {
    console.log('Spotalytics loaded');
});

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = window.SpotifyDataTool;
}
