// Tailwind Configuration
if (typeof tailwind !== 'undefined') {
    tailwind.config = {
        darkMode: 'class',
        theme: {
            extend: {
                colors: {
                    dark: {
                        bg: '#0f172a',
                        card: '#1e293b',
                        border: '#334155'
                    }
                }
            }
        }
    };
}
