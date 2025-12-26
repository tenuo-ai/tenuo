export const truncate = (str: string, n: number = 12) => {
    if (!str) return '';
    return str.length > n ? str.slice(0, n) + '...' : str;
};

// Helper: PEM Detection & Cleanup
export const cleanInput = (input: string): { b64: string; isPem: boolean } => {
    const trimmed = input.trim();

    // If it looks like PEM, extract the payload
    const pemMatch = trimmed.match(
        /-----BEGIN TENUO WARRANT-----([\s\S]*?)-----END TENUO WARRANT-----/
    );

    if (pemMatch) {
        return {
            b64: pemMatch[1].replace(/\s+/g, ''),
            isPem: true
        };
    }

    // Otherwise assume raw base64, just strip whitespace
    return {
        b64: trimmed.replace(/\s+/g, ''),
        isPem: false
    };
};

export const generateId = () => Math.random().toString(36).substring(2, 9);
