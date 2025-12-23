import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';

// Mock component for testing (extract from App.tsx when ready)
const ExpirationDisplay = ({ issuedAt, expiresAt }: { issuedAt: number; expiresAt: number }) => {
    const now = Date.now() / 1000;
    const remaining = expiresAt - now;
    const isExpired = remaining <= 0;

    const formatTime = (seconds: number) => {
        if (seconds <= 0) return 'Expired';
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        const s = Math.floor(seconds % 60);
        if (h > 0) return `${h}h ${m}m ${s}s`;
        if (m > 0) return `${m}m ${s}s`;
        return `${s}s`;
    };

    return (
        <div>
            <span style={{ color: isExpired ? 'red' : 'green' }}>
                {formatTime(remaining)}
            </span>
        </div>
    );
};

describe('ExpirationDisplay', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    it('shows correct time remaining for valid warrant', () => {
        const now = Date.now() / 1000;
        const issuedAt = now - 1800; // 30 min ago
        const expiresAt = now + 1800; // 30 min from now

        render(<ExpirationDisplay issuedAt={issuedAt} expiresAt={expiresAt} />);
        expect(screen.getByText(/30m/)).toBeInTheDocument();
    });

    it('shows expired state for expired warrant', () => {
        const now = Date.now() / 1000;
        const issuedAt = now - 7200; // 2 hours ago
        const expiresAt = now - 1800; // expired 30 min ago

        render(<ExpirationDisplay issuedAt={issuedAt} expiresAt={expiresAt} />);
        expect(screen.getByText('Expired')).toBeInTheDocument();
    });

    it('formats hours correctly', () => {
        const now = Date.now() / 1000;
        const issuedAt = now;
        const expiresAt = now + 3665; // 1h 1m 5s

        render(<ExpirationDisplay issuedAt={issuedAt} expiresAt={expiresAt} />);
        expect(screen.getByText(/1h 1m 5s/)).toBeInTheDocument();
    });

    it('formats minutes correctly', () => {
        const now = Date.now() / 1000;
        const issuedAt = now;
        const expiresAt = now + 125; // 2m 5s

        render(<ExpirationDisplay issuedAt={issuedAt} expiresAt={expiresAt} />);
        expect(screen.getByText(/2m 5s/)).toBeInTheDocument();
    });

    it('formats seconds correctly', () => {
        const now = Date.now() / 1000;
        const issuedAt = now;
        const expiresAt = now + 45; // 45s

        render(<ExpirationDisplay issuedAt={issuedAt} expiresAt={expiresAt} />);
        expect(screen.getByText(/45s/)).toBeInTheDocument();
    });
});
