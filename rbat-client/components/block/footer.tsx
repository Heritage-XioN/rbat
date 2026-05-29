import Link from "next/link";

export function Footer() {
  return (
    <footer className="mt-auto border-t border-rbat-border bg-rbat-bg">
      <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-4 px-6 py-6 sm:flex-row">
        {/* Left side */}
        <div className="flex items-center gap-4 text-xs text-rbat-muted">
          <span className="font-semibold text-rbat-text-secondary">
            RBAT v0.1.0
          </span>
          <span>© 2026 RBAT Binary Analysis Toolkit</span>
        </div>

        {/* Right side links */}
        <nav className="flex items-center gap-6 text-xs text-rbat-muted">
          <Link
            href="/terms"
            className="transition-colors hover:text-rbat-text"
          >
            Terms
          </Link>
          <Link
            href="/privacy"
            className="transition-colors hover:text-rbat-text"
          >
            Privacy
          </Link>
          <Link
            href="/docs"
            className="transition-colors hover:text-rbat-text"
          >
            Documentation
          </Link>
          <Link href="/api" className="transition-colors hover:text-rbat-text">
            API
          </Link>
        </nav>
      </div>
    </footer>
  );
}
