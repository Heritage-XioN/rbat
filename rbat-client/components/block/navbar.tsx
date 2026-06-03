import Link from "next/link";

export function Navbar() {
  return (
    <header className="sticky top-4 z-50 mx-auto w-full max-w-7xl px-6">
      <div className="flex h-14 items-center justify-center rounded-2xl border border-rbat-border bg-rbat-card/60 px-6 shadow-lg shadow-black/40 backdrop-blur-xl">
        <Link
          href="/"
          className="flex items-center gap-2 transition-opacity hover:opacity-90"
        >
          <span className="font-mono text-base font-bold tracking-[0.25em] text-rbat-text uppercase">
            RBAT
          </span>
        </Link>
      </div>
    </header>
  );
}
