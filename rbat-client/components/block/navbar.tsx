import Link from "next/link";

export function Navbar() {
  return (
    <header className="sticky top-0 z-50 w-full border-b border-rbat-border bg-rbat-bg/80 backdrop-blur-xl">
      <div className="mx-auto flex h-14 max-w-7xl items-center px-6">
        <Link href="/" className="flex items-center gap-2">
          <span className="text-lg font-bold tracking-tight text-rbat-text">
            RBAT
          </span>
        </Link>
      </div>
    </header>
  );
}
