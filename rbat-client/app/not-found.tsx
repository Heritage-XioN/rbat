import { Home, TerminalSquare } from "lucide-react";
import Link from "next/link";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-rbat-bg px-6 font-sans antialiased text-rbat-text">
      {/* 404 Error Box */}
      <div className="flex w-full max-w-md flex-col items-center border border-rbat-border bg-rbat-card/40 p-8 text-center rounded-2xl shadow-xl shadow-black/50 backdrop-blur-xl">
        {/* Glow Icon */}
        <div className="mb-6 flex size-16 items-center justify-center rounded-xl border border-red-500/30 bg-red-500/10">
          <TerminalSquare className="size-8 text-red-500 animate-pulse" />
        </div>

        {/* Cyber Error Badge */}
        <span className="mb-4 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-1 font-mono text-xs font-bold tracking-widest text-red-500 uppercase">
          Error 404: Not Found
        </span>

        {/* Title */}
        <h1 className="mb-3 text-2xl font-bold tracking-tight text-rbat-text">
          Target Not Found
        </h1>

        {/* Message */}
        <p className="mb-8 font-mono text-sm leading-relaxed text-rbat-muted">
          The requested resource could not be located.
        </p>

        {/* Go back CTA */}
        <Link href="/" className="w-full block">
          <Button className="w-full gap-2 border border-rbat-accent/30 bg-rbat-accent/10 text-rbat-accent hover:bg-rbat-accent/20">
            <Home className="size-4" />
            <span className="font-mono text-xs font-bold uppercase tracking-wider">
              Return to dashboard
            </span>
          </Button>
        </Link>
      </div>
    </div>
  );
}
