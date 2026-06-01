"use client";

import { AlertOctagon, Home, RefreshCcw } from "lucide-react";
import Link from "next/link";
import { useEffect } from "react";
import { Button } from "@/components/ui/button";

interface ErrorProps {
  error: Error & { digest?: string };
  reset: () => void;
}

export default function Error({ error, reset }: ErrorProps) {
  useEffect(() => {
    // Log the error for developer analysis
    console.error("Critical Client Exception:", error);
  }, [error]);

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-rbat-bg px-6 font-sans antialiased text-rbat-text">
      {/* Error Card */}
      <div className="flex w-full max-w-md flex-col items-center border border-red-500/20 bg-rbat-card/40 p-8 text-center rounded-2xl shadow-xl shadow-black/50 backdrop-blur-xl">
        {/* Glow Hazard Icon */}
        <div className="mb-6 flex size-16 items-center justify-center rounded-xl border border-red-500/30 bg-red-500/10">
          <AlertOctagon className="size-8 text-red-500 animate-bounce" />
        </div>

        {/* Cyber Fault Badge */}
        <span className="mb-4 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-1 font-mono text-xs font-bold tracking-widest text-red-500 uppercase">
          Fault Code: Critical Client Exception
        </span>

        {/* Title */}
        <h1 className="mb-3 text-2xl font-bold tracking-tight text-rbat-text">
          Runtime Core Exception
        </h1>

        {/* Message */}
        <p className="mb-6 font-mono text-sm leading-relaxed text-rbat-muted">
          An unexpected error occurred within the RBAT client runtime. The
          current analysis session may be unstable. Please review the error
          details below and take appropriate action.
        </p>

        {/* Diagnostic console snippet */}
        <div className="mb-8 w-full rounded-lg border border-rbat-border bg-black/60 p-4 text-left font-mono text-[10px] text-red-400/80">
          <p className="font-bold text-red-400"># EXCEPTION LOG:</p>
          <p className="mt-1 break-all">
            {error.name || "Error"}:{" "}
            {error.message || "Unknown segmentation fault"}
          </p>
          {error.digest && (
            <p className="mt-1 text-rbat-muted break-all">
              digest: {error.digest}
            </p>
          )}
        </div>

        {/* Action button container */}
        <div className="flex w-full flex-col gap-3 sm:flex-row">
          <Button
            onClick={() => reset()}
            className="flex-1 gap-2 border border-red-500/30 bg-red-500/10 text-red-500 hover:bg-red-500/20"
          >
            <RefreshCcw className="size-3.5" />
            <span className="font-mono text-[10px] font-bold uppercase tracking-wider">
              Re-init Core
            </span>
          </Button>

          <Link href="/" className="flex-1">
            <Button
              variant="outline"
              className="w-full gap-2 border-rbat-border bg-rbat-card text-rbat-text hover:bg-rbat-card/80"
            >
              <Home className="size-3.5" />
              <span className="font-mono text-[10px] font-bold uppercase tracking-wider">
                Safe Mode
              </span>
            </Button>
          </Link>
        </div>
      </div>
    </div>
  );
}
