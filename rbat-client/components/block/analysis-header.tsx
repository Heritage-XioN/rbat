"use client";

import { Download, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useAnalysisStore } from "@/lib/store/analysis-store";

export function AnalysisHeader() {
  const { fileName, reset } = useAnalysisStore();

  const handleReanalyze = () => {
    reset();
  };

  return (
    <section className="mx-auto w-full max-w-7xl px-6 pt-8 pb-4">
      {/* Label */}
      <p className="mb-1 text-xs font-medium uppercase tracking-widest text-rbat-muted">
        analysis result
      </p>

      {/* File name row */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3">
          <h1
            id="analysis-header-title"
            className="font-mono text-2xl font-bold text-rbat-text"
          >
            {fileName || "No Binary Loaded"}
          </h1>
          <Badge className="rounded-md bg-rbat-accent px-3 py-1 text-xs font-bold text-rbat-bg hover:bg-rbat-accent/90">
            ANALYZE
          </Badge>
        </div>

        {/* Action buttons */}
        <div className="flex items-center gap-3">
          <Button
            id="export-report-btn"
            variant="outline"
            className="gap-2 border-rbat-border bg-rbat-card text-rbat-text hover:bg-rbat-card/80"
          >
            <Download className="size-4" />
            <span className="hidden sm:inline">Export Report</span>
          </Button>
        </div>
      </div>
    </section>
  );
}
