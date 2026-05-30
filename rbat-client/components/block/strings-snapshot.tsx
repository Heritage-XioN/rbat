"use client";

import { useAnalysisStore } from "@/lib/store/analysis-store";

export function StringsSnapshot() {
  const { analysisData } = useAnalysisStore();

  // Map all YARA matching strings to list
  const strings = Object.values(
    analysisData?.analysis_result?.string_values || {},
  )
    .flat()
    .map((match) => ({
      offset: `0x${match.offset.toString(16).toUpperCase()}`,
      value: match.data,
    }))
    .slice(0, 7); // Show top 7

  return (
    <div className="flex flex-col rounded-xl border border-rbat-border bg-rbat-card p-5 h-95">
      {/* Header */}
      <h3 className="mb-4 text-[11px] font-bold uppercase tracking-widest text-rbat-muted">
        Embedded Strings Snapshot
      </h3>

      {/* Table */}
      <div className="space-y-0 flex-1 overflow-y-auto scrollbar-none pr-1">
        {/* Table header */}
        <div className="grid grid-cols-[100px_1fr] gap-4 border-b border-rbat-border/50 pb-2 sticky top-0 bg-rbat-card z-10">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-rbat-muted">
            Offset
          </span>
          <span className="text-[10px] font-semibold uppercase tracking-wider text-rbat-muted">
            Value
          </span>
        </div>

        {/* Table rows */}
        {strings.length > 0 ? (
          strings.map((str, index) => (
            <div
              key={`${str.offset}-${index}`}
              className="grid grid-cols-[100px_1fr] gap-4 border-b border-rbat-border/30 py-2.5 last:border-b-0"
            >
              <span className="font-mono text-xs text-rbat-text-secondary">
                {str.offset}
              </span>
              <span
                className="truncate font-mono text-xs text-rbat-text"
                title={str.value}
              >
                {str.value}
              </span>
            </div>
          ))
        ) : (
          <div className="text-center py-8 text-xs font-mono text-rbat-muted">
            No strings indexed
          </div>
        )}
      </div>
    </div>
  );
}
