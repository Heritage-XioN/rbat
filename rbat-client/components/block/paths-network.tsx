"use client";

import { useAnalysisStore } from "@/lib/store/analysis-store";

export function PathsNetwork() {
  const { analysisData } = useAnalysisStore();

  // Pattern matching URL schemas, UNIX/Windows directory markers, or host IP ranges
  const pathOrNetworkRegex =
    /(https?:\/\/|\/bin\/|\/tmp\/|\/etc\/|\\\\|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i;

  const entries = Object.values(
    analysisData?.analysis_result?.string_values || {},
  )
    .flat()
    .filter((match) => pathOrNetworkRegex.test(match.data))
    .map((match) => ({
      offset: `0x${match.offset.toString(16).toUpperCase()}`,
      value: match.data,
    }))
    .slice(0, 7); // Show top 7

  return (
    <div className="flex flex-col rounded-xl border border-rbat-border bg-rbat-card p-5">
      {/* Header with legend */}
      <div className="mb-4 flex items-center gap-4">
        <div className="flex items-center gap-1.5">
          <span className="inline-block size-2.5 rounded-sm bg-rbat-accent" />
          <span className="text-[10px] font-semibold uppercase tracking-wider text-rbat-muted">
            Paths
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="inline-block size-2.5 rounded-sm bg-white" />
          <span className="text-[10px] font-semibold uppercase tracking-wider text-rbat-muted">
            Network
          </span>
        </div>
      </div>

      {/* Table */}
      <div className="space-y-0">
        {/* Table header */}
        <div className="grid grid-cols-[100px_1fr] gap-4 border-b border-rbat-border/50 pb-2">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-rbat-muted">
            Offset
          </span>
          <span className="text-[10px] font-semibold uppercase tracking-wider text-rbat-muted">
            Value
          </span>
        </div>

        {/* Table rows */}
        {entries.length > 0 ? (
          entries.map((entry, index) => (
            <div
              key={`${entry.offset}-${index}`}
              className="grid grid-cols-[100px_1fr] gap-4 border-b border-rbat-border/30 py-2.5 last:border-b-0"
            >
              <span className="font-mono text-xs text-rbat-text-secondary">
                {entry.offset}
              </span>
              <span
                className="truncate font-mono text-xs text-rbat-text"
                title={entry.value}
              >
                {entry.value}
              </span>
            </div>
          ))
        ) : (
          <div className="text-center py-8 text-xs font-mono text-rbat-muted">
            No system paths or network indicators detected
          </div>
        )}
      </div>
    </div>
  );
}
