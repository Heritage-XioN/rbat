interface NetworkEntry {
  offset: string;
  value: string;
}

interface PathsNetworkProps {
  entries?: NetworkEntry[];
}

export function PathsNetwork({ entries }: PathsNetworkProps) {
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
        {entries?.map((entry, index) => (
          <div
            key={`${entry.offset}-${index}`}
            className="grid grid-cols-[100px_1fr] gap-4 border-b border-rbat-border/30 py-2.5 last:border-b-0"
          >
            <span className="font-mono text-xs text-rbat-text-secondary">
              {entry.offset}
            </span>
            <span className="truncate font-mono text-xs text-rbat-text">
              {entry.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
