interface EmbeddedString {
  offset: string;
  value: string;
}

interface StringsSnapshotProps {
  strings?: EmbeddedString[];
}

export function StringsSnapshot({ strings }: StringsSnapshotProps) {
  return (
    <div className="flex flex-col rounded-xl border border-rbat-border bg-rbat-card p-5">
      {/* Header */}
      <h3 className="mb-4 text-[11px] font-bold uppercase tracking-widest text-rbat-muted">
        Embedded Strings Snapshot
      </h3>

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
        {strings?.map((str, index) => (
          <div
            key={`${str.offset}-${index}`}
            className="grid grid-cols-[100px_1fr] gap-4 border-b border-rbat-border/30 py-2.5 last:border-b-0"
          >
            <span className="font-mono text-xs text-rbat-text-secondary">
              {str.offset}
            </span>
            <span className="truncate font-mono text-xs text-rbat-text">
              {str.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
