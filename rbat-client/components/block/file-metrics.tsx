import { DataRow } from "@/components/ui/data-row";
import { EntropyHeatmap } from "@/components/ui/entropy-heatmap";

interface FileMetricsProps {
  size?: string;
  architecture?: string;
  endianness?: string;
  md5Hash?: string;
}

export function FileMetrics({
  size,
  architecture,
  endianness,
  md5Hash,
}: FileMetricsProps) {
  return (
    <div className="flex flex-col rounded-xl border border-rbat-border bg-rbat-card p-5">
      {/* Header */}
      <h3 className="mb-4 text-[11px] font-bold uppercase tracking-widest text-rbat-muted">
        File Data Metrics
      </h3>

      {/* Data rows */}
      <div className="space-y-0 divide-y divide-rbat-border/50">
        <DataRow label="Size" value={size} />
        <DataRow label="Architecture" value={architecture} />
        <DataRow label="Endianness" value={endianness} />
      </div>

      {/* MD5 Hash — full width mono */}
      <div className="mt-3 space-y-1">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-rbat-muted">
          MD5 Hash
        </span>
        <p className="break-all font-mono text-xs text-rbat-text-secondary">
          {md5Hash}
        </p>
      </div>

      {/* Entropy Heatmap */}
      <div className="mt-4">
        <EntropyHeatmap />
      </div>
    </div>
  );
}
