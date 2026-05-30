"use client";

import { DataRow } from "@/components/ui/data-row";
import { EntropyHeatmap } from "@/components/ui/entropy-heatmap";
import { useAnalysisStore } from "@/lib/store/analysis-store";

export function FileMetrics() {
  const { fileSize, md5Hash, analysisData } = useAnalysisStore();

  const metadata = analysisData?.analysis_result?.metadata;

  // Format file size representation
  const formattedSize = fileSize
    ? fileSize > 1024 * 1024
      ? `${(fileSize / (1024 * 1024)).toFixed(2)} MB`
      : `${(fileSize / 1024).toFixed(2)} KB`
    : "0 B";

  // Map architecture enum values to readable formats
  const getArchName = (arch?: number) => {
    if (!arch) return "Unknown";
    if (arch === 62) return "x86_64";
    if (arch === 3) return "i386";
    if (arch === 183) return "AArch64";
    if (arch === 34404) return "AMD64";
    if (arch === 332) return "i386";
    return `Arch ID: ${arch}`;
  };

  const architecture =
    metadata?.binary_type && metadata?.architecture
      ? `${metadata.binary_type} (${getArchName(metadata.architecture)})`
      : metadata?.binary_type || "Unknown";

  // Feed section entropy values dynamically
  const entropySections = Object.entries(
    analysisData?.analysis_result?.section_entropy || {},
  ).map(([name, entropy]) => ({ name, entropy }));

  return (
    <div className="flex flex-col rounded-xl border border-rbat-border bg-rbat-card p-5">
      {/* Header */}
      <h3 className="mb-4 text-[11px] font-bold uppercase tracking-widest text-rbat-muted">
        File Data Metrics
      </h3>

      {/* Data rows */}
      <div className="space-y-0 divide-y divide-rbat-border/50">
        <DataRow label="Size" value={formattedSize} />
        <DataRow label="Architecture" value={architecture} />
        <DataRow label="Endianness" value="Little Endian" />
      </div>

      {/* MD5 Hash — full width mono */}
      <div className="mt-3 space-y-1">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-rbat-muted">
          MD5 Hash
        </span>
        <p className="break-all font-mono text-xs text-rbat-text-secondary">
          {md5Hash || "N/A"}
        </p>
      </div>

      {/* Entropy Heatmap */}
      <div className="mt-4">
        {entropySections.length > 0 ? (
          <EntropyHeatmap sections={entropySections} />
        ) : (
          <EntropyHeatmap />
        )}
      </div>
    </div>
  );
}
