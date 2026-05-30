"use client";

import { useAnalysisStore } from "@/lib/store/analysis-store";

export function BinaryComposition() {
  const { analysisData } = useAnalysisStore();

  const sections = Object.entries(
    analysisData?.analysis_result?.section_entropy || {},
  ).map(([name, entropy]) => {
    // Normalise entropy (0.0 - 8.0) into a percentage scale (min 5% for rendering)
    const percentage = Math.min(
      Math.max(Math.round((entropy / 8.0) * 100), 5),
      100,
    );

    let label = "Data Section";
    if (name === ".text" || name === "CODE") label = "Executable Code";
    else if (name === ".data") label = "Initialized Data";
    else if (name === ".rodata") label = "Read-Only Constants";
    else if (name === ".bss") label = "Uninitialized Variable Space";

    return {
      name,
      label,
      percentage,
    };
  });

  return (
    <div className="flex flex-col rounded-xl border border-rbat-border bg-rbat-card p-5 h-95">
      {/* Header */}
      <h3 className="mb-4 text-[11px] font-bold uppercase tracking-widest text-rbat-muted">
        Binary Composition
      </h3>

      {/* Progress bars */}
      <div className="space-y-4 flex-1 overflow-y-auto scrollbar-none pr-1">
        {sections.length > 0 ? (
          sections.map((section) => (
            <div key={section.name} className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-rbat-text">
                  {section.label}{" "}
                  <span className="text-rbat-muted">({section.name})</span>
                </span>
                <span className="text-xs font-semibold text-rbat-text-secondary">
                  {section.percentage}%
                </span>
              </div>
              <div className="h-1.5 w-full overflow-hidden rounded-full bg-rbat-border">
                <div
                  className="h-full rounded-full bg-linear-to-r from-rbat-accent to-pink-400 transition-all duration-700"
                  style={{ width: `${section.percentage}%` }}
                />
              </div>
            </div>
          ))
        ) : (
          <div className="text-center py-8 text-xs font-mono text-rbat-muted">
            No sections mapped
          </div>
        )}
      </div>
    </div>
  );
}
