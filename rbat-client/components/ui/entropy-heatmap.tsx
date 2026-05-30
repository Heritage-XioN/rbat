import { cn } from "@/lib/utils";

interface EntropySection {
  name: string;
  entropy: number;
}

interface EntropyHeatmapProps {
  sections?: EntropySection[];
  className?: string;
}

function entropyToColor(entropy: number): string {
  // Map 0.0-8.0 to a color gradient: blue (low) -> purple (mid) -> red/pink (high)
  const normalized = Math.min(entropy / 8, 1);

  if (normalized < 0.25) {
    // Low entropy: dark blue
    return `rgba(59, 130, 246, ${0.3 + normalized * 2})`;
  }
  if (normalized < 0.5) {
    // Medium-low: purple
    return `rgba(139, 92, 246, ${0.4 + normalized})`;
  }
  if (normalized < 0.75) {
    // Medium-high: magenta
    return `rgba(192, 132, 252, ${0.5 + normalized * 0.5})`;
  }
  // High entropy: pink/red (potential packing/encryption)
  return `rgba(236, 72, 153, ${0.6 + normalized * 0.3})`;
}

export function EntropyHeatmap({ sections, className }: EntropyHeatmapProps) {
  const displaySections = sections || [];

  return (
    <div className={cn("space-y-2", className)}>
      <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider text-rbat-muted">
        <span className="inline-block size-1.5 rounded-full bg-rbat-accent animate-pulse" />
        Live Entropy Mapping
      </div>

      {displaySections.length > 0 ? (
        <>
          <div className="grid grid-cols-3 gap-1">
            {displaySections.map((section) => (
              <div
                key={section.name}
                className="relative rounded-sm p-2 text-center transition-all hover:scale-105"
                style={{ backgroundColor: entropyToColor(section.entropy) }}
              >
                <div className="text-[9px] font-mono font-semibold text-white/90 truncate" title={section.name}>
                  {section.name}
                </div>
                <div className="text-[8px] font-mono text-white/60">
                  {section.entropy.toFixed(2)}
                </div>
              </div>
            ))}
          </div>
          {/* Entropy scale legend */}
          <div className="flex items-center gap-1 pt-1">
            <span className="text-[8px] text-rbat-muted">0.0</span>
            <div className="h-1.5 flex-1 rounded-full bg-linear-to-r from-blue-500/50 via-purple-500/70 to-pink-500/80" />
            <span className="text-[8px] text-rbat-muted">8.0</span>
          </div>
        </>
      ) : (
        <div className="text-center py-6 text-xs font-mono text-rbat-muted border border-dashed border-rbat-border/50 rounded-lg">
          No entropy data mapped
        </div>
      )}
    </div>
  );
}
