import { Navbar } from "@/components/block/navbar";
import { UploadZone } from "@/components/block/upload-zone";
import { AnalysisHeader } from "@/components/block/analysis-header";
import { FileMetrics } from "@/components/block/file-metrics";
import { RiskAssessment } from "@/components/block/risk-assessment";
import { VulnerabilityFindings } from "@/components/block/vulnerability-findings";
import { StringsSnapshot } from "@/components/block/strings-snapshot";
import { PathsNetwork } from "@/components/block/paths-network";
import { BinaryComposition } from "@/components/block/binary-composition";
import { AiInsight } from "@/components/block/ai-insight";
import { Footer } from "@/components/block/footer";

export function Dashboard() {
  return (
    <div className="flex min-h-screen flex-col bg-rbat-bg">
      {/* Navbar */}
      <Navbar />

      {/* Upload Zone */}
      <UploadZone />

      {/* Analysis Header */}
      <AnalysisHeader fileName="" />

      {/* Main Analysis Grid */}
      <section className="mx-auto w-full max-w-7xl px-6 py-4">
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          {/* File Metrics — spans 1 col */}
          <FileMetrics />

          {/* Risk Assessment — spans 1 col */}
          <RiskAssessment />

          {/* Vulnerability Findings — spans 1 col */}
          <VulnerabilityFindings />
        </div>
      </section>

      {/* Bottom Analysis Grid */}
      <section className="mx-auto w-full max-w-7xl px-6 py-4">
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          {/* Embedded Strings */}
          <StringsSnapshot />

          {/* Paths & Network */}
          <PathsNetwork />

          {/* Binary Composition */}
          <BinaryComposition />
        </div>
      </section>

      {/* AI Insight — full width */}
      <section className="mx-auto w-full max-w-7xl px-6 py-4">
        <AiInsight />
      </section>

      {/* Footer */}
      <Footer />
    </div>
  );
}
