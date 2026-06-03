"use client";

import { AiInsight } from "@/components/block/ai-insight";
import { AnalysisHeader } from "@/components/block/analysis-header";
import { BinaryComposition } from "@/components/block/binary-composition";
import { FileMetrics } from "@/components/block/file-metrics";
import { Footer } from "@/components/block/footer";
import { Navbar } from "@/components/block/navbar";
import { PathsNetwork } from "@/components/block/paths-network";
import { RiskAssessment } from "@/components/block/risk-assessment";
import { StringsSnapshot } from "@/components/block/strings-snapshot";
import { UploadZone } from "@/components/block/upload-zone";
import { VulnerabilityFindings } from "@/components/block/vulnerability-findings";
import { TransitionWrapper } from "@/components/ui/transition-wrapper";
import { useAnalysisStore } from "@/lib/store/analysis-store";

export function Dashboard() {
  const status = useAnalysisStore((state) => state.status);
  const showResults = status === "completed";

  return (
    <div className="flex min-h-screen flex-col bg-rbat-bg">
      {/* Navbar */}
      <Navbar />

      {/* Upload Zone */}
      <UploadZone />

      {/* Analysis Header */}
      <TransitionWrapper show={showResults} delay="delay-[0ms]">
        <AnalysisHeader />
      </TransitionWrapper>

      {/* Main Analysis Grid */}
      <section className="mx-auto w-full max-w-7xl px-6 py-4">
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          {/* File Metrics — spans 1 col */}
          <TransitionWrapper show={showResults} delay="delay-[100ms]">
            <FileMetrics />
          </TransitionWrapper>

          {/* Risk Assessment — spans 1 col */}
          <TransitionWrapper show={showResults} delay="delay-[200ms]">
            <RiskAssessment />
          </TransitionWrapper>

          {/* Vulnerability Findings — spans 1 col */}
          <TransitionWrapper show={showResults} delay="delay-[300ms]">
            <VulnerabilityFindings />
          </TransitionWrapper>
        </div>
      </section>

      {/* Bottom Analysis Grid */}
      <section className="mx-auto w-full max-w-7xl px-6 py-4">
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          {/* Embedded Strings */}
          <TransitionWrapper show={showResults} delay="delay-[400ms]">
            <StringsSnapshot />
          </TransitionWrapper>

          {/* Paths & Network */}
          <TransitionWrapper show={showResults} delay="delay-[500ms]">
            <PathsNetwork />
          </TransitionWrapper>

          {/* Binary Composition */}
          <TransitionWrapper show={showResults} delay="delay-[600ms]">
            <BinaryComposition />
          </TransitionWrapper>
        </div>
      </section>

      {/* AI Insight — full width */}
      <section className="mx-auto w-full max-w-7xl px-6 py-4">
        <TransitionWrapper show={showResults} delay="delay-[700ms]">
          <AiInsight />
        </TransitionWrapper>
      </section>

      {/* Footer */}
      <Footer />
    </div>
  );
}
