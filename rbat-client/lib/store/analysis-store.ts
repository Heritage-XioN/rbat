import { create } from "zustand";

export interface YaraMatch {
  offset: number;
  section: string;
  length: number;
  data: string;
}

export interface BinaryMetadata {
  binary_type: string;
  entry_point: number;
  architecture: number;
}

export interface AnalysisResult {
  metadata: BinaryMetadata;
  code_cave: Record<string, number[]>;
  blacklisted_mnemonics: Record<string, number[]>;
  api_hooking: Record<string, number>;
  process_injection: string[];
  section_entropy: Record<string, number>;
  string_values: Record<string, YaraMatch[]>;
  packer_signatures: Record<string, YaraMatch[]>;
}

export interface Finding {
  indicator: string;
  description: string;
  confidence: "Low" | "Medium" | "High" | "Critical";
  weight: number;
}

export interface RiskAssessment {
  score: number;
  severity: string;
  findings: Finding[];
  recommendations: string[];
}

export interface AnalysisData {
  file_id: string;
  analysis_result: AnalysisResult;
  risk_assesment: RiskAssessment;
}

export type AnalysisStatus =
  | "idle"
  | "uploading"
  | "analyzing"
  | "completed"
  | "failed";

interface AnalysisState {
  status: AnalysisStatus;
  fileName: string;
  md5Hash: string;
  fileSize: number | null;
  errorMessage: string;
  analysisData: AnalysisData | null;

  // AI Insights
  insightText: string;
  insightRecommendation: string;
  isInsightLoading: boolean;

  // Actions
  setStatus: (status: AnalysisStatus) => void;
  setFileName: (fileName: string) => void;
  setFileInfo: (md5Hash: string, size: number) => void;
  setAnalysisData: (data: AnalysisData) => void;
  setErrorMessage: (error: string) => void;
  setInsight: (insight: string, recommendation: string) => void;
  setInsightLoading: (isLoading: boolean) => void;
  reset: () => void;
}

export const useAnalysisStore = create<AnalysisState>((set) => ({
  status: "idle",
  fileName: "",
  md5Hash: "",
  fileSize: null,
  errorMessage: "",
  analysisData: null,
  insightText: "",
  insightRecommendation: "",
  isInsightLoading: false,

  setStatus: (status) => set({ status }),
  setFileName: (fileName) => set({ fileName }),
  setFileInfo: (md5Hash, fileSize) => set({ md5Hash, fileSize }),
  setAnalysisData: (analysisData) => set({ analysisData }),
  setErrorMessage: (errorMessage) => set({ errorMessage }),
  setInsight: (insightText, insightRecommendation) =>
    set({ insightText, insightRecommendation }),
  setInsightLoading: (isInsightLoading) => set({ isInsightLoading }),
  reset: () =>
    set({
      status: "idle",
      fileName: "",
      md5Hash: "",
      fileSize: null,
      errorMessage: "",
      analysisData: null,
      insightText: "",
      insightRecommendation: "",
      isInsightLoading: false,
    }),
}));
