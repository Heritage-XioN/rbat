import { google } from "@ai-sdk/google";
import { streamText } from "ai";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const { analysis_result, risk_assesment } = body;

    if (!analysis_result || !risk_assesment) {
      return new Response(
        JSON.stringify({ error: "Missing analysis data in request body" }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        },
      );
    }

    const prompt = `
You are an expert reverse engineer and binary security analyst.
Review the following static analysis metrics for a binary and summarize your security findings:

- Binary Type: ${analysis_result.metadata?.binary_type || "Unknown"}
- Entry Point: 0x${(analysis_result.metadata?.entry_point || 0).toString(16)}
- Threat Score: ${risk_assesment.score || 0}/100
- Severity Evaluation: ${risk_assesment.severity || "Safe"}
- Suspicious API Hooking Detections: ${JSON.stringify(analysis_result.api_hooking || {})}
- Process Injection Indicators: ${JSON.stringify(analysis_result.process_injection || [])}
- Section Entropy Scores: ${JSON.stringify(analysis_result.section_entropy || {})}
- Packer Signature Matches: ${JSON.stringify(analysis_result.packer_signatures || {})}

Provide a response divided exactly into two parts separated by the separator "---RECOMMENDATION---":
Part 1 (Security Analysis): Summarize the suspicious heuristics, potential compiler anomalies, and evasion techniques found in the binary in a concise, highly professional security audit paragraph (max 4 sentences).
Part 2 (Recommendation): Write the single most critical actionable step the security operations center or developer should take (max 2 sentences).

Example Output Format:
Static heuristics show suspicious API calls matching process injection techniques. The high entropy in .text sections indicates possible packing or encryption. Evasion mnemonics were also detected.
---RECOMMENDATION---
We recommend sandbox execution and dynamic behavioral analysis to inspect memory dumps before deploying this binary in production.
`;

    // Stream text using Gemini 2.5 Flash model
    const result = streamText({
      model: google("gemini-2.5-flash"),
      prompt,
    });

    return result.toTextStreamResponse();
  } catch (error: any) {
    console.error("AI Insight Route Error:", error);
    return new Response(
      JSON.stringify({ error: error.message || "Internal Server Error" }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      },
    );
  }
}
