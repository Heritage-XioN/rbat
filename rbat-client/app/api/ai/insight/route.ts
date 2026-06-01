import { createGoogleGenerativeAI } from "@ai-sdk/google";
import { streamText } from "ai";
import { logger } from "@/lib/logger";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const promptStr = body.prompt;
    if (!promptStr) {
      return new Response(
        JSON.stringify({ error: "Missing prompt in request body" }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        },
      );
    }

    let data: any;
    try {
      data = JSON.parse(promptStr);
    } catch (parseError: any) {
      logger.warn(
        `AI Insight JSON parse error: (parseError.message || parseError)`,
      );
      return new Response(
        JSON.stringify({
          error: `Invalid JSON string in prompt: ${parseError.message}`,
        }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        },
      );
    }

    const { analysis_result, risk_assesment } = data;

    if (!analysis_result || !risk_assesment) {
      logger.warn(
        `AI Insight validation failed. Missing analysis_result or risk_assesment. Keys in data:
          Object.keys(data).join(", ")`,
      );
      return new Response(
        JSON.stringify({
          error: "Missing analysis_result or risk_assesment in prompt payload",
          receivedKeys: Object.keys(data),
        }),
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

    // Retrieve API key from environment variables
    const apiKey =
      process.env.GEMINI_API_KEY || process.env.GOOGLE_GENERATIVE_AI_API_KEY;
    if (!apiKey) {
      throw new Error(
        "Missing Google Generative AI API key in environment variables (GEMINI_API_KEY or GOOGLE_GENERATIVE_AI_API_KEY)",
      );
    }

    const googleProvider = createGoogleGenerativeAI({
      apiKey,
    });

    // Stream text using Gemini 2.5 Flash model
    const result = streamText({
      model: googleProvider("gemini-2.5-flash"),
      prompt,
    });

    return result.toUIMessageStreamResponse();
  } catch (error: any) {
    logger.error(`AI Insight Route Error: ${error.message || error}`);
    return new Response(JSON.stringify({ error: "Internal Server Error" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}
