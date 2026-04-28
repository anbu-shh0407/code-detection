const express = require("express");
const cors = require("cors");
const https = require("https");
const app = express();

app.use(cors());
app.use(express.json({ limit: "50kb" }));

// ── LANGUAGE ANALYSIS RULES (fallback if AI call fails) ──
const LANGUAGE_RULES = {
  javascript: {
    patterns: [
      { regex: /var\s+/g,              msg: "Use 'let' or 'const' instead of 'var'",         severity: "warning", weight: 5 },
      { regex: /==(?!=)/g,             msg: "Use '===' instead of '==' for strict equality", severity: "warning", weight: 4 },
      { regex: /console\.log/g,        msg: "Remove console.log before production",           severity: "info",    weight: 2 },
      { regex: /eval\s*\(/g,           msg: "Avoid using eval() — security risk",             severity: "error",   weight: 15 },
      { regex: /document\.write/g,     msg: "Avoid document.write() — deprecated",           severity: "error",   weight: 10 },
      { regex: /catch\s*\(\w+\)\s*\{\s*\}/g, msg: "Empty catch block — handle the error",   severity: "error",   weight: 12 },
      { regex: /debugger\s*;/g,        msg: "Remove debugger statement before production",    severity: "error",   weight: 10 },
      { regex: /alert\s*\(/g,          msg: "Remove alert() before production",               severity: "warning", weight: 5 },
    ],
    good: [
      { regex: /const\s+/g,            msg: "Good use of 'const' for immutable bindings",    weight: 3 },
      { regex: /=>/g,                  msg: "Arrow functions used — modern syntax",           weight: 2 },
      { regex: /try\s*\{[\s\S]*?\}\s*catch/g, msg: "Error handling present",                weight: 5 },
      { regex: /\/\/.+/g,              msg: "Code comments found",                           weight: 2 },
    ]
  },
  python: {
    patterns: [
      { regex: /except\s*:/g,          msg: "Bare except clause — catch specific exceptions", severity: "error",   weight: 12 },
      { regex: /print\s*\(/g,          msg: "Remove print statements before production",      severity: "info",    weight: 2 },
      { regex: /import \*/g,           msg: "Avoid wildcard imports — import explicitly",     severity: "warning", weight: 7 },
      { regex: /exec\s*\(/g,           msg: "Avoid exec() — security risk",                  severity: "error",   weight: 15 },
      { regex: /global\s+\w+/g,        msg: "Global variable usage — consider refactoring",  severity: "warning", weight: 5 },
    ],
    good: [
      { regex: /def\s+\w+\s*\(/g,     msg: "Functions defined",                             weight: 3 },
      { regex: /"""[\s\S]*?"""/g,     msg: "Docstrings present",                            weight: 5 },
      { regex: /if __name__\s*==\s*['"]__main__['"]/g, msg: "Main guard present",           weight: 4 },
      { regex: /#.+/g,                 msg: "Inline comments found",                        weight: 2 },
    ]
  },
  java: {
    patterns: [
      { regex: /catch\s*\(Exception/g, msg: "Catching generic Exception — be specific",      severity: "warning", weight: 8 },
      { regex: /System\.out\.print/g,  msg: "Use a logger instead of System.out",            severity: "info",    weight: 3 },
      { regex: /System\.exit\s*\(/g,   msg: "Avoid System.exit() — use exceptions instead",  severity: "warning", weight: 6 },
      { regex: /catch\s*\(\w+\)\s*\{\s*\}/g, msg: "Empty catch block",                      severity: "error",   weight: 12 },
    ],
    good: [
      { regex: /@Override/g,           msg: "Proper @Override annotations",                 weight: 3 },
      { regex: /\/\*\*[\s\S]*?\*\//g,  msg: "Javadoc comments present",                    weight: 5 },
      { regex: /final\s+/g,            msg: "Immutable variables declared with final",      weight: 3 },
    ]
  },
  cpp: {
    patterns: [
      { regex: /using namespace std;/g, msg: "Avoid 'using namespace std' in headers",       severity: "warning", weight: 7 },
      { regex: /goto\s+/g,             msg: "Avoid goto — use structured control flow",      severity: "error",   weight: 12 },
      { regex: /malloc\s*\(/g,         msg: "Prefer new/delete over malloc in C++",          severity: "warning", weight: 6 },
      { regex: /gets\s*\(/g,           msg: "gets() is unsafe — use fgets()",                severity: "error",   weight: 14 },
      { regex: /strcpy\s*\(/g,         msg: "strcpy() is unsafe — use strncpy()",            severity: "error",   weight: 12 },
    ],
    good: [
      { regex: /#include\s+<memory>/g, msg: "Smart pointer header included",                weight: 4 },
      { regex: /auto\s+/g,             msg: "Type inference with auto",                     weight: 2 },
      { regex: /const\s+/g,            msg: "Const correctness applied",                    weight: 3 },
    ]
  },
  typescript: {
    patterns: [
      { regex: /:\s*any\b/g,           msg: "Avoid 'any' type — defeats TypeScript safety",  severity: "warning", weight: 8 },
      { regex: /as\s+any/g,            msg: "Type assertion to any is unsafe",               severity: "error",   weight: 10 },
      { regex: /\/\/@ts-ignore/g,      msg: "ts-ignore suppresses type errors — fix them",   severity: "warning", weight: 7 },
      { regex: /\/\/@ts-nocheck/g,     msg: "@ts-nocheck disables all checks in the file",   severity: "error",   weight: 12 },
      { regex: /console\.log/g,        msg: "Remove console.log before production",           severity: "info",    weight: 2 },
    ],
    good: [
      { regex: /interface\s+\w+/g,    msg: "Interfaces defined for type safety",            weight: 5 },
      { regex: /:\s*string\b|:\s*number\b|:\s*boolean\b/g, msg: "Explicit types declared", weight: 3 },
      { regex: /readonly\s+/g,        msg: "Readonly properties for immutability",          weight: 4 },
    ]
  },
};

function detectLanguage(code) {
  if (/def\s+\w+|import\s+\w+|print\s*\(|:\s*$/.test(code)) return "python";
  if (/public\s+class|System\.out|@Override/.test(code)) return "java";
  if (/#include|std::|cout|cin/.test(code)) return "cpp";
  if (/:\s*(string|number|boolean|any)\b|interface\s+\w+/.test(code)) return "typescript";
  return "javascript";
}

function analyzeCodeLocally(code, language) {
  const rules = LANGUAGE_RULES[language] || LANGUAGE_RULES.javascript;
  const errors = [];
  let penaltyScore = 0;
  let bonusScore = 0;
  const lines = code.split("\n");

  for (const rule of rules.patterns) {
    rule.regex.lastIndex = 0;
    const matches = code.match(rule.regex);
    if (matches) {
      const count = matches.length;
      penaltyScore += rule.weight * Math.min(count, 3);
      const lineNums = [];
      lines.forEach((line, i) => {
        rule.regex.lastIndex = 0;
        if (rule.regex.test(line)) lineNums.push(i + 1);
        rule.regex.lastIndex = 0;
      });
      errors.push({ id: errors.length + 1, severity: rule.severity, message: rule.msg, count, lines: lineNums.slice(0, 4) });
    }
    rule.regex.lastIndex = 0;
  }

  const goodPractices = [];
  for (const g of rules.good) {
    g.regex.lastIndex = 0;
    const matches = code.match(g.regex);
    if (matches) { bonusScore += g.weight; goodPractices.push(g.msg); }
    g.regex.lastIndex = 0;
  }

  let longLines = 0;
  lines.forEach(line => { if (line.length > 100) longLines++; });
  if (longLines > 0) {
    errors.push({ id: errors.length + 1, severity: "info", message: `${longLines} line(s) exceed 100 characters`, count: longLines, lines: [] });
    penaltyScore += longLines * 2;
  }

  const accuracy = Math.max(0, Math.min(100, Math.round(100 - penaltyScore + Math.min(bonusScore, 20))));
  const grade = accuracy >= 90 ? "A" : accuracy >= 75 ? "B" : accuracy >= 60 ? "C" : accuracy >= 40 ? "D" : "F";
  const summary = accuracy >= 90 ? "Excellent code quality. Well-structured and follows best practices."
    : accuracy >= 75 ? "Good code with minor improvements possible."
    : accuracy >= 60 ? "Average quality. Several issues should be addressed."
    : accuracy >= 40 ? "Below average. Significant improvements needed."
    : "Poor quality. Major refactoring recommended.";

  return {
    accuracy, grade, summary, language,
    linesOfCode: lines.filter(l => l.trim()).length,
    totalLines: lines.length,
    errors, goodPractices,
    stats: {
      errorCount: errors.filter(e => e.severity === "error").length,
      warningCount: errors.filter(e => e.severity === "warning").length,
      infoCount: errors.filter(e => e.severity === "info").length,
    },
    source: "local"
  };
}

// ── CLAUDE AI REVIEW ──
async function analyzeWithClaude(code, language) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) throw new Error("ANTHROPIC_API_KEY not set");

  const prompt = `You are a senior code reviewer. Analyze the following code and return ONLY a valid JSON object — no markdown, no explanation, no backticks.

Language: ${language}

Code:
\`\`\`
${code}
\`\`\`

Return this exact JSON structure:
{
  "language": "detected language name (javascript/python/java/cpp/typescript)",
  "accuracy": <integer 0-100 representing code quality score>,
  "grade": "<A/B/C/D/F>",
  "summary": "<one sentence overall summary>",
  "linesOfCode": <number of non-empty lines>,
  "totalLines": <total lines>,
  "errors": [
    {
      "id": <number>,
      "severity": "<error|warning|info>",
      "message": "<clear description of the issue>",
      "count": <how many times this pattern occurs>,
      "lines": [<line numbers where issue appears, up to 4>]
    }
  ],
  "goodPractices": ["<list of positive things found in the code>"],
  "stats": {
    "errorCount": <number of error severity items>,
    "warningCount": <number of warning severity items>,
    "infoCount": <number of info severity items>
  }
}

Rules:
- Detect actual syntax errors, undefined variables, missing brackets, wrong types as "error"
- Report style issues, bad practices, deprecated APIs as "warning"
- Report minor suggestions like removing console.log as "info"
- accuracy: start at 100, deduct errors (-15 each), warnings (-8 each), info (-2 each), add good practices (+3 each), min 0 max 100
- grade: A=90+, B=75+, C=60+, D=40+, F=below 40
- Be specific with line numbers`;

  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      model: "claude-sonnet-4-20250514",
      max_tokens: 1500,
      messages: [{ role: "user", content: prompt }]
    });

    const options = {
      hostname: "api.anthropic.com",
      path: "/v1/messages",
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
        "Content-Length": Buffer.byteLength(body)
      }
    };

    const req = https.request(options, (res) => {
      let data = "";
      res.on("data", chunk => data += chunk);
      res.on("end", () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.error) return reject(new Error(parsed.error.message));
          const text = parsed.content.map(b => b.text || "").join("").trim();
          const clean = text.replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/i, "").trim();
          const result = JSON.parse(clean);
          result.source = "claude";
          result.linesOfCode = result.linesOfCode || code.split("\n").filter(l => l.trim()).length;
          result.totalLines = result.totalLines || code.split("\n").length;
          result.errors = result.errors || [];
          result.goodPractices = result.goodPractices || [];
          result.stats = result.stats || {
            errorCount: result.errors.filter(e => e.severity === "error").length,
            warningCount: result.errors.filter(e => e.severity === "warning").length,
            infoCount: result.errors.filter(e => e.severity === "info").length,
          };
          resolve(result);
        } catch (e) {
          reject(new Error("Failed to parse Claude response: " + e.message));
        }
      });
    });

    req.on("error", reject);
    req.setTimeout(15000, () => { req.destroy(); reject(new Error("Claude API timeout")); });
    req.write(body);
    req.end();
  });
}

// ── ROUTES ──
app.post("/api/review", async (req, res) => {
  const { code, language } = req.body;
  if (!code || !code.trim()) return res.status(400).json({ error: "No code provided" });

  const detectedLang = language && language !== "auto" ? language : detectLanguage(code);

  // Try Claude AI first, fall back to local analysis
  try {
    const result = await analyzeWithClaude(code, detectedLang);
    return res.json(result);
  } catch (aiErr) {
    console.warn("Claude AI unavailable:", aiErr.message, "— using local analysis");
    const result = analyzeCodeLocally(code, detectedLang);
    return res.json(result);
  }
});

app.get("/api/health", (_, res) => res.json({ status: "ok", ai: !!process.env.ANTHROPIC_API_KEY }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`\nCode Guruvi API running on http://localhost:${PORT}`);
  if (process.env.ANTHROPIC_API_KEY) {
    console.log("✅ ANTHROPIC_API_KEY detected — Claude AI mode enabled");
  } else {
    console.log("⚠️  ANTHROPIC_API_KEY not set — using local rule-based analysis");
    console.log("   Set it with: export ANTHROPIC_API_KEY=your_key_here");
  }
});
