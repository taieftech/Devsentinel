// ==================== DEVSENTINEL - $0 AUTONOMOUS AGENT ====================
// Runs on Render FREE tier, scans GitHub for secrets, auto-creates issues
// Created on phone in 30 minutes - HACKATHON SUBMISSION

// ✅ SAFE! No secrets here!
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;  // 👈 Reads from Render, not GitHub
const GEMINI_KEY = process.env.GEMINI_KEY;      // 👈 Same thing!
// Import libraries from CDN (no npm install needed!)
import { GoogleGenAI } from "https://esm.sh/@google/genai@0.2.0";
import { Octokit } from "https://esm.sh/octokit@4.0.2";

// Initialize APIs
const ai = new GoogleGenAI({ apiKey: GEMINI_KEY });
const github = new Octokit({ auth: GITHUB_TOKEN });

console.log("🤖 DevSentinel starting...");

// ============ SECRET DETECTION ENGINE ============
async function scanRepo(owner, repo) {
    console.log(`🔍 Scanning ${owner}/${repo}...`);
    
    try {
        // Get recent commits
        const commits = await github.rest.repos.listCommits({
            owner, repo, per_page: 5
        });
        
        for (const commit of commits.data) {
            // Get commit details with files
            const commitData = await github.rest.repos.getCommit({
                owner, repo, ref: commit.sha
            });
            
            for (const file of commitData.data.files || []) {
                if (!file.patch) continue;
                
                // Ask Gemini if this contains secrets
                const prompt = `Does this code contain ANY API keys, passwords, tokens, or secrets?
                Reply ONLY with "YES" or "NO".
                
                Code:
                ${file.patch.substring(0, 800)}`;
                
                const response = await ai.models.generateContent({
                    model: "gemini-1.5-flash",
                    contents: [{ role: "user", parts: [{ text: prompt }] }]
                });
                
                if (response.text.includes("YES")) {
                    console.log(`⚠️ SECRET FOUND in ${file.filename}`);
                    
                    // Create issue alert
                    await github.rest.issues.create({
                        owner, repo,
                        title: "🚨 SECURITY: Possible secret detected",
                        body: `## 🔐 AI Detected Potential Secret\n\n` +
                              `**File:** \`${file.filename}\`\n` +
                              `**Commit:** ${commit.sha.substring(0,7)}\n` +
                              `**Action:** ${file.status}\n\n` +
                              `### ⚡ Immediate Actions Required:\n` +
                              `1. Rotate this key immediately\n` +
                              `2. Remove from code\n` +
                              `3. Check for unauthorized access\n\n` +
                              `_Auto-detected by DevSentinel AI_`,
                        labels: ["security", "critical", "auto-detected"]
                    });
                    
                    console.log("✅ Created issue #" + response.data?.number);
                }
            }
        }
    } catch (err) {
        console.log(`Error scanning ${repo}: ${err.message}`);
    }
}

// ============ AUTO-RUN ON STARTUP ============
async function main() {
    console.log("🚀 DevSentinel Activated!");
    
    // Get your repos
    const user = await github.rest.users.getAuthenticated();
    const repos = await github.rest.repos.listForAuthenticatedUser({
        per_page: 3  // Stay within FREE limits
    });
    
    console.log(`👤 Logged in as: ${user.data.login}`);
    console.log(`📦 Scanning ${repos.data.length} repositories...`);
    
    // Scan each repo
    for (const repo of repos.data) {
        await scanRepo(repo.owner.login, repo.name);
    }
    
    console.log("✅ Scan complete!");
    console.log("⏰ Waiting for next trigger...");
}

// Run once at startup
await main();
