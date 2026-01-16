const cerebrasService = require('./cerebrasService');
const geminiService = require('./geminiService');

class SecurityAdvisorService {
  /**
   * Generates a detailed Penetration Testing strategy for a specific issue or repository
   */
  async generateTestingStrategy(issue, repository) {
    const systemPrompt = `You are a Senior Penetration Tester and Security Architect. 
Your goal is to provide a SAFE, GUIDED testing strategy for identified vulnerabilities.
DO NOT exploit. Provide educational and strategic advice.
Focus on: 1. Attack surface mapping, 2. Endpoint identification, 3. Neutral testing vectors.`;

    const userPrompt = `Vuln: ${issue.title}
File: ${issue.filePath}
Description: ${issue.description}
Code Context:
${issue.codeSnippet}

TASK: Provide a Guided Penetration Testing Plan. Include:
1. ATTACK SURFACE: Which endpoints/files are exposed?
2. RISKS: What is the impact if exploited?
3. SAFE TESTING STRATEGY: How can a developer verify this vulnerability without causing harm?
4. PLAYBOOK: Steps to secure and monitor this area.`;

    try {
      let response;
      if (process.env.CEREBRAS_API_KEY) {
        response = await cerebrasService.analyzeCode(systemPrompt, userPrompt, {
          model: 'llama3.1-70b',
          temperature: 0.1,
          maxTokens: 2000
        });
      } else {
        response = await geminiService.analyzeCode(systemPrompt, userPrompt, {
          temperature: 0.2,
          maxTokens: 4000
        });
      }

      return {
        success: true,
        strategy: response.text,
        service: process.env.CEREBRAS_API_KEY ? 'Cerebras' : 'Gemini'
      };
    } catch (error) {
      console.error("❌ Security Strategy Generation Failed:", error);
      throw error;
    }
  }

  /**
   * Specifically analyzes API surface for missing auth or broken access control
   */
  async analyzeAPISurface(files) {
    const systemPrompt = `You are an Expert API Security Auditor specialized in OWASP API Security Top 10.
Analyze the provided code for:
1. Broken Object Level Authorization (BOLA)
2. Broken User Authentication
3. Excessive Data Exposure
4. Lack of Resources & Rate Limiting
5. Mass Assignment
6. Security Misconfiguration
7. Injection (SQL, NoSQL, etc.)

Return a JSON array of findings. Each finding must have:
{
  "title": string,
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
  "endpoint": string,
  "issueType": "api-security",
  "description": string,
  "remediation": string
}`;

    const codeContext = files.map(f => `FILE: ${f.path}\nCONTENT:\n${f.content}`).join('\n\n');
    const userPrompt = `Analyze the following API-related files for security vulnerabilities:\n\n${codeContext}`;

    try {
      let response;
      if (process.env.CEREBRAS_API_KEY) {
        response = await cerebrasService.analyzeCode(systemPrompt, userPrompt, {
          model: 'llama3.1-70b',
          temperature: 0.1,
          maxTokens: 3000
        });
      } else {
        response = await geminiService.analyzeCode(systemPrompt, userPrompt, {
          temperature: 0.1,
          maxTokens: 8192
        });
      }

      // Extract JSON from response text
      const jsonMatch = response.text.match(/\[[\s\S]*\]/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]);
      }
      
      return [];
    } catch (error) {
      console.error("❌ API Surface Analysis Failed:", error);
      throw error;
    }
  }

  /**
   * Get categorized threats for a repository
   */
  async getThreatsDetected(repositoryId, userId) {
    try {
      const Issue = require('../models/Issue');
      
      const threats = await Issue.find({
        repositoryId,
        userId,
        status: { $ne: 'resolved' }
      });

      // Categorize threats
      const categorized = {
        apiSecurity: threats.filter(t => t.issueType === 'api-security'),
        penTest: threats.filter(t => t.issueType === 'pen-test'),
        dependency: threats.filter(t => t.issueType === 'dependency'),
        security: threats.filter(t => t.issueType === 'security'),
        other: threats.filter(t => !['api-security', 'pen-test', 'dependency', 'security'].includes(t.issueType))
      };

      const summary = {
        total: threats.length,
        byCategory: {
          apiSecurity: categorized.apiSecurity.length,
          penTest: categorized.penTest.length,
          dependency: categorized.dependency.length,
          security: categorized.security.length,
          other: categorized.other.length
        },
        bySeverity: {
          critical: threats.filter(t => t.severity === 'CRITICAL').length,
          high: threats.filter(t => t.severity === 'HIGH').length,
          medium: threats.filter(t => t.severity === 'MEDIUM').length,
          low: threats.filter(t => t.severity === 'LOW').length
        }
      };

      return {
        success: true,
        threats: categorized,
        summary
      };
    } catch (error) {
      console.error("❌ Get threats failed:", error);
      throw error;
    }
  }

  /**
   * Test API endpoint security (safe, non-exploitative testing)
   */
  async testAPIEndpoint(endpoint, method = 'GET', headers = {}) {
    const axios = require('axios');
    
    const results = {
      endpoint,
      method,
      timestamp: new Date(),
      findings: [],
      score: 100
    };

    try {
      // Test 1: Check if endpoint requires authentication
      console.log(`🔍 Testing endpoint: ${endpoint}`);
      
      try {
        const response = await axios({
          method,
          url: endpoint,
          headers,
          timeout: 5000,
          validateStatus: () => true // Accept any status
        });

        // Check authentication
        if (response.status === 200 && !headers.Authorization) {
          results.findings.push({
            severity: 'HIGH',
            category: 'Authentication',
            issue: 'Endpoint accessible without authentication',
            recommendation: 'Implement authentication middleware'
          });
          results.score -= 20;
        }

        // Check security headers
        const securityHeaders = ['x-frame-options', 'x-content-type-options', 'strict-transport-security'];
        const missingHeaders = securityHeaders.filter(h => !response.headers[h]);
        
        if (missingHeaders.length > 0) {
          results.findings.push({
            severity: 'MEDIUM',
            category: 'Security Headers',
            issue: `Missing security headers: ${missingHeaders.join(', ')}`,
            recommendation: 'Add security headers to all responses'
          });
          results.score -= 10;
        }

        // Check for rate limiting
        const rateLimitHeaders = ['x-ratelimit-limit', 'x-ratelimit-remaining'];
        const hasRateLimit = rateLimitHeaders.some(h => response.headers[h]);
        
        if (!hasRateLimit) {
          results.findings.push({
            severity: 'MEDIUM',
            category: 'Rate Limiting',
            issue: 'No rate limiting detected',
            recommendation: 'Implement rate limiting to prevent abuse'
          });
          results.score -= 15;
        }

        // Check CORS configuration
        if (response.headers['access-control-allow-origin'] === '*') {
          results.findings.push({
            severity: 'MEDIUM',
            category: 'CORS',
            issue: 'Permissive CORS policy (allows all origins)',
            recommendation: 'Restrict CORS to specific trusted origins'
          });
          results.score -= 10;
        }

      } catch (requestError) {
        results.findings.push({
          severity: 'INFO',
          category: 'Connectivity',
          issue: `Could not reach endpoint: ${requestError.message}`,
          recommendation: 'Verify endpoint URL and network connectivity'
        });
      }

      if (results.findings.length === 0) {
        results.findings.push({
          severity: 'INFO',
          category: 'Overall',
          issue: 'No major security issues detected',
          recommendation: 'Continue monitoring and regular security audits'
        });
      }

      return results;

    } catch (error) {
      console.error("❌ API endpoint test failed:", error);
      throw error;
    }
  }

  /**
   * Generate penetration testing report for a repository
   */
  async generatePenetrationTestReport(repositoryId) {
    try {
      const Issue = require('../models/Issue');
      const Repository = require('../models/Repository');

      const repository = await Repository.findById(repositoryId);
      const issues = await Issue.find({
        repositoryId,
        status: { $ne: 'resolved' }
      });

      // Identify attack surfaces
      const attackSurfaces = issues
        .filter(i => ['api-security', 'pen-test', 'security'].includes(i.issueType))
        .map(i => ({
          surface: i.filePath || 'Unknown',
          vulnerability: i.title,
          severity: i.severity,
          testingStrategy: i.suggestedFix || 'Manual review recommended'
        }));

      const report = {
        repository: repository.repoName,
        generatedAt: new Date(),
        summary: {
          totalVulnerabilities: issues.length,
          criticalFindings: issues.filter(i => i.severity === 'CRITICAL').length,
          attackSurfaces: attackSurfaces.length
        },
        attackSurfaces,
        recommendations: [
          'Conduct regular security audits',
          'Implement automated security testing in CI/CD',
          'Review and update authentication mechanisms',
          'Ensure all endpoints have proper authorization checks',
          'Keep dependencies up to date'
        ]
      };

      return report;
    } catch (error) {
      console.error("❌ Pen test report generation failed:", error);
      throw error;
    }
  }
}

module.exports = new SecurityAdvisorService();
