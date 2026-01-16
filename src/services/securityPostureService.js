const Issue = require("../models/Issue");
const Repository = require("../models/Repository");
const PullRequest = require("../models/PullRequest");

class SecurityPostureService {
  /**
   * Calculate dynamic security posture index for a user
   * @param {string} userId - User ID
   * @returns {Object} Security posture data
   */
  async calculateSecurityPosture(userId) {
    try {
      // Get all issues for user
      const allIssues = await Issue.find({ userId });
      const openIssues = allIssues.filter(
        (i) => i.status !== "resolved" && i.status !== "ignored"
      );
      const resolvedIssues = allIssues.filter((i) => i.status === "resolved");

      // Count by severity
      const criticalCount = openIssues.filter(
        (i) => i.severity === "CRITICAL"
      ).length;
      const highCount = openIssues.filter((i) => i.severity === "HIGH").length;
      const mediumCount = openIssues.filter(
        (i) => i.severity === "MEDIUM"
      ).length;
      const lowCount = openIssues.filter((i) => i.severity === "LOW").length;

      // Get repository stats
      const repositories = await Repository.find({ userId });
      const analyzedRepos = repositories.filter(
        (r) => r.lastAnalyzedAt
      ).length;
      const totalRepos = repositories.length;

      // Get recent PR activity (last 7 days)
      const sevenDaysAgo = new Date();
      sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
      const recentPRs = await PullRequest.find({
        userId,
        createdAt: { $gte: sevenDaysAgo },
      });
      const mergedPRs = recentPRs.filter((pr) => pr.status === "merged").length;

      // Calculate base score (100)
      let postureIndex = 100;

      // Deduct points for open issues
      postureIndex -= criticalCount * 15; // Critical issues: -15 each
      postureIndex -= highCount * 8; // High issues: -8 each
      postureIndex -= mediumCount * 3; // Medium issues: -3 each
      postureIndex -= lowCount * 1; // Low issues: -1 each

      // Add points for resolved issues (up to 20 points)
      const resolvedBonus = Math.min(resolvedIssues.length * 2, 20);
      postureIndex += resolvedBonus;

      // Add points for repository coverage (up to 10 points)
      if (totalRepos > 0) {
        const coverageBonus = Math.floor(
          (analyzedRepos / totalRepos) * 10
        );
        postureIndex += coverageBonus;
      }

      // Add points for recent remediation activity (up to 10 points)
      const activityBonus = Math.min(mergedPRs * 2, 10);
      postureIndex += activityBonus;

      // Ensure score is between 0 and 100
      postureIndex = Math.max(0, Math.min(100, Math.round(postureIndex)));

      // Determine trend based on recent activity
      let trend = "stable";
      if (mergedPRs >= 3 && resolvedIssues.length > openIssues.length) {
        trend = "improving";
      } else if (criticalCount > 5 || highCount > 10) {
        trend = "declining";
      }

      // Generate recommendations
      const recommendations = this.generateRecommendations({
        criticalCount,
        highCount,
        mediumCount,
        lowCount,
        analyzedRepos,
        totalRepos,
        mergedPRs,
      });

      // Generate health advisory
      const healthAdvisory = this.generateHealthAdvisory({
        postureIndex,
        criticalCount,
        highCount,
        trend,
      });

      return {
        postureIndex,
        trend,
        breakdown: {
          critical: criticalCount,
          high: highCount,
          medium: mediumCount,
          low: lowCount,
          resolved: resolvedIssues.length,
          total: allIssues.length,
        },
        coverage: {
          analyzed: analyzedRepos,
          total: totalRepos,
          percentage: totalRepos > 0 ? Math.round((analyzedRepos / totalRepos) * 100) : 0,
        },
        activity: {
          recentPRs: recentPRs.length,
          mergedPRs,
        },
        recommendations,
        healthAdvisory,
      };
    } catch (error) {
      console.error("❌ Error calculating security posture:", error);
      throw error;
    }
  }

  /**
   * Generate actionable recommendations
   */
  generateRecommendations(stats) {
    const recommendations = [];

    if (stats.criticalCount > 0) {
      recommendations.push({
        priority: "CRITICAL",
        message: `Address ${stats.criticalCount} critical security issue${
          stats.criticalCount > 1 ? "s" : ""
        } immediately`,
        action: "Review and fix critical vulnerabilities in Issues tab",
      });
    }

    if (stats.highCount > 5) {
      recommendations.push({
        priority: "HIGH",
        message: `${stats.highCount} high-severity issues require attention`,
        action: "Prioritize high-severity fixes in your backlog",
      });
    }

    if (stats.totalRepos > stats.analyzedRepos) {
      const unanalyzed = stats.totalRepos - stats.analyzedRepos;
      recommendations.push({
        priority: "MEDIUM",
        message: `${unanalyzed} repository${
          unanalyzed > 1 ? "ies" : "y"
        } not yet analyzed`,
        action: "Run security scans on all repositories",
      });
    }

    if (stats.mergedPRs === 0) {
      recommendations.push({
        priority: "LOW",
        message: "No recent remediation activity detected",
        action: "Review and merge pending security fixes",
      });
    }

    if (recommendations.length === 0) {
      recommendations.push({
        priority: "INFO",
        message: "Security posture is healthy",
        action: "Continue monitoring and maintain current practices",
      });
    }

    return recommendations;
  }

  /**
   * Generate health advisory message
   */
  generateHealthAdvisory({ postureIndex, criticalCount, highCount, trend }) {
    if (postureIndex >= 90) {
      return "Your attack surface is highly secure. Continue monitoring for new threats.";
    } else if (postureIndex >= 75) {
      return `Your attack surface is relatively secure. ${
        criticalCount > 0
          ? `Review ${criticalCount} critical issue${criticalCount > 1 ? "s" : ""}.`
          : `Address ${highCount} high-severity issue${highCount > 1 ? "s" : ""}.`
      }`;
    } else if (postureIndex >= 50) {
      return `Security posture needs improvement. ${criticalCount + highCount} critical/high issues detected. Immediate action recommended.`;
    } else {
      return `ALERT: Critical security vulnerabilities detected. ${criticalCount} critical and ${highCount} high-severity issues require immediate remediation.`;
    }
  }
}

module.exports = new SecurityPostureService();
