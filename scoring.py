# scoring.py - Complete fixed version
# Simple Risk Scoring Logic

class RiskScorer:
    def __init__(self):
        # Define severity weights
        self.severity_weights = {
            "CRITICAL": 10,
            "HIGH": 7,
            "MEDIUM": 4,
            "LOW": 1,
            "UNKNOWN": 0
        }
        
        # Define status scores
        self.status_scores = {
            "PASS": 0,      # No risk
            "WARN": 0.5,    # Low risk
            "FAIL": 1,      # High risk
            "ERROR": 0.2,   # Unknown risk
            "INFO": 0       # Information only
        }
    
    def calculate_risk_score(self, results):
        """
        Calculate overall risk score (0-100, where 0 is perfect, 100 is worst)
        """
        if not results:
            return {
                "overall_risk_score": 0,
                "risk_level": "UNKNOWN",
                "risk_emoji": "⚪",
                "total_checks": 0,
                "passed_checks": 0,
                "failed_checks": 0,
                "warning_checks": 0,
                "error_checks": 0,
            }
        
        total_weighted_risk = 0
        max_possible_risk = 0
        
        # Calculate risk
        for result in results:
            severity = result.get("severity", "UNKNOWN")
            status = result.get("status", "ERROR")
            
            # Add to risk calculation
            weight = self.severity_weights.get(severity, 0)
            status_score = self.status_scores.get(status, 0)
            
            total_weighted_risk += weight * status_score
            max_possible_risk += weight * 1  # Worst case: all FAIL
        
        # Calculate scores
        if max_possible_risk == 0:
            risk_score = 0
        else:
            risk_score = (total_weighted_risk / max_possible_risk) * 100
        
        # Count checks by status
        total_checks = len(results)
        passed_checks = len([r for r in results if r.get("status") == "PASS"])
        failed_checks = len([r for r in results if r.get("status") == "FAIL"])
        warning_checks = len([r for r in results if r.get("status") == "WARN"])
        error_checks = len([r for r in results if r.get("status") == "ERROR"])
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = "CRITICAL"
            emoji = "🔴"
        elif risk_score >= 40:
            risk_level = "HIGH"
            emoji = "🟠"
        elif risk_score >= 20:
            risk_level = "MEDIUM"
            emoji = "🟡"
        elif risk_score >= 5:
            risk_level = "LOW"
            emoji = "🔵"
        else:
            risk_level = "EXCELLENT"
            emoji = "🟢"
        
        return {
            "overall_risk_score": round(risk_score, 1),
            "risk_level": risk_level,
            "risk_emoji": emoji,
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
            "warning_checks": warning_checks,
            "error_checks": error_checks,
        }
    
    def generate_summary_report(self, score_results):
        """Create a human-readable summary"""
        summary = []
        summary.append("=" * 60)
        summary.append("🔍 AWS SECURITY AUDIT SUMMARY")
        summary.append("=" * 60)
        summary.append(f"Overall Risk Score: {score_results['overall_risk_score']}/100 {score_results['risk_emoji']}")
        summary.append(f"Risk Level: {score_results['risk_level']}")
        summary.append("-" * 60)
        summary.append("Check Results:")
        summary.append(f"  Total Checks: {score_results['total_checks']}")
        summary.append(f"  ✅ Passed: {score_results['passed_checks']}")
        summary.append(f"  ❌ Failed: {score_results['failed_checks']}")
        summary.append(f"  ⚠️  Warnings: {score_results['warning_checks']}")
        summary.append(f"  🔧 Errors: {score_results['error_checks']}")
        
        # Add priority actions based on findings
        if score_results['failed_checks'] > 0:
            summary.append("-" * 60)
            summary.append("🔴 PRIORITY ACTIONS REQUIRED:")
            if score_results['overall_risk_score'] >= 70:
                summary.append("  • Fix CRITICAL findings immediately")
            elif score_results['overall_risk_score'] >= 40:
                summary.append("  • Address HIGH severity findings this week")
            else:
                summary.append("  • Review all findings in next security review")
        
        summary.append("=" * 60)
        
        return "\n".join(summary)