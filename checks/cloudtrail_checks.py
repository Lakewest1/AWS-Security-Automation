# checks/cloudtrail_checks.py
# CloudTrail Checks

class CloudTrailChecks:
    def __init__(self, cloudtrail_client):
        self.cloudtrail = cloudtrail_client
    
    def check_cloudtrail_enabled(self):
        """Check if CloudTrail is enabled"""
        try:
            # Get all CloudTrail trails
            trails = self.cloudtrail.describe_trails()['trailList']
            
            if not trails:
                return {
                    "check_id": "CLOUDTRAIL",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "title": "CloudTrail Not Enabled",
                    "description": "No CloudTrail trails found",
                    "remediation": "Enable CloudTrail from console"
                }
            
            # Check if any trail is logging
            for trail in trails:
                status = self.cloudtrail.get_trail_status(Name=trail['TrailARN'])
                if status.get('IsLogging', False):
                    return {
                        "check_id": "CLOUDTRAIL",
                        "status": "PASS",
                        "severity": "HIGH",
                        "title": "CloudTrail Enabled",
                        "description": "CloudTrail is enabled and logging",
                        "remediation": "No action needed"
                    }
            
            return {
                "check_id": "CLOUDTRAIL",
                "status": "FAIL",
                "severity": "HIGH",
                "title": "CloudTrail Not Logging",
                "description": "CloudTrail exists but not logging",
                "remediation": "Start CloudTrail logging"
            }
            
        except Exception as e:
            return self._create_error_result("CLOUDTRAIL", "CloudTrail Check", str(e))
    
    def _create_error_result(self, check_id, check_name, error):
        return {
            "check_id": check_id,
            "status": "ERROR",
            "severity": "UNKNOWN",
            "title": f"{check_name} Error",
            "description": f"Failed to run check: {error}",
            "remediation": "Check AWS permissions"
        }
    
    def run_all_checks(self): 
        """Run all CloudTrail checks"""
        print("📝 Running CloudTrail Security Checks...")
        
        checks = [
            self.check_cloudtrail_enabled,
        ]
        
        results = []
        for check_function in checks:
            result = check_function()
            results.append(result)
            status_icon = "✅" if result['status'] == 'PASS' else "❌" if result['status'] == 'FAIL' else "⚠️"
            print(f"  {status_icon} {result['title']}")
        
        return results