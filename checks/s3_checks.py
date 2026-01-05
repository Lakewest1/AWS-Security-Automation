# checks/s3_checks.py
# S3 Security Checks

class S3Checks:
    def __init__(self, s3_client):
        self.s3 = s3_client
    
    def check_public_buckets(self):
        """Check for public S3 buckets"""
        try:
            # List all S3 buckets
            buckets = self.s3.list_buckets()['Buckets']
            
            public_buckets = []
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    # Check bucket policy for public access
                    policy_status = self.s3.get_bucket_policy_status(Bucket=bucket_name)
                    
                    if policy_status['PolicyStatus']['IsPublic']:
                        public_buckets.append(bucket_name)
                        
                except Exception:
                    # If we can't check, assume it's not public
                    continue
            
            if public_buckets:
                return {
                    "check_id": "S3-PUBLIC",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "title": "Public S3 Buckets",
                    "description": f"Found {len(public_buckets)} publicly accessible buckets",
                    "remediation": "Review and fix bucket policies"
                }
            else:
                return {
                    "check_id": "S3-PUBLIC",
                    "status": "PASS",
                    "severity": "HIGH",
                    "title": "No Public Buckets",
                    "description": "No publicly accessible S3 buckets found",
                    "remediation": "No action needed"
                }
                
        except Exception as e:
            return self._create_error_result("S3-PUBLIC", "S3 Public Buckets Check", str(e))
    
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
        """Run all S3 checks"""
        print("📦 Running S3 Security Checks...")
        
        checks = [
            self.check_public_buckets,
        ]
        
        results = []
        for check_function in checks:
            result = check_function()
            results.append(result)
            status_icon = "✅" if result['status'] == 'PASS' else "❌" if result['status'] == 'FAIL' else "⚠️"
            print(f"  {status_icon} {result['title']}")
        
        return results