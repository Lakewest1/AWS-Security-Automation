# checks/ec2_checks.py
# EC2 Security Checks

class EC2Checks:
    def __init__(self, ec2_client):
        self.ec2 = ec2_client
    
    def check_open_security_groups(self):
        """Check security groups with unrestricted SSH/RDP access"""
        try:
            # Get all security groups
            security_groups = self.ec2.describe_security_groups()['SecurityGroups']
            
            insecure_groups = []
            
            for sg in security_groups:
                sg_name = sg['GroupName']
                
                for permission in sg.get('IpPermissions', []):
                    from_port = permission.get('FromPort')
                    to_port = permission.get('ToPort')
                    
                    # Check for SSH (22) or RDP (3389)
                    if from_port in [22, 3389] or to_port in [22, 3389]:
                        # Check if open to the world
                        for ip_range in permission.get('IpRanges', []):
                            if ip_range['CidrIp'] == '0.0.0.0/0':
                                insecure_groups.append(sg_name)
                                break
            
            if insecure_groups:
                return {
                    "check_id": "EC2-SECURITY-GROUPS",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "title": "Insecure Security Groups",
                    "description": f"Found {len(insecure_groups)} groups open to the world",
                    "remediation": "Restrict SSH/RDP to specific IPs"
                }
            else:
                return {
                    "check_id": "EC2-SECURITY-GROUPS",
                    "status": "PASS",
                    "severity": "HIGH",
                    "title": "Security Groups Secure",
                    "description": "No unrestricted SSH/RDP access found",
                    "remediation": "No action needed"
                }
                
        except Exception as e:
            return self._create_error_result("EC2-SECURITY-GROUPS", "Security Groups Check", str(e))
    
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
        """Run all EC2 checks"""
        print("🖥️  Running EC2 Security Checks...")
        
        checks = [
            self.check_open_security_groups,
        ]
        
        results = []
        for check_function in checks:
            result = check_function()
            results.append(result)
            status_icon = "✅" if result['status'] == 'PASS' else "❌" if result['status'] == 'FAIL' else "⚠️"
            print(f"  {status_icon} {result['title']}")
        
        return results