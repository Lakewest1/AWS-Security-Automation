# checks/iam_checks.py
# IAM Security Checks

from datetime import datetime, timezone

class IAMChecks:
    def __init__(self, iam_client):
        self.iam = iam_client
    
    def check_root_mfa_enabled(self):
        """CIS 1.1: Check if root account has MFA enabled"""
        try:
            # Get MFA devices
            mfa_devices = self.iam.list_virtual_mfa_devices()
            
            # Check if any MFA device is enabled for root account
            root_mfa_enabled = False
            for device in mfa_devices['VirtualMFADevices']:
                if device.get('User', {}).get('UserName') == 'root':
                    root_mfa_enabled = True
                    break
            #If enable i give it pass and i print good result
            if root_mfa_enabled:
                return {
                    "check_id": "CIS-1.1",
                    "status": "PASS",
                    "severity": "CRITICAL",
                    "title": "Root MFA Enabled",
                    "description": "Root account has Multi-Factor Authentication enabled",
                    "remediation": "No action needed"
                }
            else:
                return {
                    "check_id": "CIS-1.1",
                    "status": "FAIL",
                    "severity": "CRITICAL",
                    "title": "Root MFA Not Enabled",
                    "description": "Root account does not have MFA enabled",
                    "remediation": "Enable MFA for root account in IAM console"
                }
                
        except Exception as e:
            return self._create_error_result("CIS-1.1", "Root MFA Check", str(e))
    
    #HOw to check Password Policy####################################
    
    def check_iam_password_policy(self):
        """CIS 1.5: Check IAM password policy strength"""
        try:
            # Get current password policy
            policy = self.iam.get_account_password_policy()['PasswordPolicy']
            
            issues = []
            
            # Check minimum password length
            if policy.get('MinimumPasswordLength', 0) < 14:
                issues.append(f"Password length too short ({policy.get('MinimumPasswordLength')})")
            
            # Check complexity requirements
            if not policy.get('RequireSymbols', False):
                issues.append("No symbol requirement")
            if not policy.get('RequireNumbers', False):
                issues.append("No number requirement")
            if not policy.get('RequireUppercaseCharacters', False):
                issues.append("No uppercase requirement")
            
            if issues:
                return {
                    "check_id": "CIS-1.5",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "title": "Weak Password Policy",
                    "description": f"Password policy issues: {', '.join(issues)}",
                    "remediation": "Update password policy in IAM console"
                }
            else:
                return {
                    "check_id": "CIS-1.5",
                    "status": "PASS",
                    "severity": "HIGH",
                    "title": "Strong Password Policy",
                    "description": "Password policy meets basic requirements",
                    "remediation": "No action needed"
                }
                
        except Exception as e:
            if "NoSuchEntity" in str(e):
                return {
                    "check_id": "CIS-1.5",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "title": "No Password Policy",
                    "description": "No password policy configured",
                    "remediation": "Create a password policy in IAM console"
                }
            return self._create_error_result("CIS-1.5", "Password Policy Check", str(e))
    
    def check_access_keys_90_days(self):
        """Check access keys older than 90 days"""
        try:
            # List all users
            users = self.iam.list_users()['Users']
            
            old_keys = []
            
            for user in users:
                username = user['UserName']
                
                # Get access keys for this user
                access_keys = self.iam.list_access_keys(UserName=username)['AccessKeyMetadata']
                
                for key in access_keys:
                    key_age = (datetime.now(timezone.utc) - key['CreateDate']).days
                    
                    if key_age > 90:
                        old_keys.append({
                            'user': username,
                            'age_days': key_age
                        })
            
            if old_keys:
                return {
                    "check_id": "IAM-ACCESS-KEYS",
                    "status": "WARN",
                    "severity": "MEDIUM",
                    "title": "Old Access Keys Found",
                    "description": f"Found {len(old_keys)} access keys older than 90 days",
                    "remediation": "Rotate old access keys"
                }
            else:
                return {
                    "check_id": "IAM-ACCESS-KEYS",
                    "status": "PASS",
                    "severity": "MEDIUM",
                    "title": "Access Keys Up-to-date",
                    "description": "All access keys are relatively new",
                    "remediation": "No action needed"
                }
                
        except Exception as e:
            return self._create_error_result("IAM-ACCESS-KEYS", "Access Keys Age Check", str(e))
    
    def _create_error_result(self, check_id, check_name, error):
        """Helper to create error result"""
        return {
            "check_id": check_id,
            "status": "ERROR",
            "severity": "UNKNOWN",
            "title": f"{check_name} Error",
            "description": f"Failed to run check: {error}",
            "remediation": "Check AWS permissions"
        }
    
    def run_all_checks(self):
        """Run all IAM checks"""
        print("🔐 Running IAM Security Checks...")
        
        checks = [
            self.check_root_mfa_enabled,
            self.check_iam_password_policy,
            self.check_access_keys_90_days,
        ]
        
        results = []
        for check_function in checks:
            result = check_function()
            results.append(result)
            status_icon = "✅" if result['status'] == 'PASS' else "❌" if result['status'] == 'FAIL' else "⚠️"
            print(f"  {status_icon} {result['title']}")
        
        return results