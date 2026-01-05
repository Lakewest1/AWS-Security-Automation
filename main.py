#!/usr/bin/env python3
"""
AWS Security Scanner - Simple Version
"""

import argparse
import sys
from datetime import datetime

# Import our modules
from config import get_session, get_clients
from checks.iam_checks import IAMChecks
from checks.s3_checks import S3Checks
from checks.ec2_checks import EC2Checks
from checks.cloudtrail_checks import CloudTrailChecks
from scoring import RiskScorer
from report import ReportGenerator

def main():
    """
    Main function - orchestrates the entire security scan
    """
    print("🔐 AWS Security Scanner")
    print("=" * 50)
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Scan AWS account for security issues"
    )
    parser.add_argument(
        "--profile",
        help="AWS profile name (from ~/.aws/credentials)",
        default="default"
    )
    parser.add_argument(
        "--region",
        help="AWS region to scan",
        default="us-east-1"
    )
    parser.add_argument(
        "--output",
        choices=["json", "csv", "html", "all"],
        default="json",
        help="Output format"
    )
    
    args = parser.parse_args()
    
    # Record start time
    start_time = datetime.now()
    print(f"Scan started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Profile: {args.profile}")
    print(f"Region: {args.region}")
    print("-" * 50)
    
    try:
        # Step 1: Connect to AWS
        print("\n🔗 Connecting to AWS...")
        session = get_session(profile_name=args.profile, region=args.region)
        clients = get_clients(session)
        print("✅ Connected successfully!")
        
        # Step 2: Initialize checkers and run checks
        all_results = []
        
        print("\n🚀 Running Security Checks...")
        
        # IAM Checks
        iam_checker = IAMChecks(clients["iam"])
        iam_results = iam_checker.run_all_checks()
        all_results.extend(iam_results)
        
        # S3 Checks
        s3_checker = S3Checks(clients["s3"])
        s3_results = s3_checker.run_all_checks()
        all_results.extend(s3_results)
        
        # EC2 Checks
        ec2_checker = EC2Checks(clients["ec2"])
        ec2_results = ec2_checker.run_all_checks()
        all_results.extend(ec2_results)
        
        # CloudTrail Checks
        cloudtrail_checker = CloudTrailChecks(clients["cloudtrail"])
        cloudtrail_results = cloudtrail_checker.run_all_checks()
        all_results.extend(cloudtrail_results)
        
        # Step 3: Calculate risk scores
        print("\n📊 Calculating risk scores...")
        scorer = RiskScorer()
        score_results = scorer.calculate_risk_score(all_results)
        
        # Step 4: Generate reports
        print("\n📋 Generating reports...")
        reporter = ReportGenerator()
        
        # Always print text summary
        text_summary = reporter.generate_text_summary(all_results, score_results)
        print(text_summary)
        
        # Print executive summary
        executive_summary = scorer.generate_summary_report(score_results)
        print(executive_summary)
        
        # Generate output files
        if args.output in ["json", "all"]:
            reporter.generate_json_report(all_results, score_results)
        
        if args.output in ["csv", "all"]:
            reporter.generate_csv_report(all_results)
        
        if args.output in ["html", "all"]:
            reporter.generate_html_report(all_results, score_results)
        
        # Step 5: Print completion message
        end_time = datetime.now()
        duration = end_time - start_time
        
        print("\n" + "=" * 50)
        print("✅ Scan Completed Successfully!")
        print(f"⏱️  Duration: {duration.total_seconds():.1f} seconds")
        print(f"📊 Risk Level: {score_results['risk_level']} {score_results['risk_emoji']}")
        print("=" * 50)
        
        # Exit with appropriate code
        if score_results['failed_checks'] > 0:
            print("\n❌ Security issues found. Please review the findings.")
            sys.exit(1)
        else:
            print("\n✅ No critical security issues found!")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Error during scan: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()