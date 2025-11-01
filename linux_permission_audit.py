#!/usr/bin/env python3
"""
Linux File Permission Vulnerability Scanner
Identifies potential privilege escalation vectors through file permission analysis
"""

import os
import stat
import pwd
import grp
from pathlib import Path
from typing import List, Dict, Set
import argparse


class PermissionScanner:
    def __init__(self, scan_paths: List[str], verbose: bool = False):
        self.scan_paths = scan_paths
        self.verbose = verbose
        self.findings: Dict[str, List[Dict]] = {
            'suid_sgid': [],
            'world_writable': [],
            'weak_permissions': [],
            'suspicious_ownership': [],
            'config_files': []
        }
        
        # Common sensitive directories and files to check
        self.sensitive_paths = [
            '/etc/passwd', '/etc/shadow', '/etc/sudoers',
            '/etc/ssh/sshd_config', '/root/.ssh',
            '/home/*/.ssh', '/var/www', '/opt'
        ]
        
        # Known SUID binaries that are typically safe
        self.known_safe_suid = {
            '/usr/bin/sudo', '/usr/bin/su', '/usr/bin/passwd',
            '/usr/bin/mount', '/usr/bin/umount', '/bin/ping'
        }

    def get_file_info(self, filepath: str) -> Dict:
        """Extract detailed file information"""
        try:
            file_stat = os.stat(filepath)
            mode = file_stat.st_mode
            
            return {
                'path': filepath,
                'mode': oct(stat.S_IMODE(mode)),
                'uid': file_stat.st_uid,
                'gid': file_stat.st_gid,
                'owner': pwd.getpwuid(file_stat.st_uid).pw_name,
                'group': grp.getgrgid(file_stat.st_gid).gr_name,
                'size': file_stat.st_size,
                'is_suid': bool(mode & stat.S_ISUID),
                'is_sgid': bool(mode & stat.S_ISGID),
                'is_sticky': bool(mode & stat.S_ISVTX),
                'world_readable': bool(mode & stat.S_IROTH),
                'world_writable': bool(mode & stat.S_IWOTH),
                'world_executable': bool(mode & stat.S_IXOTH)
            }
        except (OSError, KeyError, PermissionError) as e:
            if self.verbose:
                print(f"[!] Error accessing {filepath}: {e}")
            return None

    def check_suid_sgid(self, file_info: Dict) -> bool:
        """Check for SUID/SGID binaries"""
        if file_info['is_suid'] or file_info['is_sgid']:
            risk_level = 'LOW' if file_info['path'] in self.known_safe_suid else 'HIGH'
            
            self.findings['suid_sgid'].append({
                **file_info,
                'risk': risk_level,
                'reason': f"{'SUID' if file_info['is_suid'] else 'SGID'} bit set"
            })
            return True
        return False

    def check_world_writable(self, file_info: Dict) -> bool:
        """Check for world-writable files"""
        if file_info['world_writable'] and not file_info['is_sticky']:
            risk_level = 'CRITICAL' if file_info['owner'] == 'root' else 'HIGH'
            
            self.findings['world_writable'].append({
                **file_info,
                'risk': risk_level,
                'reason': 'World-writable without sticky bit'
            })
            return True
        return False

    def check_weak_permissions(self, file_info: Dict) -> bool:
        """Check for weak permissions on sensitive files"""
        path = file_info['path']
        
        # Check if it's a sensitive file
        is_sensitive = any(
            path.startswith(sp.rstrip('*')) or path == sp 
            for sp in self.sensitive_paths
        )
        
        if is_sensitive:
            # Check for group or other write permissions
            mode = int(file_info['mode'], 8)
            group_write = bool(mode & 0o020)
            other_write = bool(mode & 0o002)
            other_read = bool(mode & 0o004)
            
            if group_write or other_write or (other_read and 'shadow' in path):
                self.findings['weak_permissions'].append({
                    **file_info,
                    'risk': 'CRITICAL',
                    'reason': 'Sensitive file with weak permissions'
                })
                return True
        return False

    def check_suspicious_ownership(self, file_info: Dict) -> bool:
        """Check for files owned by root but writable by others"""
        if file_info['owner'] == 'root':
            mode = int(file_info['mode'], 8)
            group_write = bool(mode & 0o020)
            
            # Check if group has write and group is not root
            if group_write and file_info['group'] != 'root':
                self.findings['suspicious_ownership'].append({
                    **file_info,
                    'risk': 'HIGH',
                    'reason': 'Root-owned file writable by non-root group'
                })
                return True
        return False

    def scan_directory(self, directory: str):
        """Recursively scan directory for vulnerabilities"""
        try:
            for root, dirs, files in os.walk(directory):
                # Skip common directories that cause issues
                dirs[:] = [d for d in dirs if d not in [
                    'proc', 'sys', 'dev', 'run', 'snap', '.git'
                ]]
                
                # Check directories
                dir_info = self.get_file_info(root)
                if dir_info:
                    self.check_world_writable(dir_info)
                    self.check_weak_permissions(dir_info)
                
                # Check files
                for filename in files:
                    filepath = os.path.join(root, filename)
                    file_info = self.get_file_info(filepath)
                    
                    if file_info:
                        self.check_suid_sgid(file_info)
                        self.check_world_writable(file_info)
                        self.check_weak_permissions(file_info)
                        self.check_suspicious_ownership(file_info)
                        
        except PermissionError:
            if self.verbose:
                print(f"[!] Permission denied: {directory}")

    def run_scan(self):
        """Execute the full scan"""
        print("[*] Starting Linux Permission Vulnerability Scan")
        print(f"[*] Scanning paths: {', '.join(self.scan_paths)}\n")
        
        for path in self.scan_paths:
            if os.path.exists(path):
                print(f"[*] Scanning: {path}")
                if os.path.isdir(path):
                    self.scan_directory(path)
                else:
                    file_info = self.get_file_info(path)
                    if file_info:
                        self.check_suid_sgid(file_info)
                        self.check_world_writable(file_info)
                        self.check_weak_permissions(file_info)
                        self.check_suspicious_ownership(file_info)
            else:
                print(f"[!] Path not found: {path}")

    def print_report(self):
        """Print detailed vulnerability report"""
        print("\n" + "="*80)
        print("VULNERABILITY SCAN REPORT")
        print("="*80 + "\n")
        
        total_findings = sum(len(v) for v in self.findings.values())
        print(f"Total findings: {total_findings}\n")
        
        # SUID/SGID Binaries
        if self.findings['suid_sgid']:
            print(f"\n[!] SUID/SGID Binaries ({len(self.findings['suid_sgid'])})")
            print("-" * 80)
            for item in self.findings['suid_sgid']:
                print(f"  Risk: {item['risk']}")
                print(f"  Path: {item['path']}")
                print(f"  Mode: {item['mode']} | Owner: {item['owner']}:{item['group']}")
                print(f"  Reason: {item['reason']}\n")
        
        # World-Writable Files
        if self.findings['world_writable']:
            print(f"\n[!] World-Writable Files ({len(self.findings['world_writable'])})")
            print("-" * 80)
            for item in self.findings['world_writable']:
                print(f"  Risk: {item['risk']}")
                print(f"  Path: {item['path']}")
                print(f"  Mode: {item['mode']} | Owner: {item['owner']}:{item['group']}")
                print(f"  Reason: {item['reason']}\n")
        
        # Weak Permissions
        if self.findings['weak_permissions']:
            print(f"\n[!] Weak Permissions on Sensitive Files ({len(self.findings['weak_permissions'])})")
            print("-" * 80)
            for item in self.findings['weak_permissions']:
                print(f"  Risk: {item['risk']}")
                print(f"  Path: {item['path']}")
                print(f"  Mode: {item['mode']} | Owner: {item['owner']}:{item['group']}")
                print(f"  Reason: {item['reason']}\n")
        
        # Suspicious Ownership
        if self.findings['suspicious_ownership']:
            print(f"\n[!] Suspicious Ownership ({len(self.findings['suspicious_ownership'])})")
            print("-" * 80)
            for item in self.findings['suspicious_ownership']:
                print(f"  Risk: {item['risk']}")
                print(f"  Path: {item['path']}")
                print(f"  Mode: {item['mode']} | Owner: {item['owner']}:{item['group']}")
                print(f"  Reason: {item['reason']}\n")
        
        if total_findings == 0:
            print("[+] No significant vulnerabilities found!")


def main():
    parser = argparse.ArgumentParser(
        description='Linux File Permission Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python linux_permission_audit.py /etc /usr/bin
  python linux_permission_audit.py / --verbose
  python linux_permission_audit.py /home /var/www --verbose
        """
    )
    
    parser.add_argument(
        'paths',
        nargs='+',
        help='Paths to scan (directories or files)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("[!] Warning: Not running as root. Some files may be inaccessible.")
        print("[!] For complete scan, run with sudo.\n")
    
    scanner = PermissionScanner(args.paths, args.verbose)
    scanner.run_scan()
    scanner.print_report()


if __name__ == '__main__':
    main()
