#!/usr/bin/env python3
"""
Web Address Monitor
A Python tool specifically designed to monitor web addresses/URLs accessed from PC
"""

import psutil
import socket
import requests
import time
import json
import csv
from datetime import datetime
from collections import defaultdict
import threading
from typing import Dict, List, Set, Optional
import re
from urllib.parse import urlparse

class WebAddressMonitor:
    def __init__(self):
        self.web_connections = []
        self.domain_cache = {}
        self.running = False
        self.monitor_thread = None
        
        # Common web ports
        self.web_ports = {80, 443, 8080, 8443, 3000, 5000, 8000, 9000}
        
        # Known web browsers
        self.browsers = {
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe',
            'opera.exe', 'brave.exe', 'vivaldi.exe', 'safari.exe',
            'chromium.exe', 'edge.exe'
        }
        
    def resolve_ip_to_domain(self, ip_address: str) -> str:
        """Resolve IP address to domain name"""
        if ip_address in self.domain_cache:
            return self.domain_cache[ip_address]
        
        try:
            domain = socket.gethostbyaddr(ip_address)[0]
            self.domain_cache[ip_address] = domain
            return domain
        except (socket.herror, socket.gaierror):
            self.domain_cache[ip_address] = ip_address
            return ip_address
    
    def is_web_connection(self, conn) -> bool:
        """Check if connection is web-related"""
        if not conn.raddr:
            return False
            
        # Check if it's a common web port
        remote_port = conn.raddr.port
        if remote_port in self.web_ports:
            return True
            
        # Check if it's from a browser process
        if conn.pid:
            try:
                process = psutil.Process(conn.pid)
                process_name = process.name().lower()
                return any(browser in process_name for browser in self.browsers)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
                
        return False
    
    def get_process_info(self, pid: int) -> Dict:
        """Get detailed process information"""
        try:
            process = psutil.Process(pid)
            return {
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': ' '.join(process.cmdline()) if process.cmdline() else '',
                'create_time': datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S')
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return {
                'name': 'Unknown',
                'exe': 'Unknown', 
                'cmdline': 'Unknown',
                'create_time': 'Unknown'
            }
    
    def categorize_website(self, domain: str) -> str:
        """Categorize website by domain"""
        domain_lower = domain.lower()
        
        categories = {
            'Search': ['google', 'bing', 'yahoo', 'duckduckgo', 'baidu'],
            'Social Media': ['facebook', 'twitter', 'instagram', 'linkedin', 'tiktok', 'youtube', 'reddit'],
            'E-commerce': ['amazon', 'ebay', 'shopee', 'lazada', 'tiki'],
            'News': ['bbc', 'cnn', 'vnexpress', 'tuoitre', 'thanhnien'],
            'Technology': ['github', 'stackoverflow', 'microsoft', 'apple', 'developer'],
            'Entertainment': ['netflix', 'spotify', 'twitch', 'disney'],
            'Cloud/CDN': ['cloudflare', 'amazonaws', 'googleusercontent', 'fbcdn'],
            'Banking': ['vietcombank', 'techcombank', 'mbbank', 'agribank']
        }
        
        for category, keywords in categories.items():
            if any(keyword in domain_lower for keyword in keywords):
                return category
        
        return 'Other'
    
    def get_web_connections(self) -> List[Dict]:
        """Get current web connections with domain resolution"""
        web_connections = []
        
        try:
            net_connections = psutil.net_connections(kind='inet')
            
            for conn in net_connections:
                if not self.is_web_connection(conn):
                    continue
                
                if conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    
                    # Resolve IP to domain
                    domain = self.resolve_ip_to_domain(remote_ip)
                    
                    # Determine protocol
                    protocol = 'HTTPS' if remote_port == 443 else 'HTTP' if remote_port == 80 else f'Port {remote_port}'
                    
                    # Get process info
                    process_info = self.get_process_info(conn.pid) if conn.pid else {
                        'name': 'System', 'exe': 'System', 'cmdline': 'System', 'create_time': 'N/A'
                    }
                    
                    connection_info = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'domain': domain,
                        'ip_address': remote_ip,
                        'port': remote_port,
                        'protocol': protocol,
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                        'status': conn.status if hasattr(conn, 'status') else 'N/A',
                        'process_name': process_info['name'],
                        'process_exe': process_info['exe'],
                        'process_cmdline': process_info['cmdline'],
                        'category': self.categorize_website(domain),
                        'pid': conn.pid if conn.pid else 0
                    }
                    
                    web_connections.append(connection_info)
        
        except Exception as e:
            print(f"Error getting web connections: {e}")
            
        return web_connections
    
    def monitor_web_traffic(self, interval: int = 3, duration: Optional[int] = None):
        """Monitor web traffic continuously"""
        self.running = True
        start_time = time.time()
        
        print(f"🌐 Starting web address monitoring (interval: {interval}s)")
        if duration:
            print(f"Will run for {duration} seconds")
        print("Press Ctrl+C to stop\n")
        
        try:
            while self.running:
                connections = self.get_web_connections()
                self.web_connections.extend(connections)
                
                print(f"\n{'='*80}")
                print(f"🕒 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - Active Web Connections: {len(connections)}")
                print(f"{'='*80}")
                
                if connections:
                    # Group by category
                    by_category = defaultdict(list)
                    for conn in connections:
                        by_category[conn['category']].append(conn)
                    
                    for category, conns in by_category.items():
                        print(f"\n📂 {category} ({len(conns)} connections):")
                        print("-" * 60)
                        
                        # Group by domain within category
                        by_domain = defaultdict(list)
                        for conn in conns:
                            by_domain[conn['domain']].append(conn)
                        
                        for domain, domain_conns in list(by_domain.items())[:10]:  # Show top 10 domains per category
                            browsers = set(conn['process_name'] for conn in domain_conns)
                            protocols = set(conn['protocol'] for conn in domain_conns)
                            
                            print(f"  🌍 {domain}")
                            print(f"     📱 Apps: {', '.join(browsers)}")
                            print(f"     🔒 Protocols: {', '.join(protocols)}")
                            print(f"     📊 Connections: {len(domain_conns)}")
                            print()
                else:
                    print("No web connections detected")
                
                # Check duration
                if duration and (time.time() - start_time) >= duration:
                    break
                    
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n🛑 Monitoring stopped by user")
        finally:
            self.running = False
    
    def get_web_statistics(self) -> Dict:
        """Get comprehensive web statistics"""
        if not self.web_connections:
            return {}
        
        stats = {
            'total_connections': len(self.web_connections),
            'unique_domains': len(set(conn['domain'] for conn in self.web_connections)),
            'categories': defaultdict(int),
            'top_domains': defaultdict(int),
            'browsers_used': defaultdict(int),
            'protocols': defaultdict(int),
            'hourly_activity': defaultdict(int)
        }
        
        for conn in self.web_connections:
            stats['categories'][conn['category']] += 1
            stats['top_domains'][conn['domain']] += 1
            stats['browsers_used'][conn['process_name']] += 1
            stats['protocols'][conn['protocol']] += 1
            
            # Extract hour for activity analysis
            hour = conn['timestamp'].split(' ')[1].split(':')[0]
            stats['hourly_activity'][f"{hour}:00"] += 1
        
        # Convert to sorted lists
        stats['top_domains'] = sorted(stats['top_domains'].items(), key=lambda x: x[1], reverse=True)[:20]
        stats['browsers_used'] = sorted(stats['browsers_used'].items(), key=lambda x: x[1], reverse=True)
        stats['categories'] = sorted(stats['categories'].items(), key=lambda x: x[1], reverse=True)
        
        return stats
    
    def show_current_web_activity(self):
        """Display current web activity in a formatted way"""
        connections = self.get_web_connections()
        
        if not connections:
            print("🚫 No web connections detected")
            return
        
        print(f"\n🌐 Current Web Activity ({len(connections)} connections)")
        print("="*80)
        
        # Group by domain
        by_domain = defaultdict(list)
        for conn in connections:
            by_domain[conn['domain']].append(conn)
        
        for domain, conns in sorted(by_domain.items(), key=lambda x: len(x[1]), reverse=True):
            browsers = set(conn['process_name'] for conn in conns)
            protocols = set(conn['protocol'] for conn in conns)
            category = conns[0]['category']
            
            print(f"\n🌍 {domain} ({category})")
            print(f"   📱 Apps: {', '.join(browsers)}")
            print(f"   🔒 Protocols: {', '.join(protocols)}")
            print(f"   📊 Active connections: {len(conns)}")
            
            # Show IP addresses if different from domain
            ips = set(conn['ip_address'] for conn in conns)
            if len(ips) > 1 or (len(ips) == 1 and list(ips)[0] != domain):
                print(f"   🌐 IP addresses: {', '.join(ips)}")
    
    def export_web_data(self, filename: str):
        """Export web connections to file"""
        if not self.web_connections:
            print("No web data to export")
            return
        
        if filename.endswith('.json'):
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.web_connections, f, indent=2, ensure_ascii=False)
        else:
            with open(filename, 'w', newline='', encoding='utf-8') as f:
                if self.web_connections:
                    fieldnames = self.web_connections[0].keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(self.web_connections)
        
        print(f"📄 Web data exported to {filename}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Web Address Monitor - Track websites accessed from your PC')
    parser.add_argument('--interval', '-i', type=int, default=3, help='Monitoring interval in seconds (default: 3)')
    parser.add_argument('--duration', '-d', type=int, help='Monitoring duration in seconds')
    parser.add_argument('--current', '-c', action='store_true', help='Show current web activity only')
    parser.add_argument('--stats', '-s', action='store_true', help='Show statistics after monitoring')
    parser.add_argument('--export', '-e', help='Export results to file (CSV or JSON)')
    
    args = parser.parse_args()
    
    monitor = WebAddressMonitor()
    
    try:
        if args.current:
            monitor.show_current_web_activity()
        else:
            monitor.monitor_web_traffic(args.interval, args.duration)
            
            if args.stats:
                stats = monitor.get_web_statistics()
                print(f"\n📊 WEB TRAFFIC STATISTICS")
                print("="*50)
                print(f"Total web connections: {stats['total_connections']}")
                print(f"Unique domains visited: {stats['unique_domains']}")
                
                print(f"\n📂 Website Categories:")
                for category, count in stats['categories']:
                    print(f"  {category}: {count}")
                
                print(f"\n🌍 Top Domains:")
                for domain, count in stats['top_domains'][:10]:
                    print(f"  {domain}: {count}")
                
                print(f"\n📱 Browsers Used:")
                for browser, count in stats['browsers_used']:
                    print(f"  {browser}: {count}")
            
            if args.export:
                monitor.export_web_data(args.export)
                
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()