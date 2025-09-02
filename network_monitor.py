#!/usr/bin/env python3
"""
Network Connection Monitor
A Python tool to monitor and track network connections on PC
"""

import psutil
import time
import json
import csv
from datetime import datetime
from collections import defaultdict
import argparse
import os
import threading
from typing import Dict, List, Set, Optional

class NetworkMonitor:
    def __init__(self):
        self.connections_history = []
        self.process_cache = {}
        self.running = False
        self.monitor_thread = None
        
    def get_process_info(self, pid: int) -> Dict:
        """Get process information for a given PID"""
        if pid in self.process_cache:
            return self.process_cache[pid]
            
        try:
            process = psutil.Process(pid)
            info = {
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': ' '.join(process.cmdline()) if process.cmdline() else '',
                'create_time': datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S')
            }
            self.process_cache[pid] = info
            return info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return {
                'name': 'Unknown',
                'exe': 'Unknown',
                'cmdline': 'Unknown',
                'create_time': 'Unknown'
            }
    
    def get_current_connections(self) -> List[Dict]:
        """Get all current network connections"""
        connections = []
        
        try:
            # Get all network connections
            net_connections = psutil.net_connections(kind='inet')
            
            for conn in net_connections:
                connection_info = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'family': 'IPv4' if conn.family == 2 else 'IPv6',
                    'type': 'TCP' if conn.type == 1 else 'UDP',
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                    'status': conn.status if hasattr(conn, 'status') else 'N/A',
                    'pid': conn.pid if conn.pid else 0
                }
                
                # Add process information
                if conn.pid:
                    process_info = self.get_process_info(conn.pid)
                    connection_info.update({
                        'process_name': process_info['name'],
                        'process_exe': process_info['exe'],
                        'process_cmdline': process_info['cmdline'],
                        'process_start_time': process_info['create_time']
                    })
                else:
                    connection_info.update({
                        'process_name': 'System',
                        'process_exe': 'System',
                        'process_cmdline': 'System Process',
                        'process_start_time': 'N/A'
                    })
                
                connections.append(connection_info)
                
        except Exception as e:
            print(f"Error getting connections: {e}")
            
        return connections
    
    def monitor_connections(self, interval: int = 5, duration: Optional[int] = None):
        """Monitor connections continuously"""
        self.running = True
        start_time = time.time()
        
        print(f"Starting network monitoring (interval: {interval}s)")
        if duration:
            print(f"Will run for {duration} seconds")
        print("Press Ctrl+C to stop\n")
        
        try:
            while self.running:
                connections = self.get_current_connections()
                self.connections_history.extend(connections)
                
                print(f"\n=== {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
                print(f"Active connections: {len(connections)}")
                
                # Group by process
                by_process = defaultdict(list)
                for conn in connections:
                    by_process[conn['process_name']].append(conn)
                
                for process_name, conns in by_process.items():
                    print(f"\n{process_name} ({len(conns)} connections):")
                    for conn in conns[:5]:  # Show first 5 connections per process
                        print(f"  {conn['type']} {conn['local_address']} -> {conn['remote_address']} [{conn['status']}]")
                    if len(conns) > 5:
                        print(f"  ... and {len(conns) - 5} more")
                
                # Check if duration exceeded
                if duration and (time.time() - start_time) >= duration:
                    break
                    
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")
        finally:
            self.running = False
    
    def start_background_monitoring(self, interval: int = 5):
        """Start monitoring in background thread"""
        if self.monitor_thread and self.monitor_thread.is_alive():
            print("Monitoring is already running")
            return
            
        self.monitor_thread = threading.Thread(
            target=self.monitor_connections,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
        print("Background monitoring started")
    
    def stop_monitoring(self):
        """Stop background monitoring"""
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
        print("Monitoring stopped")
    
    def get_statistics(self) -> Dict:
        """Get connection statistics"""
        if not self.connections_history:
            return {}
            
        stats = {
            'total_connections': len(self.connections_history),
            'unique_processes': len(set(conn['process_name'] for conn in self.connections_history)),
            'connection_types': defaultdict(int),
            'connection_states': defaultdict(int),
            'top_processes': defaultdict(int),
            'top_remote_addresses': defaultdict(int)
        }
        
        for conn in self.connections_history:
            stats['connection_types'][conn['type']] += 1
            stats['connection_states'][conn['status']] += 1
            stats['top_processes'][conn['process_name']] += 1
            if conn['remote_address']:
                stats['top_remote_addresses'][conn['remote_address']] += 1
        
        # Convert to sorted lists
        stats['top_processes'] = sorted(stats['top_processes'].items(), key=lambda x: x[1], reverse=True)[:10]
        stats['top_remote_addresses'] = sorted(stats['top_remote_addresses'].items(), key=lambda x: x[1], reverse=True)[:10]
        
        return stats
    
    def export_to_csv(self, filename: str):
        """Export connections history to CSV"""
        if not self.connections_history:
            print("No data to export")
            return
            
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = self.connections_history[0].keys()
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.connections_history)
        
        print(f"Data exported to {filename}")
    
    def export_to_json(self, filename: str):
        """Export connections history to JSON"""
        if not self.connections_history:
            print("No data to export")
            return
            
        with open(filename, 'w', encoding='utf-8') as jsonfile:
            json.dump(self.connections_history, jsonfile, indent=2, ensure_ascii=False)
        
        print(f"Data exported to {filename}")
    
    def show_current_connections(self):
        """Display current connections in a formatted way"""
        connections = self.get_current_connections()
        
        if not connections:
            print("No active connections found")
            return
        
        print(f"\n=== Current Network Connections ({len(connections)} total) ===\n")
        
        # Group by process
        by_process = defaultdict(list)
        for conn in connections:
            by_process[conn['process_name']].append(conn)
        
        for process_name, conns in sorted(by_process.items()):
            print(f"🔹 {process_name} ({len(conns)} connections)")
            print("-" * 60)
            
            for conn in conns:
                local = conn['local_address']
                remote = conn['remote_address'] if conn['remote_address'] else 'N/A'
                status = conn['status']
                conn_type = conn['type']
                
                print(f"  {conn_type:3} | {local:22} -> {remote:22} | {status}")
            
            print()

def main():
    parser = argparse.ArgumentParser(description='Network Connection Monitor')
    parser.add_argument('--interval', '-i', type=int, default=5, help='Monitoring interval in seconds (default: 5)')
    parser.add_argument('--duration', '-d', type=int, help='Monitoring duration in seconds')
    parser.add_argument('--export-csv', help='Export results to CSV file')
    parser.add_argument('--export-json', help='Export results to JSON file')
    parser.add_argument('--current', '-c', action='store_true', help='Show current connections only')
    parser.add_argument('--stats', '-s', action='store_true', help='Show statistics after monitoring')
    
    args = parser.parse_args()
    
    monitor = NetworkMonitor()
    
    try:
        if args.current:
            monitor.show_current_connections()
        else:
            monitor.monitor_connections(args.interval, args.duration)
            
            if args.stats:
                stats = monitor.get_statistics()
                print("\n=== STATISTICS ===")
                print(f"Total connections recorded: {stats['total_connections']}")
                print(f"Unique processes: {stats['unique_processes']}")
                
                print("\nConnection types:")
                for conn_type, count in stats['connection_types'].items():
                    print(f"  {conn_type}: {count}")
                
                print("\nTop processes:")
                for process, count in stats['top_processes']:
                    print(f"  {process}: {count}")
                
                print("\nTop remote addresses:")
                for address, count in stats['top_remote_addresses']:
                    print(f"  {address}: {count}")
            
            if args.export_csv:
                monitor.export_to_csv(args.export_csv)
            
            if args.export_json:
                monitor.export_to_json(args.export_json)
                
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()