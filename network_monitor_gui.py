#!/usr/bin/env python3
"""
Network Connection Monitor GUI
A GUI version of the network monitor using tkinter
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import psutil
import threading
import time
from datetime import datetime
from collections import defaultdict
import csv
import json

class NetworkMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Connection Monitor")
        self.root.geometry("1000x700")
        
        self.monitoring = False
        self.monitor_thread = None
        self.connections_data = []
        self.process_cache = {}
        
        self.setup_ui()
        self.refresh_connections()
    
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Control panel
        control_frame = ttk.LabelFrame(main_frame, text="Controls", padding="5")
        control_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Buttons
        self.start_btn = ttk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_btn.grid(row=0, column=0, padx=(0, 5))
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring, state='disabled')
        self.stop_btn.grid(row=0, column=1, padx=(0, 5))
        
        self.refresh_btn = ttk.Button(control_frame, text="Refresh", command=self.refresh_connections)
        self.refresh_btn.grid(row=0, column=2, padx=(0, 5))
        
        self.export_btn = ttk.Button(control_frame, text="Export Data", command=self.export_data)
        self.export_btn.grid(row=0, column=3, padx=(0, 5))
        
        self.clear_btn = ttk.Button(control_frame, text="Clear History", command=self.clear_history)
        self.clear_btn.grid(row=0, column=4, padx=(0, 5))
        
        # Settings
        ttk.Label(control_frame, text="Interval (s):").grid(row=0, column=5, padx=(20, 5))
        self.interval_var = tk.StringVar(value="5")
        interval_spin = ttk.Spinbox(control_frame, from_=1, to=60, width=5, textvariable=self.interval_var)
        interval_spin.grid(row=0, column=6)
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="5")
        status_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var).grid(row=0, column=0, sticky=tk.W)
        
        self.conn_count_var = tk.StringVar(value="Connections: 0")
        ttk.Label(status_frame, textvariable=self.conn_count_var).grid(row=0, column=1, padx=(20, 0))
        
        self.history_count_var = tk.StringVar(value="History: 0")
        ttk.Label(status_frame, textvariable=self.history_count_var).grid(row=0, column=2, padx=(20, 0))
        
        # Notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Current connections tab
        self.setup_current_tab(notebook)
        
        # Process summary tab
        self.setup_process_tab(notebook)
        
        # History tab
        self.setup_history_tab(notebook)
        
        # Statistics tab
        self.setup_stats_tab(notebook)
    
    def setup_current_tab(self, notebook):
        current_frame = ttk.Frame(notebook, padding="5")
        notebook.add(current_frame, text="Current Connections")
        
        # Treeview for current connections
        columns = ('Type', 'Local Address', 'Remote Address', 'Status', 'Process', 'PID')
        self.current_tree = ttk.Treeview(current_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.current_tree.heading(col, text=col)
            self.current_tree.column(col, width=120)
        
        # Scrollbars
        v_scroll = ttk.Scrollbar(current_frame, orient=tk.VERTICAL, command=self.current_tree.yview)
        h_scroll = ttk.Scrollbar(current_frame, orient=tk.HORIZONTAL, command=self.current_tree.xview)
        self.current_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        # Grid layout
        self.current_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scroll.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        current_frame.columnconfigure(0, weight=1)
        current_frame.rowconfigure(0, weight=1)
    
    def setup_process_tab(self, notebook):
        process_frame = ttk.Frame(notebook, padding="5")
        notebook.add(process_frame, text="Process Summary")
        
        columns = ('Process', 'Connections', 'TCP', 'UDP', 'Listening', 'Established')
        self.process_tree = ttk.Treeview(process_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.process_tree.heading(col, text=col)
            self.process_tree.column(col, width=100)
        
        # Scrollbar
        p_scroll = ttk.Scrollbar(process_frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=p_scroll.set)
        
        self.process_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        p_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        process_frame.columnconfigure(0, weight=1)
        process_frame.rowconfigure(0, weight=1)
    
    def setup_history_tab(self, notebook):
        history_frame = ttk.Frame(notebook, padding="5")
        notebook.add(history_frame, text="Connection History")
        
        columns = ('Timestamp', 'Type', 'Local', 'Remote', 'Status', 'Process')
        self.history_tree = ttk.Treeview(history_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=120)
        
        # Scrollbar
        h_scroll = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=h_scroll.set)
        
        self.history_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        h_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        history_frame.columnconfigure(0, weight=1)
        history_frame.rowconfigure(0, weight=1)
    
    def setup_stats_tab(self, notebook):
        stats_frame = ttk.Frame(notebook, padding="5")
        notebook.add(stats_frame, text="Statistics")
        
        self.stats_text = tk.Text(stats_frame, wrap=tk.WORD, height=20)
        stats_scroll = ttk.Scrollbar(stats_frame, orient=tk.VERTICAL, command=self.stats_text.yview)
        self.stats_text.configure(yscrollcommand=stats_scroll.set)
        
        self.stats_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        stats_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        stats_frame.columnconfigure(0, weight=1)
        stats_frame.rowconfigure(0, weight=1)
    
    def get_process_info(self, pid):
        if pid in self.process_cache:
            return self.process_cache[pid]
        
        try:
            process = psutil.Process(pid)
            info = {
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': ' '.join(process.cmdline()) if process.cmdline() else '',
            }
            self.process_cache[pid] = info
            return info
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return {'name': 'Unknown', 'exe': 'Unknown', 'cmdline': 'Unknown'}
    
    def get_current_connections(self):
        connections = []
        try:
            net_connections = psutil.net_connections(kind='inet')
            
            for conn in net_connections:
                connection_info = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'type': 'TCP' if conn.type == 1 else 'UDP',
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else '',
                    'status': conn.status if hasattr(conn, 'status') else 'N/A',
                    'pid': conn.pid if conn.pid else 0
                }
                
                if conn.pid:
                    process_info = self.get_process_info(conn.pid)
                    connection_info['process_name'] = process_info['name']
                else:
                    connection_info['process_name'] = 'System'
                
                connections.append(connection_info)
        
        except Exception as e:
            self.status_var.set(f"Error: {e}")
        
        return connections
    
    def refresh_connections(self):
        # Clear current tree
        for item in self.current_tree.get_children():
            self.current_tree.delete(item)
        
        # Get current connections
        connections = self.get_current_connections()
        
        # Update current connections tree
        for conn in connections:
            self.current_tree.insert('', 'end', values=(
                conn['type'],
                conn['local_address'],
                conn['remote_address'],
                conn['status'],
                conn['process_name'],
                conn['pid']
            ))
        
        # Update process summary
        self.update_process_summary(connections)
        
        # Update status
        self.conn_count_var.set(f"Connections: {len(connections)}")
        self.history_count_var.set(f"History: {len(self.connections_data)}")
        
        if not self.monitoring:
            self.status_var.set("Ready")
    
    def update_process_summary(self, connections):
        # Clear process tree
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        # Group by process
        process_stats = defaultdict(lambda: {'total': 0, 'tcp': 0, 'udp': 0, 'listening': 0, 'established': 0})
        
        for conn in connections:
            process = conn['process_name']
            process_stats[process]['total'] += 1
            
            if conn['type'] == 'TCP':
                process_stats[process]['tcp'] += 1
            else:
                process_stats[process]['udp'] += 1
            
            if conn['status'] == 'LISTEN':
                process_stats[process]['listening'] += 1
            elif conn['status'] == 'ESTABLISHED':
                process_stats[process]['established'] += 1
        
        # Add to tree
        for process, stats in sorted(process_stats.items()):
            self.process_tree.insert('', 'end', values=(
                process,
                stats['total'],
                stats['tcp'],
                stats['udp'],
                stats['listening'],
                stats['established']
            ))
    
    def start_monitoring(self):
        if self.monitoring:
            return
        
        self.monitoring = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_var.set("Monitoring...")
        
        interval = int(self.interval_var.get())
        self.monitor_thread = threading.Thread(target=self.monitor_loop, args=(interval,), daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        self.monitoring = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_var.set("Stopped")
    
    def monitor_loop(self, interval):
        while self.monitoring:
            connections = self.get_current_connections()
            self.connections_data.extend(connections)
            
            # Update GUI in main thread
            self.root.after(0, self.refresh_connections)
            self.root.after(0, self.update_history)
            self.root.after(0, self.update_statistics)
            
            time.sleep(interval)
    
    def update_history(self):
        # Clear history tree
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # Show last 1000 entries
        recent_data = self.connections_data[-1000:] if len(self.connections_data) > 1000 else self.connections_data
        
        for conn in reversed(recent_data):
            self.history_tree.insert('', 'end', values=(
                conn['timestamp'],
                conn['type'],
                conn['local_address'],
                conn['remote_address'],
                conn['status'],
                conn['process_name']
            ))
    
    def update_statistics(self):
        if not self.connections_data:
            return
        
        # Calculate statistics
        stats = {
            'total': len(self.connections_data),
            'processes': len(set(conn['process_name'] for conn in self.connections_data)),
            'types': defaultdict(int),
            'statuses': defaultdict(int),
            'top_processes': defaultdict(int),
            'top_remotes': defaultdict(int)
        }
        
        for conn in self.connections_data:
            stats['types'][conn['type']] += 1
            stats['statuses'][conn['status']] += 1
            stats['top_processes'][conn['process_name']] += 1
            if conn['remote_address']:
                stats['top_remotes'][conn['remote_address']] += 1
        
        # Update statistics text
        self.stats_text.delete(1.0, tk.END)
        
        text = f"""Network Connection Statistics
{'='*50}

Total Connections Recorded: {stats['total']}
Unique Processes: {stats['processes']}

Connection Types:
"""
        for conn_type, count in stats['types'].items():
            text += f"  {conn_type}: {count}\n"
        
        text += "\nConnection Statuses:\n"
        for status, count in stats['statuses'].items():
            text += f"  {status}: {count}\n"
        
        text += "\nTop 10 Processes:\n"
        top_processes = sorted(stats['top_processes'].items(), key=lambda x: x[1], reverse=True)[:10]
        for process, count in top_processes:
            text += f"  {process}: {count}\n"
        
        text += "\nTop 10 Remote Addresses:\n"
        top_remotes = sorted(stats['top_remotes'].items(), key=lambda x: x[1], reverse=True)[:10]
        for remote, count in top_remotes:
            text += f"  {remote}: {count}\n"
        
        self.stats_text.insert(1.0, text)
    
    def export_data(self):
        if not self.connections_data:
            messagebox.showwarning("No Data", "No connection data to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            if file_path.endswith('.json'):
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.connections_data, f, indent=2, ensure_ascii=False)
            else:
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    if self.connections_data:
                        writer = csv.DictWriter(f, fieldnames=self.connections_data[0].keys())
                        writer.writeheader()
                        writer.writerows(self.connections_data)
            
            messagebox.showinfo("Export Complete", f"Data exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export data: {e}")
    
    def clear_history(self):
        if messagebox.askyesno("Clear History", "Are you sure you want to clear all connection history?"):
            self.connections_data.clear()
            self.update_history()
            self.update_statistics()
            self.history_count_var.set("History: 0")

def main():
    root = tk.Tk()
    app = NetworkMonitorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()