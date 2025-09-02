#!/usr/bin/env python3
"""
Web Address Monitor GUI
A specialized GUI for monitoring web addresses and websites accessed from PC
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import psutil
import socket
import threading
import time
from datetime import datetime
from collections import defaultdict
import csv
import json

class WebMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🌐 Web Address Monitor")
        self.root.geometry("1200x800")
        
        self.monitoring = False
        self.monitor_thread = None
        self.web_connections = []
        self.domain_cache = {}
        
        # Web-specific settings
        self.web_ports = {80, 443, 8080, 8443, 3000, 5000, 8000, 9000}
        self.browsers = {
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe',
            'opera.exe', 'brave.exe', 'vivaldi.exe', 'safari.exe',
            'chromium.exe', 'edge.exe'
        }
        
        self.setup_ui()
        self.refresh_web_activity()
    
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="🌐 Web Address Monitor", font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 10))
        
        # Control panel
        self.setup_controls(main_frame)
        
        # Status panel
        self.setup_status(main_frame)
        
        # Main content with tabs
        self.setup_tabs(main_frame)
    
    def setup_controls(self, parent):
        control_frame = ttk.LabelFrame(parent, text="🎛️ Controls", padding="5")
        control_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Buttons
        self.start_btn = ttk.Button(control_frame, text="▶️ Start Monitoring", command=self.start_monitoring)
        self.start_btn.grid(row=0, column=0, padx=(0, 5))
        
        self.stop_btn = ttk.Button(control_frame, text="⏹️ Stop", command=self.stop_monitoring, state='disabled')
        self.stop_btn.grid(row=0, column=1, padx=(0, 5))
        
        self.refresh_btn = ttk.Button(control_frame, text="🔄 Refresh", command=self.refresh_web_activity)
        self.refresh_btn.grid(row=0, column=2, padx=(0, 5))
        
        self.export_btn = ttk.Button(control_frame, text="💾 Export", command=self.export_data)
        self.export_btn.grid(row=0, column=3, padx=(0, 5))
        
        self.clear_btn = ttk.Button(control_frame, text="🗑️ Clear", command=self.clear_history)
        self.clear_btn.grid(row=0, column=4, padx=(0, 5))
        
        # Settings
        ttk.Label(control_frame, text="⏱️ Interval (s):").grid(row=0, column=5, padx=(20, 5))
        self.interval_var = tk.StringVar(value="3")
        interval_spin = ttk.Spinbox(control_frame, from_=1, to=30, width=5, textvariable=self.interval_var)
        interval_spin.grid(row=0, column=6)
        
        # Filter
        ttk.Label(control_frame, text="🔍 Filter:").grid(row=0, column=7, padx=(20, 5))
        self.filter_var = tk.StringVar()
        filter_entry = ttk.Entry(control_frame, textvariable=self.filter_var, width=15)
        filter_entry.grid(row=0, column=8)
        filter_entry.bind('<KeyRelease>', self.apply_filter)
    
    def setup_status(self, parent):
        status_frame = ttk.LabelFrame(parent, text="📊 Status", padding="5")
        status_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.status_var = tk.StringVar(value="Ready to monitor web traffic")
        ttk.Label(status_frame, textvariable=self.status_var).grid(row=0, column=0, sticky=tk.W)
        
        self.active_count_var = tk.StringVar(value="Active: 0")
        ttk.Label(status_frame, textvariable=self.active_count_var).grid(row=0, column=1, padx=(20, 0))
        
        self.domains_count_var = tk.StringVar(value="Domains: 0")
        ttk.Label(status_frame, textvariable=self.domains_count_var).grid(row=0, column=2, padx=(20, 0))
        
        self.history_count_var = tk.StringVar(value="History: 0")
        ttk.Label(status_frame, textvariable=self.history_count_var).grid(row=0, column=3, padx=(20, 0))
    
    def setup_tabs(self, parent):
        notebook = ttk.Notebook(parent)
        notebook.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Active websites tab
        self.setup_active_tab(notebook)
        
        # Domain summary tab
        self.setup_domains_tab(notebook)
        
        # Categories tab
        self.setup_categories_tab(notebook)
        
        # Browser activity tab
        self.setup_browsers_tab(notebook)
        
        # History tab
        self.setup_history_tab(notebook)
    
    def setup_active_tab(self, notebook):
        active_frame = ttk.Frame(notebook, padding="5")
        notebook.add(active_frame, text="🌍 Active Websites")
        
        columns = ('Domain', 'Category', 'Protocol', 'Browser', 'Connections', 'IP Address')
        self.active_tree = ttk.Treeview(active_frame, columns=columns, show='headings', height=20)
        
        # Configure columns
        column_widths = {'Domain': 200, 'Category': 100, 'Protocol': 80, 'Browser': 120, 'Connections': 100, 'IP Address': 150}
        for col in columns:
            self.active_tree.heading(col, text=col)
            self.active_tree.column(col, width=column_widths.get(col, 100))
        
        # Scrollbars
        v_scroll = ttk.Scrollbar(active_frame, orient=tk.VERTICAL, command=self.active_tree.yview)
        h_scroll = ttk.Scrollbar(active_frame, orient=tk.HORIZONTAL, command=self.active_tree.xview)
        self.active_tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        self.active_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        v_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        h_scroll.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        active_frame.columnconfigure(0, weight=1)
        active_frame.rowconfigure(0, weight=1)
    
    def setup_domains_tab(self, notebook):
        domains_frame = ttk.Frame(notebook, padding="5")
        notebook.add(domains_frame, text="📂 Top Domains")
        
        columns = ('Rank', 'Domain', 'Category', 'Total Connections', 'Last Seen', 'Browsers')
        self.domains_tree = ttk.Treeview(domains_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.domains_tree.heading(col, text=col)
            self.domains_tree.column(col, width=120)
        
        d_scroll = ttk.Scrollbar(domains_frame, orient=tk.VERTICAL, command=self.domains_tree.yview)
        self.domains_tree.configure(yscrollcommand=d_scroll.set)
        
        self.domains_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        d_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        domains_frame.columnconfigure(0, weight=1)
        domains_frame.rowconfigure(0, weight=1)
    
    def setup_categories_tab(self, notebook):
        categories_frame = ttk.Frame(notebook, padding="5")
        notebook.add(categories_frame, text="📊 Categories")
        
        # Create a frame for category statistics
        stats_frame = ttk.Frame(categories_frame)
        stats_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        self.categories_text = tk.Text(stats_frame, wrap=tk.WORD, height=25, width=50)
        cat_scroll = ttk.Scrollbar(stats_frame, orient=tk.VERTICAL, command=self.categories_text.yview)
        self.categories_text.configure(yscrollcommand=cat_scroll.set)
        
        self.categories_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        cat_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Category details tree
        details_frame = ttk.Frame(categories_frame)
        details_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        columns = ('Website', 'Connections', 'Last Access')
        self.category_details_tree = ttk.Treeview(details_frame, columns=columns, show='headings', height=25)
        
        for col in columns:
            self.category_details_tree.heading(col, text=col)
            self.category_details_tree.column(col, width=150)
        
        detail_scroll = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=self.category_details_tree.yview)
        self.category_details_tree.configure(yscrollcommand=detail_scroll.set)
        
        self.category_details_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        detail_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        categories_frame.columnconfigure(0, weight=1)
        categories_frame.columnconfigure(1, weight=1)
        categories_frame.rowconfigure(0, weight=1)
        stats_frame.columnconfigure(0, weight=1)
        stats_frame.rowconfigure(0, weight=1)
        details_frame.columnconfigure(0, weight=1)
        details_frame.rowconfigure(0, weight=1)
    
    def setup_browsers_tab(self, notebook):
        browsers_frame = ttk.Frame(notebook, padding="5")
        notebook.add(browsers_frame, text="🌐 Browser Activity")
        
        columns = ('Browser', 'Active Connections', 'Total Websites', 'Top Domain', 'Data Usage')
        self.browsers_tree = ttk.Treeview(browsers_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.browsers_tree.heading(col, text=col)
            self.browsers_tree.column(col, width=120)
        
        b_scroll = ttk.Scrollbar(browsers_frame, orient=tk.VERTICAL, command=self.browsers_tree.yview)
        self.browsers_tree.configure(yscrollcommand=b_scroll.set)
        
        self.browsers_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        b_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        browsers_frame.columnconfigure(0, weight=1)
        browsers_frame.rowconfigure(0, weight=1)
    
    def setup_history_tab(self, notebook):
        history_frame = ttk.Frame(notebook, padding="5")
        notebook.add(history_frame, text="📜 Connection History")
        
        columns = ('Time', 'Domain', 'Protocol', 'Browser', 'Category', 'IP')
        self.history_tree = ttk.Treeview(history_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=120)
        
        h_scroll = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=h_scroll.set)
        
        self.history_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        h_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        history_frame.columnconfigure(0, weight=1)
        history_frame.rowconfigure(0, weight=1)
    
    # Core monitoring functions
    def resolve_ip_to_domain(self, ip_address: str) -> str:
        """Resolve IP to domain name"""
        if ip_address in self.domain_cache:
            return self.domain_cache[ip_address]
        
        try:
            domain = socket.gethostbyaddr(ip_address)[0]
            self.domain_cache[ip_address] = domain
            return domain
        except (socket.herror, socket.gaierror):
            self.domain_cache[ip_address] = ip_address
            return ip_address
    
    def categorize_website(self, domain: str) -> str:
        """Categorize website by domain"""
        domain_lower = domain.lower()
        
        categories = {
            '🔍 Search': ['google', 'bing', 'yahoo', 'duckduckgo', 'baidu'],
            '📱 Social Media': ['facebook', 'twitter', 'instagram', 'linkedin', 'tiktok', 'youtube', 'reddit'],
            '🛒 E-commerce': ['amazon', 'ebay', 'shopee', 'lazada', 'tiki'],
            '📰 News': ['bbc', 'cnn', 'vnexpress', 'tuoitre', 'thanhnien'],
            '💻 Technology': ['github', 'stackoverflow', 'microsoft', 'apple', 'developer'],
            '🎬 Entertainment': ['netflix', 'spotify', 'twitch', 'disney'],
            '☁️ Cloud/CDN': ['cloudflare', 'amazonaws', 'googleusercontent', 'fbcdn'],
            '🏦 Banking': ['vietcombank', 'techcombank', 'mbbank', 'agribank'],
            '🎮 Gaming': ['steam', 'epic', 'origin', 'uplay', 'battle.net']
        }
        
        for category, keywords in categories.items():
            if any(keyword in domain_lower for keyword in keywords):
                return category
        
        return '🌐 Other'
    
    def is_web_connection(self, conn) -> bool:
        """Check if connection is web-related"""
        if not conn.raddr:
            return False
        
        remote_port = conn.raddr.port
        if remote_port in self.web_ports:
            return True
        
        if conn.pid:
            try:
                process = psutil.Process(conn.pid)
                process_name = process.name().lower()
                return any(browser in process_name for browser in self.browsers)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return False
    
    def get_web_connections(self):
        """Get current web connections"""
        connections = []
        try:
            net_connections = psutil.net_connections(kind='inet')
            
            for conn in net_connections:
                if not self.is_web_connection(conn):
                    continue
                
                if conn.raddr:
                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port
                    domain = self.resolve_ip_to_domain(remote_ip)
                    protocol = 'HTTPS' if remote_port == 443 else 'HTTP' if remote_port == 80 else f'Port {remote_port}'
                    
                    process_name = 'System'
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            process_name = process.name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    
                    connection_info = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'domain': domain,
                        'ip_address': remote_ip,
                        'port': remote_port,
                        'protocol': protocol,
                        'process_name': process_name,
                        'category': self.categorize_website(domain),
                        'status': conn.status if hasattr(conn, 'status') else 'N/A'
                    }
                    
                    connections.append(connection_info)
        
        except Exception as e:
            self.status_var.set(f"❌ Error: {e}")
        
        return connections
    
    def refresh_web_activity(self):
        """Refresh all tabs with current data"""
        connections = self.get_web_connections()
        
        self.update_active_websites(connections)
        self.update_domains_summary()
        self.update_categories_view()
        self.update_browsers_view(connections)
        
        # Update status
        unique_domains = len(set(conn['domain'] for conn in connections))
        self.active_count_var.set(f"Active: {len(connections)}")
        self.domains_count_var.set(f"Domains: {unique_domains}")
        self.history_count_var.set(f"History: {len(self.web_connections)}")
        
        if not self.monitoring:
            self.status_var.set("Ready to monitor web traffic")
    
    def update_active_websites(self, connections):
        """Update active websites tab"""
        # Clear tree
        for item in self.active_tree.get_children():
            self.active_tree.delete(item)
        
        # Group by domain
        by_domain = defaultdict(list)
        for conn in connections:
            by_domain[conn['domain']].append(conn)
        
        # Add to tree
        for domain, conns in sorted(by_domain.items(), key=lambda x: len(x[1]), reverse=True):
            browsers = set(conn['process_name'] for conn in conns)
            protocols = set(conn['protocol'] for conn in conns)
            ips = set(conn['ip_address'] for conn in conns)
            category = conns[0]['category']
            
            self.active_tree.insert('', 'end', values=(
                domain,
                category,
                ', '.join(protocols),
                ', '.join(browsers),
                len(conns),
                ', '.join(ips)
            ))
    
    def update_domains_summary(self):
        """Update domains summary tab"""
        # Clear tree
        for item in self.domains_tree.get_children():
            self.domains_tree.delete(item)
        
        if not self.web_connections:
            return
        
        # Analyze all historical data
        domain_stats = defaultdict(lambda: {'count': 0, 'browsers': set(), 'last_seen': '', 'category': ''})
        
        for conn in self.web_connections:
            domain = conn['domain']
            domain_stats[domain]['count'] += 1
            domain_stats[domain]['browsers'].add(conn['process_name'])
            domain_stats[domain]['last_seen'] = conn['timestamp']
            domain_stats[domain]['category'] = conn['category']
        
        # Sort by count and add to tree
        sorted_domains = sorted(domain_stats.items(), key=lambda x: x[1]['count'], reverse=True)
        
        for rank, (domain, stats) in enumerate(sorted_domains[:50], 1):
            self.domains_tree.insert('', 'end', values=(
                rank,
                domain,
                stats['category'],
                stats['count'],
                stats['last_seen'].split()[1] if ' ' in stats['last_seen'] else stats['last_seen'],
                ', '.join(stats['browsers'])
            ))
    
    def update_categories_view(self):
        """Update categories view"""
        if not self.web_connections:
            self.categories_text.delete(1.0, tk.END)
            self.categories_text.insert(1.0, "No data available. Start monitoring to see website categories.")
            return
        
        # Calculate category statistics
        category_stats = defaultdict(lambda: {'count': 0, 'domains': set()})
        
        for conn in self.web_connections:
            category = conn['category']
            category_stats[category]['count'] += 1
            category_stats[category]['domains'].add(conn['domain'])
        
        # Update text display
        self.categories_text.delete(1.0, tk.END)
        
        text = "📊 Website Categories Analysis\n"
        text += "=" * 40 + "\n\n"
        
        total_connections = len(self.web_connections)
        sorted_categories = sorted(category_stats.items(), key=lambda x: x[1]['count'], reverse=True)
        
        for category, stats in sorted_categories:
            percentage = (stats['count'] / total_connections) * 100
            text += f"{category}\n"
            text += f"  Connections: {stats['count']} ({percentage:.1f}%)\n"
            text += f"  Unique domains: {len(stats['domains'])}\n"
            text += f"  Top domains: {', '.join(list(stats['domains'])[:3])}\n\n"
        
        self.categories_text.insert(1.0, text)
    
    def update_browsers_view(self, connections):
        """Update browsers view"""
        # Clear tree
        for item in self.browsers_tree.get_children():
            self.browsers_tree.delete(item)
        
        # Analyze browser activity
        browser_stats = defaultdict(lambda: {'active': 0, 'domains': set(), 'total_history': 0})
        
        # Current connections
        for conn in connections:
            browser = conn['process_name']
            browser_stats[browser]['active'] += 1
            browser_stats[browser]['domains'].add(conn['domain'])
        
        # Historical data
        for conn in self.web_connections:
            browser = conn['process_name']
            browser_stats[browser]['total_history'] += 1
            browser_stats[browser]['domains'].add(conn['domain'])
        
        # Add to tree
        for browser, stats in sorted(browser_stats.items(), key=lambda x: x[1]['active'], reverse=True):
            top_domain = "N/A"
            if stats['domains']:
                # Find most common domain for this browser
                browser_domains = defaultdict(int)
                for conn in self.web_connections:
                    if conn['process_name'] == browser:
                        browser_domains[conn['domain']] += 1
                if browser_domains:
                    top_domain = max(browser_domains.items(), key=lambda x: x[1])[0]
            
            self.browsers_tree.insert('', 'end', values=(
                browser,
                stats['active'],
                len(stats['domains']),
                top_domain,
                f"{stats['total_history']} connections"
            ))
    
    def start_monitoring(self):
        """Start monitoring web traffic"""
        if self.monitoring:
            return
        
        self.monitoring = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_var.set("🔄 Monitoring web traffic...")
        
        interval = int(self.interval_var.get())
        self.monitor_thread = threading.Thread(target=self.monitor_loop, args=(interval,), daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.monitoring = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_var.set("⏹️ Monitoring stopped")
    
    def monitor_loop(self, interval):
        """Background monitoring loop"""
        while self.monitoring:
            connections = self.get_web_connections()
            self.web_connections.extend(connections)
            
            # Update GUI in main thread
            self.root.after(0, self.refresh_web_activity)
            self.root.after(0, self.update_history)
            
            time.sleep(interval)
    
    def update_history(self):
        """Update history tab"""
        # Clear history tree
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # Show recent entries (last 500)
        recent_data = self.web_connections[-500:] if len(self.web_connections) > 500 else self.web_connections
        
        for conn in reversed(recent_data):
            self.history_tree.insert('', 'end', values=(
                conn['timestamp'].split()[1] if ' ' in conn['timestamp'] else conn['timestamp'],
                conn['domain'],
                conn['protocol'],
                conn['process_name'],
                conn['category'],
                conn['ip_address']
            ))
    
    def apply_filter(self, event=None):
        """Apply filter to active websites"""
        filter_text = self.filter_var.get().lower()
        if not filter_text:
            self.refresh_web_activity()
            return
        
        # Filter active connections
        connections = self.get_web_connections()
        filtered = [conn for conn in connections if 
                   filter_text in conn['domain'].lower() or 
                   filter_text in conn['category'].lower() or
                   filter_text in conn['process_name'].lower()]
        
        self.update_active_websites(filtered)
    
    def export_data(self):
        """Export web data"""
        if not self.web_connections:
            messagebox.showwarning("No Data", "No web traffic data to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json")]
        )
        
        if not file_path:
            return
        
        try:
            if file_path.endswith('.json'):
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.web_connections, f, indent=2, ensure_ascii=False)
            else:
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    if self.web_connections:
                        writer = csv.DictWriter(f, fieldnames=self.web_connections[0].keys())
                        writer.writeheader()
                        writer.writerows(self.web_connections)
            
            messagebox.showinfo("Export Complete", f"Web data exported to {file_path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {e}")
    
    def clear_history(self):
        """Clear connection history"""
        if messagebox.askyesno("Clear History", "Clear all web traffic history?"):
            self.web_connections.clear()
            self.refresh_web_activity()
            self.update_history()

def main():
    root = tk.Tk()
    app = WebMonitorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()