import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import ttkbootstrap as ttkb
from ttkbootstrap.constants import *
from ttkbootstrap.tooltip import ToolTip
import logging
import threading
import json
import os
import webbrowser
from typing import Set, Tuple, List, Dict, Any
from PIL import Image, ImageTk
from .main import netsentry, load_config
from .storage import generate_report

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("data/logs/netsentry.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class NetSentryGUI:
    """Advanced GUI for NetSentry with dark mode and red team aesthetic."""
    def __init__(self, root: ttkb.Window):
        self.root = root
        self.root.title("NetSentry - Red Team Network Scanner")
        self.root.geometry("1000x700")
        self.config = load_config()
        self.setup_gui()
        self.scan_thread = None
        
    def setup_gui(self):
        """Set up GUI components with tabbed interface."""
        self.style = ttkb.Style(theme="cyborg")
        self.style.configure("TButton", font=("Consolas", 10))
        self.style.configure("TLabel", font=("Consolas", 10))
        
        # Notebook for tabs
        self.notebook = ttkb.Notebook(self.root)
        self.notebook.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Scan tab
        self.scan_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scan_tab, text="Scan")
        self.setup_scan_tab()
        
        # Results tab
        self.results_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.results_tab, text="Results")
        self.setup_results_tab()
        
        # Report tab
        self.report_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.report_tab, text="Report")
        self.setup_report_tab()
        
    def setup_scan_tab(self):
        """Configure scan tab with inputs and controls."""
        input_frame = ttkb.LabelFrame(self.scan_tab, text="Scan Configuration", bootstyle="danger")
        input_frame.pack(padx=10, pady=10, fill="x")
        
        # Interface input
        ttkb.Label(input_frame, text="Interface:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.interface_entry = ttkb.Entry(input_frame)
        self.interface_entry.insert(0, self.config["interface"])
        self.interface_entry.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        ToolTip(self.interface_entry, text="Wi-Fi interface (e.g., wlan0)")
        
        # Network range input
        ttkb.Label(input_frame, text="Network Range:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.network_entry = ttkb.Entry(input_frame)
        self.network_entry.insert(0, self.config["network_range"])
        self.network_entry.grid(row=1, column=1, padx=5, pady=5, sticky="w")
        ToolTip(self.network_entry, text="CIDR range (e.g., 192.168.1.0/24)")
        
        # Scan controls
        self.scan_button = ttkb.Button(
            input_frame, text="Start Scan", bootstyle="danger", command=self.start_scan
        )
        self.scan_button.grid(row=2, column=0, padx=5, pady=10)
        ToolTip(self.scan_button, text="Initiate network scan")
        
        self.stop_button = ttkb.Button(
            input_frame, text="Stop Scan", bootstyle="secondary", command=self.stop_scan, state="disabled"
        )
        self.stop_button.grid(row=2, column=1, padx=5, pady=10)
        ToolTip(self.stop_button, text="Stop ongoing scan")
        
        # Progress bar
        self.progress = ttkb.Progressbar(self.scan_tab, mode="indeterminate", bootstyle="danger")
        self.progress.pack(padx=10, pady=5, fill="x")
        
        # Console output
        self.console = scrolledtext.ScrolledText(self.scan_tab, height=10, font=("Consolas", 9))
        self.console.pack(padx=10, pady=10, fill="both", expand=True)
        self.console.insert(tk.END, "Ready to scan...\n")
        self.console.config(state="disabled")
        
    def setup_results_tab(self):
        """Configure results tab with treeview and image."""
        # Treeview for results
        self.results_tree = ttkb.Treeview(
            self.results_tab, columns=("Type", "Details"), show="headings", bootstyle="danger"
        )
        self.results_tree.heading("Type", text="Type")
        self.results_tree.heading("Details", text="Details")
        self.results_tree.pack(padx=10, pady=10, fill="both", expand=True)
        self.results_tree.bind("<Double-1>", self.show_details)
        
        # Image display
        self.image_frame = ttkb.Frame(self.results_tab)
        self.image_frame.pack(padx=10, pady=10, fill="x")
        self.image_label = ttkb.Label(self.image_frame)
        self.image_label.pack()
        
        # Open image button
        ttkb.Button(
            self.image_frame, text="Open Full Tree", bootstyle="danger-outline",
            command=lambda: webbrowser.open(os.path.abspath(self.config["output_tree"]))
        ).pack(pady=5)
        
    def setup_report_tab(self):
        """Configure report tab with report viewer and controls."""
        report_frame = ttkb.LabelFrame(self.report_tab, text="Pentest Report", bootstyle="danger")
        report_frame.pack(padx=10, pady=10, fill="both", expand=True)
        
        self.report_text = scrolledtext.ScrolledText(report_frame, height=20, font=("Consolas", 9))
        self.report_text.pack(padx=5, pady=5, fill="both", expand=True)
        
        button_frame = ttkb.Frame(report_frame)
        button_frame.pack(pady=5)
        
        ttkb.Button(
            button_frame, text="Generate Report", bootstyle="danger",
            command=self.generate_report
        ).pack(side="left", padx=5)
        ToolTip(button_frame.winfo_children()[0], text="Generate Markdown report")
        
        ttkb.Button(
            button_frame, text="Open Report", bootstyle="danger-outline",
            command=lambda: webbrowser.open(os.path.abspath("output/report.md"))
        ).pack(side="left", padx=5)
        ToolTip(button_frame.winfo_children()[1], text="Open report in default viewer")
        
    def log_to_console(self, message: str):
        """Log message to console widget."""
        self.console.config(state="normal")
        self.console.insert(tk.END, f"{message}\n")
        self.console.see(tk.END)
        self.console.config(state="disabled")
        
    def start_scan(self):
        """Start scanning in a separate thread."""
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showwarning("Warning", "Scan already in progress!")
            return
        
        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.progress.start()
        self.log_to_console("Starting scan...")
        
        self.scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        self.scan_thread.start()
        
    def stop_scan(self):
        """Stop ongoing scan (placeholder for future interrupt)."""
        self.log_to_console("Stop functionality not implemented yet.")
        self.scan_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.progress.stop()
        
    def run_scan(self):
        """Run NetSentry scan and update GUI."""
        try:
            config = {
                "interface": self.interface_entry.get(),
                "network_range": self.network_entry.get(),
                "output_json": self.config["output_json"],
                "output_tree": self.config["output_tree"]
            }
            networks, devices, streams = netsentry(config)
            
            # Clear tree
            for item in self.results_tree.get_children():
                self.results_tree.delete(item)
            
            # Populate results
            net_parent = self.results_tree.insert("", "end", text="Networks", values=("Networks", f"{len(networks)} found"))
            for ssid, bssid in networks:
                self.results_tree.insert(net_parent, "end", values=("Network", f"SSID: {ssid}, BSSID: {bssid}"))
            
            dev_parent = self.results_tree.insert("", "end", text="Devices", values=("Devices", f"{len(devices)} found"))
            for device in devices:
                details = f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}"
                self.results_tree.insert(dev_parent, "end", values=("Device", details))
            
            stream_parent = self.results_tree.insert("", "end", text="Streams", values=("Streams", f"{len(streams)} found"))
            for stream in streams:
                details = f"Protocol: {stream['protocol']}, Src: {stream['src_ip']}, Dst: {stream['dst_ip']}"
                self.results_tree.insert(stream_parent, "end", values=("Stream", details))
            
            # Display tree image
            if os.path.exists(self.config["output_tree"]):
                img = Image.open(self.config["output_tree"])
                img = img.resize((400, 300), Image.Resampling.LANCZOS)
                self.photo = ImageTk.PhotoImage(img)
                self.image_label.config(image=self.photo)
            
            self.log_to_console(f"Scan complete: {len(networks)} networks, {len(devices)} devices, {len(streams)} streams")
            messagebox.showinfo("Success", f"Scan complete: {len(networks)} networks, {len(devices)} devices, {len(streams)} streams")
            
        except Exception as e:
            logger.error(f"Scan failed: {str(e)}")
            self.log_to_console(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Scan failed: {str(e)}")
        
        finally:
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")
            self.progress.stop()
            
    def show_details(self, event):
        """Show detailed information for selected tree item."""
        item = self.results_tree.selection()
        if item:
            values = self.results_tree.item(item, "values")
            messagebox.showinfo("Details", f"Type: {values[0]}\nDetails: {values[1]}")
            
    def generate_report(self):
        """Generate and display pentest report."""
        try:
            with open(self.config["output_json"], "r") as f:
                results = json.load(f)
            networks = set(tuple(n) for n in results["networks"])
            devices = results["devices"]
            streams = results["streams"]
            
            generate_report(networks, devices, streams)
            with open("output/report.md", "r") as f:
                self.report_text.delete(1.0, tk.END)
                self.report_text.insert(tk.END, f.read())
            self.log_to_console("Report generated successfully")
            
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            self.log_to_console(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Report generation failed: {str(e)}")

def run_gui():
    """Launch the GUI."""
    root = ttkb.Window()
    app = NetSentryGUI(root)
    root.mainloop()

if __name__ == "__main__":
    run_gui()