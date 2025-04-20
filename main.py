import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scapy.all import sniff, IP, TCP, UDP
from scapy.config import conf
from collections import defaultdict, deque
import threading
import subprocess
import time
import ipaddress
import csv
from datetime import datetime
import re
import pystray
from pystray import MenuItem as item
from PIL import Image, ImageDraw, ImageTk
from plyer import notification
import sys
import os
import requests

# === CONFIG ===
THRESHOLD = 5000
MONITOR_SECONDS = 5
MAX_HISTORY = 60  # seconds of graph data
BLOCKED_IPS = set()
WHITELIST = {"192.168.1.1"}
alert_enabled = True

def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org", timeout=5)
        if response.status_code == 200:
            public_ip = response.text.strip()
            WHITELIST.add(public_ip)
            print(f"[INFO] Detected public IP: {public_ip} added to WHITELIST.")
        else:
            print("[Warning] Could not retrieve public IP. Continuing with static whitelist.")
    except Exception as e:
        print(f"[Warning] Could not retrieve public IP. Continuing with static whitelist.\n{e}")

my_public_ip = get_public_ip()

# === Data Stores ===
ip_traffic = defaultdict(lambda: {"count": 0, "ports": set()})
traffic_lock = threading.Lock()
history = deque(maxlen=MAX_HISTORY)

# Tray icon status
current_status = "safe"
tray_icon = None


def get_resource_path(relative_path):
    try:
        # PyInstaller bundles files in a temporary folder
        base_path = sys._MEIPASS
    except Exception:
        # If not bundled (i.e., running as a script), use the current working directory
        base_path = os.path.dirname(os.path.abspath(__file__))

    return os.path.join(base_path, relative_path)

# === Splash Screen ===
def show_splash():
    splash = tk.Toplevel()
    splash.overrideredirect(True)
    splash.geometry("600x400+500+200")  # Adjust to center on screen

    img_path = get_resource_path("splash.png")  # Get correct path for bundled file
    img = Image.open(img_path)  # Use the image from the path
    img = img.resize((600, 400), Image.Resampling.LANCZOS)  # Resize image to fit the window
    bg = ImageTk.PhotoImage(img)

    canvas = tk.Canvas(splash, width=600, height=400)
    canvas.pack()
    canvas.create_image(0, 0, anchor="nw", image=bg)

    splash.update()
    time.sleep(2.5)  # Show splash for 2.5 seconds
    splash.destroy()


# === Utility ===
def is_local_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback
    except ValueError:
        return True


def block_ip(ip):
    if ip not in BLOCKED_IPS:
        subprocess.run(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}',
                       shell=True)
        BLOCKED_IPS.add(ip)


def unblock_ip(ip):
    subprocess.run(f'netsh advfirewall firewall delete rule name="Block {ip}"', shell=True)
    BLOCKED_IPS.discard(ip)


def export_to_csv():
    filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if filename:
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["IP", "Ports", "Packets", "Status"])
            with traffic_lock:
                for ip, data in ip_traffic.items():
                    ports = ', '.join(str(p) for p in data["ports"])
                    count = data["count"]
                    status = get_status(count)
                    writer.writerow([ip, ports, count, status])
        messagebox.showinfo("Export Complete", f"Traffic data exported to {filename}")


def get_status(count):
    if count >= THRESHOLD:
        return "⚠️ DDoS Suspected"
    elif count >= (THRESHOLD // 2):
        return "Monitor"
    return "Normal"

def get_icon_path():
    # Check if we're running in a bundled PyInstaller executable
    if hasattr(sys, '_MEIPASS'):
        # This path is where PyInstaller unpacks the files to at runtime
        return os.path.join(sys._MEIPASS, "icon.ico")  # Modify with your icon's actual name
    else:
        # If we're running the script directly, use the icon in the current directory
        return "icon.ico"  # Modify this if your icon is in a subfolder, e.g., "assets/icon.png"



# === GUI ===
root = tk.Tk()
root.title("🛡️ Mursy Anti-DDoS Dashboard")
root.geometry("1000x600")

icon_path = get_icon_path()  # Get the correct path for the icon
root.iconbitmap(icon_path)  # Set the window's icon

# Top Controls
control_frame = tk.Frame(root)
control_frame.pack(fill="x")

filter_var = tk.StringVar()
filter_entry = tk.Entry(control_frame, textvariable=filter_var)
filter_entry.pack(side="left", padx=5, pady=5)
filter_entry.insert(0, "Filter by IP or Port")

alert_toggle = tk.IntVar(value=1)
toggle_btn = tk.Checkbutton(control_frame, text="Enable Alerts", variable=alert_toggle)
toggle_btn.pack(side="left", padx=10)

export_btn = tk.Button(control_frame, text="Export to CSV", command=export_to_csv)
export_btn.pack(side="left", padx=5)

# Table
columns = ("IP", "Ports", "Packets", "Status", "Action")
tree = ttk.Treeview(root, columns=columns, show="headings", height=20)
for col in columns:
    tree.heading(col, text=col, command=lambda _col=col: sort_by_column(_col, False))
    tree.column(col, width=180 if col != "Ports" else 200)
tree.pack(expand=True, fill="both")


def sort_by_column(col, reverse):
    l = [(tree.set(k, col), k) for k in tree.get_children('')]
    if col == "Packets":
        l.sort(key=lambda t: int(t[0]), reverse=reverse)
    else:
        l.sort(reverse=reverse)
    for index, (val, k) in enumerate(l):
        tree.move(k, '', index)
    tree.heading(col, command=lambda: sort_by_column(col, not reverse))


# === Blocked IP Tab ===
def view_blocked_ips():
    blocked_window = tk.Toplevel(root)
    blocked_window.title("Blocked IPs")
    blocked_window.geometry("400x300")

    blocked_listbox = tk.Listbox(blocked_window, height=10, width=50)
    blocked_listbox.pack(padx=10, pady=10)

    for ip in BLOCKED_IPS:
        blocked_listbox.insert(tk.END, ip)

    def unblock_selected_ip():
        selected_ip = blocked_listbox.get(tk.ACTIVE)
        if selected_ip:
            unblock_ip(selected_ip)
            blocked_listbox.delete(tk.ACTIVE)
            messagebox.showinfo("Unblocked", f"IP {selected_ip} has been unblocked.")

    unblock_btn = tk.Button(blocked_window, text="Unblock IP", command=unblock_selected_ip)
    unblock_btn.pack(pady=10)


# Add "Blocked IPs" tab in the toolbar
toolbar = tk.Frame(root)
toolbar.pack(side="top", fill="x")

blocked_ips_button = tk.Button(toolbar, text="View Blocked IPs", command=view_blocked_ips)
blocked_ips_button.pack(side="left", padx=5, pady=5)


# === GUI Update ===
def update_gui():
    with traffic_lock:
        tree.delete(*tree.get_children())
        query = filter_var.get().strip()

        if query and re.match(r'^[0-9\.]+$', query):
            for ip, data in ip_traffic.items():
                count = data["count"]
                ports = ', '.join(str(p) for p in data["ports"])
                status = get_status(count)
                if query not in ip and query not in ports:
                    continue
                action_text = "Unblock" if ip in BLOCKED_IPS else "Block"
                tree.insert("", "end", values=(ip, ports, count, status, action_text), tags=(ip,))
        else:
            for ip, data in ip_traffic.items():
                count = data["count"]
                ports = ', '.join(str(p) for p in sorted(data["ports"]))
                status = get_status(count)
                action_text = "Unblock" if ip in BLOCKED_IPS else "Block"
                tree.insert("", "end", values=(ip, ports, count, status, action_text), tags=(ip,))

    root.after(1000, update_gui)


def on_tree_click(event):
    item = tree.identify_row(event.y)
    if item:
        ip = tree.item(item, 'values')[0]
        if ip in BLOCKED_IPS:
            unblock_ip(ip)
        else:
            block_ip(ip)


tree.bind("<Button-1>", on_tree_click)


# === Packet Handling ===
def count_packet(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        if src_ip not in WHITELIST and src_ip not in BLOCKED_IPS and not is_local_ip(src_ip):
            with traffic_lock:
                ip_traffic[src_ip]["count"] += 1
                if TCP in pkt:
                    ip_traffic[src_ip]["ports"].add(pkt[TCP].dport)
                elif UDP in pkt:
                    ip_traffic[src_ip]["ports"].add(pkt[UDP].dport)


# === Packet Sniffing ===
def packet_sniffer():
    interface = conf.iface
    while True:
        sniff(iface=interface, filter="ip", prn=count_packet, timeout=MONITOR_SECONDS, store=0)


# === Tray Icon Logic ===
def create_icon(color):
    image = Image.new("RGB", (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse([16, 16, 48, 48], fill=color)
    return image


def on_quit(icon, item):
    shutdown_event.set()
    icon.stop()
    root.quit()


def on_open(icon, item):
    root.deiconify()
    icon.stop()


def ddos_watchdog():
    global current_status, tray_icon
    while True:
        time.sleep(2)
        with traffic_lock:
            suspects = [ip for ip, data in ip_traffic.items() if get_status(data["count"]) == "⚠️ DDoS Suspected"]
        if suspects:
            if current_status != "alert":
                current_status = "alert"
                tray_icon.icon = create_icon("red")
                tray_icon.update_menu()
                try:
                    notification.notify(
                        title="DDoS Suspect Detected",
                        message=f"Suspect IPs: {', '.join(suspects[:3])}" + ("..." if len(suspects) > 3 else ""),
                        app_name="Mursy Anti-DDoS",
                        timeout=5
                    )

                except:
                    pass
        else:
            if current_status != "safe":
                current_status = "safe"
                tray_icon.icon = create_icon("green")
                tray_icon.update_menu()


def minimize_to_tray():
    global tray_icon
    root.withdraw()
    tray_icon = pystray.Icon("DDoS Protect", create_icon("green"), menu=pystray.Menu(
        item('Open', on_open),
        item('Quit', on_quit)
    ))
    threading.Thread(target=ddos_watchdog, daemon=True).start()
    tray_icon.run_detached()


# === Traffic Reset ===
def reset_traffic_loop():
    while True:
        time.sleep(MONITOR_SECONDS)
        with traffic_lock:
            preserved = {
                ip: data for ip, data in ip_traffic.items()
                if data["count"] >= THRESHOLD
            }
            ip_traffic.clear()
            ip_traffic.update(preserved)


# Show the main window after the splash screen closes
def show_main_window():
    root.deiconify()  # Show the main window
    threading.Thread(target=packet_sniffer, daemon=True).start()
    threading.Thread(target=reset_traffic_loop, daemon=True).start()
    update_gui()
    root.mainloop()


shutdown_event = threading.Event()



# === Launch ===
root.withdraw()
root.after(100, show_splash)
root.after(2500, show_main_window)

threading.Thread(target=packet_sniffer, daemon=True).start()
threading.Thread(target=reset_traffic_loop, daemon=True).start()
root.protocol("WM_DELETE_WINDOW", minimize_to_tray)
update_gui()
root.mainloop()
