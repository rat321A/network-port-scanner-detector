
import os

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


# ---- detection settings ----

THRESHOLD = 10      # 10 or more unique ports in one window is flagged as suspicious
WINDOW_SIZE = 300   # 300 seconds = 5 minutes
IMAGE_DIR = "images"
SHOW_PLOTS = True   # set to False to only save the images


# ---- network connection data ----

connections = [
    # computer a
    {"source_ip": "192.168.1.5", "dest_port": 80, "second": 100},   # port 80: http (web traffic)
    {"source_ip": "192.168.1.5", "dest_port": 443, "second": 120},  # port 443: https (secure web traffic)
    {"source_ip": "192.168.1.5", "dest_port": 22, "second": 150},   # port 22: ssh

    # computer b
    {"source_ip": "10.0.0.99", "dest_port": 21, "second": 110},
    {"source_ip": "10.0.0.99", "dest_port": 22, "second": 115},

    # computer c - simulated port scan
    {"source_ip": "10.0.0.50", "dest_port": 20, "second": 200},
    {"source_ip": "10.0.0.50", "dest_port": 21, "second": 205},
    {"source_ip": "10.0.0.50", "dest_port": 22, "second": 210},
    {"source_ip": "10.0.0.50", "dest_port": 23, "second": 215},
    {"source_ip": "10.0.0.50", "dest_port": 25, "second": 220},
    {"source_ip": "10.0.0.50", "dest_port": 53, "second": 225},
    {"source_ip": "10.0.0.50", "dest_port": 80, "second": 230},
    {"source_ip": "10.0.0.50", "dest_port": 110, "second": 235},
    {"source_ip": "10.0.0.50", "dest_port": 143, "second": 240},
    {"source_ip": "10.0.0.50", "dest_port": 443, "second": 245},
]


def group_ports(connections, window_size):
    """Collect the unique destination ports for each (ip, time window) pair."""
    port_groups = {}

    for connection in connections:
        ip = connection["source_ip"]
        port = connection["dest_port"]
        window = connection["second"] // window_size
        group = (ip, window)

        if group not in port_groups:
            port_groups[group] = set()

        port_groups[group].add(port)  # a set removes duplicate ports

    return port_groups


def detect_suspicious(port_groups, threshold):
    """Label each group as suspicious or normal and return a DataFrame."""
    results = []

    for (ip, window), unique_ports in port_groups.items():
        total_ports = len(unique_ports)
        status = "suspicious" if total_ports >= threshold else "normal"

        results.append({
            "source_ip": ip,
            "window": window,
            "unique_port_count": total_ports,
            "status": status,
        })

    return pd.DataFrame(results)


def print_report(df, total_connections):
    """Print the full report, security alerts and statistics."""
    print("\n===== network port scan report =====")
    print(df.to_string(index=False))

    alerts = df[df["status"] == "suspicious"]

    print("\n===== security alerts =====")
    if alerts.empty:
        print("no suspicious activity detected.")
    else:
        for _, alert in alerts.iterrows():
            print(
                "suspicious activity detected from ip:", alert["source_ip"],
                "| unique ports:", alert["unique_port_count"],
                "| time window:", alert["window"],
            )

    port_counts = df["unique_port_count"].to_numpy()

    print("\n===== network statistics =====")
    print("total connection records:", total_connections)
    print("total ip and time-window groups:", len(df))
    print("average unique ports:", round(np.mean(port_counts), 2))
    print("maximum unique ports:", np.max(port_counts))


def finish_plot(filename):
    """Tidy the layout, save the figure into the images folder, then show or close it."""
    os.makedirs(IMAGE_DIR, exist_ok=True)

    plt.tight_layout()
    plt.savefig(os.path.join(IMAGE_DIR, filename), dpi=150)  # save before show()

    if SHOW_PLOTS:
        plt.show()
    plt.close()


def plot_results(df, threshold):
    """Bar chart of unique ports per (ip, window) group with the threshold line."""
    labels = df["source_ip"] + "\nwindow " + df["window"].astype(str)

    bar_colors = [
        "tomato" if status == "suspicious" else "steelblue"
        for status in df["status"]
    ]

    plt.figure(figsize=(10, 6))
    plt.bar(labels, df["unique_port_count"], color=bar_colors)

    plt.axhline(
        y=threshold,
        linestyle="--",
        color="black",
        label=f"detection threshold ({threshold})",
    )

    plt.title("network port scan detection")
    plt.xlabel("source ip and time window")
    plt.ylabel("total unique destination ports")
    plt.legend()

    finish_plot("scan_chart.png")


def plot_timeline(connections, window_size):
    """Scatter plot of destination port over time, one color per source ip."""
    df = pd.DataFrame(connections)

    plt.figure(figsize=(10, 6))

    for ip, group in df.groupby("source_ip"):
        plt.scatter(group["second"], group["dest_port"], label=ip, s=60)

    # dotted vertical lines mark where each time window starts
    for boundary in range(0, int(df["second"].max()) + window_size, window_size):
        plt.axvline(boundary, linestyle=":", color="gray")

    plt.title("connection timeline by source ip")
    plt.xlabel("time (seconds)")
    plt.ylabel("destination port")
    plt.legend(title="source ip")

    finish_plot("port_timeline.png")


def plot_connections_per_ip(connections):
    """Bar chart of how many connections each source ip made in total."""
    df = pd.DataFrame(connections)
    counts = df["source_ip"].value_counts()

    plt.figure(figsize=(8, 5))
    plt.bar(counts.index, counts.values, color="steelblue")

    plt.title("total connections per source ip")
    plt.xlabel("source ip")
    plt.ylabel("number of connections")

    finish_plot("connections_per_ip.png")


def main():
    port_groups = group_ports(connections, WINDOW_SIZE)
    df = detect_suspicious(port_groups, THRESHOLD)
    print_report(df, len(connections))

    plot_results(df, THRESHOLD)
    plot_timeline(connections, WINDOW_SIZE)
    plot_connections_per_ip(connections)


if __name__ == "__main__":
    main()