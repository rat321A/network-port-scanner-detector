import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


# ---- detection settings ----

THRESHOLD = 10      # 10 or more unique ports in one window is flagged as suspicious
WINDOW_SIZE = 300   # 300 seconds = 5 minutes


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


def plot_results(df, threshold, save_path="scan_chart.png"):
    """Draw a bar chart of unique ports per group, save it, and show it."""
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
    plt.tight_layout()

    plt.savefig(save_path)  # save before show(), otherwise the image can be blank
    plt.show()


def main():
    port_groups = group_ports(connections, WINDOW_SIZE)
    df = detect_suspicious(port_groups, THRESHOLD)
    print_report(df, len(connections))
    plot_results(df, THRESHOLD)


if __name__ == "__main__":
    main()