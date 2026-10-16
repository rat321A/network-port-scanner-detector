
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


# ---- network connection data ----

connections = [
    # computer a
    {"source_ip": "192.168.1.5", "dest_port": 80, "second": 100},  # port 80 is for http i.e web traffic
    {"source_ip": "192.168.1.5", "dest_port": 443, "second": 120},  # port 443 is for https i.e secure web traffic
    {"source_ip": "192.168.1.5", "dest_port": 22, "second": 150},  # port 22 is for ssh traffic

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
    {"source_ip": "10.0.0.50", "dest_port": 443, "second": 245}
]


# ---- detection limit / time window ----

threshold = 10  # limitation of 10 unique ports after that flagged as suspicious
window_size = 300  # 300 seconds means 5 minutes


# ---- grouping ports by ip address and time window ----

port_groups = {}

for connection in connections:
    ip = connection["source_ip"]
    port = connection["dest_port"]
    second = connection["second"]

    # ---- finding the 5-minute time window ----
    window = second // window_size
    group = (ip, window)

    if group not in port_groups:
        port_groups[group] = set()

    # ---- removing duplicate ports ----
    port_groups[group].add(port)


# ---- detecting suspicious activity ----

results = []

for group, unique_ports in port_groups.items():
    ip, window = group
    total_ports = len(unique_ports)

    if total_ports >= threshold:
        status = "suspicious"
    else:
        status = "normal"

    results.append({
        "source_ip": ip,
        "window": window,
        "unique_port_count": total_ports,
        "status": status
    })


# ---- displaying the results using pandas ----

df = pd.DataFrame(results)

print("\n===== network port scan report =====")
print(df.to_string(index=False))


# ---- showing security alerts ----

alerts = df[df["status"] == "suspicious"]

print("\n===== security alerts =====")

if alerts.empty:
    print("no suspicious activity detected.")
else:
    for _, alert in alerts.iterrows():
        print(
            "suspicious activity detected from ip:",
            alert["source_ip"],
            "| unique ports:",
            alert["unique_port_count"],
            "| time window:",
            alert["window"]
        )


# ---- numpy statistics ----

port_counts = df["unique_port_count"].to_numpy()

print("\n===== network statistics =====")
print("total connection records:", len(connections))
print("total ip and time-window groups:", len(df))
print("average unique ports:", round(np.mean(port_counts), 2))
print("maximum unique ports:", np.max(port_counts))


# ---- graph: port scan detection ----

labels = (
    df["source_ip"]
    + "\nwindow "
    + df["window"].astype(str)
)

# ---- setting graph colors based on activity ----
bar_colors = [
    "tomato" if status == "suspicious" else "steelblue"
    for status in df["status"]
]

plt.figure(figsize=(10, 6))

plt.bar(labels, df["unique_port_count"], color=bar_colors)

# ---- dotted line showing the detection threshold ----
plt.axhline(
    y=threshold,
    linestyle="--",
    color="black",
    label=f"detection threshold ({threshold})"
)

plt.title("network port scan detection")
plt.xlabel("source ip and time window")
plt.ylabel("total unique destination ports")
plt.legend()

plt.tight_layout()
plt.show()
