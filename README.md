
# network port scan detector

## about the project

This project detects potentially suspicious network activity by analyzing simulated network connection data.

It groups connections by source ip address and time window, counts unique destination ports, and flags activity that reaches the detection threshold.

## how it works

- stores simulated network connection records
- groups connections by source ip and 5-minute time window
- removes duplicate destination ports
- flags an ip when it accesses 10 or more unique ports in a window
- displays a report and security alerts
- calculates network statistics using numpy
- uses pandas to organize and analyze the data
- creates a graph using matplotlib

## detection rule

- time window: 300 seconds (5 minutes)
- detection threshold: 10 unique destination ports
- fewer than 10 unique ports: normal
- 10 or more unique ports: suspicious

## technologies used

- python
- numpy
- pandas
- matplotlib

## installation

install the required libraries:

```bash
pip install -r requirements.txt
```

## run the project

```bash
python port_scan_detector.py
```

## limitations

This project uses simulated network data and a simple rule-based detection method. It does not capture live network traffic, and a suspicious alert does not prove malicious activity.

## learning objectives

- python data structures and loops
- duplicate removal using sets
- data analysis with numpy and pandas
- data visualization with matplotlib
- basic network security concepts
