---
layout: writeup.html
title: Behavioral Analysis with Python - Beaconing
description: In the previous lab, we identified beaconing as a key behavioral indicator of C2 activity but acknowledged that detecting it requires more than endpoint telemetry. Sysmon couldn't see Sliver's in-memory execution, and HTTPS traffic on port 443 blends seamlessly with legitimate web traffic. NDR tools address this gap through statistical analysis of connection timing but what if you don't have an NDR solution, or it hasn't alerted?
date: 2026-06-22T12:00:00-07:00
tags: blog
---

#### Intro
In the previous lab, we identified beaconing as a key behavioral indicator of C2 activity but acknowledged that detecting it requires more than endpoint telemetry. Sysmon couldn't see Sliver's in-memory execution, and HTTPS traffic on port 443 blends seamlessly with legitimate web traffic. NDR tools address this gap through statistical analysis of connection timing but what if you don't have an NDR solution, or it hasn't alerted?

This lab builds a lightweight Python script that an analyst can run on a suspicious endpoint's packet capture to identify beaconing behavior without enterprise tooling. The idea is simple, malware beacons at regular intervals, legitimate software doesn't (for the most part). By analyzing the statistical regularity of outbound connections we can surface C2 activity that signature-based tools miss.

This isn't meant to replace an NDR solution or any enterprise tooling. This is a focused utility and something that an analyst can run during an investigation when purpose-built tools are available, haven't alerted or you just want a second opinion on suspicious traffic.

When I took statistics in college, I assumed I would never apply it but look at me now. 

#### Tools Used
As always, below is a list of tools used to build this lab.

| Tool              | Purpose                                                                   |
| ----------------- | ------------------------------------------------------------------------- |
| Sliver            | Generate realistic beacon traffic for analysis                            |
| Wireshark/tcpdump | Capture network traffic                                                   |
| Python/Scapy      | Parse pcap and extract connection timestamps                              |
| Python/Statistics | Calculate intervals, standard deviation and CV (coefficient of variation) |

#### Beaconing Theory
Beaconing theory is simple. Instead of maintaining a persistent connection, a beacon checks in at intervals, executes queued tasks, then goes quiet until the next check-in. A beacon is a drop of communication rather than a stream. Legitimate software rarely needs to check in on a fixed schedule. For example, DRM checks might happen once a day or when you launch an app. A beacon checking in every 60 seconds has a purpose.

Modern C2 frameworks like Sliver add jitter to their beacon interval to avoid detection. Instead of checking in every exactly 60 seconds, it might check in at 55, 68, 71, or 58 seconds. Simple interval matching fails here because no two intervals are identical.

This is where the Coefficient of Variation (CV) comes in. Standard deviation measures how much variation exists in absolute terms but it can't tell you whether that variation is significant relative to the interval. A 5 second deviation looks the same whether the beacon runs every 10 seconds or every 60 seconds, but those are different levels of regularity. CV divides standard deviation by the mean, normalizing the measurement. This lets us flag suspicious regularity at any beacon speed with a single threshold, because we're hunting for consistency rather than a specific interval. 

#### Code Walkthrough
Let's go through each function and explain what it does so we can connect the theory to the execution. 

##### CLI Usage
We can use the utility in two ways, either with arguments or without. Function `cli_args()` is self explanatory. We have three arguments that can be provided.
- `--help` brings up a help menu
- `-f or --file` lets us specify the input capture file in pcap format
- `--local-ip` lets us exclude the local IP of the computer we are capturing network traffic
```
from collections import defaultdict
from scapy.all import rdpcap
import statistics, argparse

def cli_args():
    parser = argparse.ArgumentParser(description="Beacon Detection Script. Use with .pcap files.")
    parser.add_argument("--local-ip", help="Local machine IP to be excluded from analysis")
    parser.add_argument("-f", "--file", help="Location of file")
    args = parser.parse_args()

    return args
```

None of the arguments are required so we can just run `python capture_analysis.py` and get an interactive cli prompt for our pcap file.  

Usage: `python capture_analysis.py -f capture.pcap --local-ip x.x.x.x`  
![](</assets/images/Pasted image 20260620174047.png>)

#### File Input
Next up is the `file_input()` function. As the name implies, this handles our capture file. 
First, we check for the `-f or --file` argument. If we find a file specified, we move on and return `cap` which uses the `rdpcap` function from `scapy.all`

We also handle errors such as a Keyboard interrupt (`Ctrl+C` during file prompt) and File not found if the file does not exist. This lets us have a clean cli screen during execution. 

```
def file_input():
    args = cli_args()
    if args.file:
        print("Processing Capture. This may take a minute...")
        capture = args.file
        cap = rdpcap(capture)
        return cap

    else:
        while True:
            try:
                capture = input(f"Enter File location: ")
            except KeyboardInterrupt:
                print("\nExiting...")
                exit(1)
            try:
                print("Processing Capture. This may take a minute...")
                cap = rdpcap(capture)
                return cap
            except FileNotFoundError:
                print("\nFile not found. Check name or directory and try again.")
                continue
```

#### Packet Capture Processing
The `parse_cap()` function is where the parsing of the pcap happens. Smaller files can be parsed quickly but a bigger file may take a little bit of time. 

An important thing to know with `rdpcap()` is it parses every packet fully, meaning all layers, fields and data is passed into our script and into memory, even if we're only looking for one or two specifics. Scapy is also pure Python, meaning there is no C acceleration for the parsing loop like we'd find with other libraries. 

`defaultdict(list)` automatically creates an empty list for any new destination IP key, so we don't need to check if the key exists before appending. Keeps the code clean and readable. 

In this function, we're also looking at whether the packet has the TCP and IP layers, and if the flags are `S or SA`, meaning the start of the connection. Because the beacon is just a blip, we only need the start of the connection as that's when a machine checks in. Everything after that is just noise (for our purpose).

Then, we're grouping our Source IPs and Timestamps by the **Destination** IP. The source IP isn't required for this to work but it's good to have anyway in case the network is a bit noisier. That way, we'll know what machine connected to the what destination at what time. 

```
def parse_cap():
    destIp = defaultdict(list)
    cap = file_input()
    for pkt in cap:
        if pkt.haslayer('TCP') and pkt.haslayer('IP'):
           if pkt["TCP"].flags == 'S' or pkt["TCP"].flags == 'SA':
                destIp[(pkt["IP"].dst)].append({
                    "Source IP": pkt["IP"].src, 
                    "Timestamp": float(pkt.time)
                    })
    return destIp
```

#### Statistics Calculation
With `calculate_std()`, we get into the math behind the theory. This is where our Destination IP, Source IP, and timestamp get analyzed. 

```
def calculate_std():
    result = parse_cap()
    beacons_found = False
    for dest_ip, connections in result.items():
        try:
            timestamps = [conn["Timestamp"] for conn in connections]
            interval = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

            if len(interval) < 2:
                continue

            deviation = statistics.stdev(interval)
            mean = statistics.mean(interval)
            cv = deviation/mean
            if cv < 0.5 and len(timestamps) >=5:
                beacons_found = True
                print(f"--------------------------------")
                print(f"POTENTIAL BEACONING DETECTED")
                print(f"Destination: {dest_ip}")
                print(f"Packet count: {len(timestamps)}")
                print(f"Mean interval: {mean:.2f}s")
                print(f"StDev: {deviation:.2f}")
                print(f"CV: {cv:.2f}")
                print(f"--------------------------------")
        except statistics.StatisticsError as e:
            continue
    if not beacons_found:
        print("No beacons found.")
```

We have a variable called `beacons_found` that is set to `False`. This is used to track whether or not we enter our `if cv < 0.5` loop because a potential beacon was found. If we enter the loop, the variable is flipped to `True` and we print the relevant info. If beacons are not found and we don't enter the loop, we enter the final `if not beacons_found` loop to finish the script. 

There are two for loops here. First, `timestamps` loop extracts the timestamps. This is Python shorthand so it might look weird or unfamiliar but the structure is the same as a regular for loop.
`timestamps = [conn["Timestamp"] for conn in connections]`

Longform would look like this:
```
timestamps = []
for conn in connections:
	timestamps.append(conn["Timestamp"])
```

For reference, timestamp format looks like this: 
```
"X.X.X.X": [ 
{ 
"Source IP": "10.0.0.12", 
"Timestamp": 1781380894.417503 
}, 
{ 
"Source IP": "10.0.0.12", 
"Timestamp": 1781380894.436258 
}
]
```

Then, we calculate the intervals between every **two** timestamps.  
`interval = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]`  
Here, we are looking at `timestamp i and timestamp i+1` as a pair because math usually involves more than one thing in a vacuum. 

`if len(interval) < 2: continue` is a safety check for the next portion. We need to have more than one interval to check the standard deviation and mean. If we have less than two, then we'd get an error. 

This is where the magic happens. Thankfully, the statistics module allows us to not to do any manual math. We're calculating the standard deviation, mean and the coefficient of variance here. 
```
deviation = statistics.stdev(interval)
mean = statistics.mean(interval)
cv = deviation/mean
```

This next part requires some judgment, research, and testing. We're looking for two things in our `if` statement. If both of those are satisfied, then we have a potential beacon. 
- make sure the `cv` is less than `0.5` which means it's **regular**
- make sure we have 5 or more timestamps to work with. 
```
if cv < 0.5 and len(timestamps) >=5:
				beacons_found = True
                print(f"--------------------------------")
                print(f"POTENTIAL BEACONING DETECTED")
                print(f"Destination: {dest_ip}")
                print(f"Packet count: {len(timestamps)}")
                print(f"Mean interval: {mean:.2f}s")
                print(f"StDev: {deviation:.2f}")
                print(f"CV: {cv:.2f}")
                print(f"--------------------------------")
        except statistics.StatisticsError as e:
            continue
```

As a handy guide, this is what the internet says. 
Based on this, our threshold of 0.5 sits between Regular and Random. Anything below 0.5 is worth investigating. 

| CV Range             | Traffic Characteristic | Common Example                                 |
| -------------------- | ---------------------- | ---------------------------------------------- |
| Low (< 0.2)          | Highly Deterministic   | Scheduled cron jobs, hardcoded system pings    |
| Moderate (0.2 - 0.7) | Regular / Assisted     | Polling, active streaming                      |
| Random (= 1.0)       | Memoryless / Poisson   | Traditional, independent user session starts   |
| High (> 1.0)         | Heavy-Tailed / Bursty  | Human web browsing, flash crowds, DDoS attacks |

#### Results
I captured about 10-15 minutes worth of network traffic while our Sliver beacon was running and because I knew what the "attacker" IP was, I could verify whether the script correctly identified the beacon traffic. 

Below are the results.
![](</assets/images/Pasted image 20260620185154.png>)
```
--------------------------------
POTENTIAL BEACONING DETECTED
Destination: 10.0.0.19
Packet count: 7
Mean interval: 75.83s
StDev: 11.97
CV: 0.16
--------------------------------
```

The output is destination IP, how many packets were sent, the mean interval between each packet, the standard deviation and the CV. A CV of 0.16 puts us in the highly deterministic range from our reference table above, too regular to be a coincidence. Combined with the mean interval of 75.83 seconds aligning closely with Sliver's default beacon interval, this is a strong indicator of C2 activity. 

For an analyst, the StDev and CV information may not matter but it's good to have in case we want to investigate why this popped up. 

Seven check-ins in roughly 15 minutes is consistent with a ~75s beacon interval so our math checks out. 

#### Conclusion
Using Python, we demonstrated that even an advanced framework like Sliver can be detected. We used statistics and judgment to set thresholds for the CV and even with jitter, Sliver was detected. A CV of 0.16 against Sliver's jittered beacon is a concrete result, not just a proof of concept. Even though this is a relatively simple utility, the result demonstrated that options exist even without an enterprise budget. That said, self-built utilities have real limitations and we should be honest about how much we can rely on them. 

The biggest limitation is scope. We are reduced to point-in-time captures from a single machine that do not show us how the device behaved the previous day. Enterprise tooling which includes SIEMs, EDR, NDR, ML/AI and identity protection provides continuous visibility, broader context and correlation across the entire environment. This goes for all types of security tools. Rule of thumb: If your self hosted solution is that good, you should start a company. 

The biggest takeaway is defense in depth. We saw the gaps regular monitoring has when faced with a more advanced threat. Defense in depth allows us to analyze more than one layer of our environment and catch potential threats. We saw in the previous Metasploit and Sliver labs the evolution of detection. Metasploit was trivial; Sliver was significantly more difficult and this exercise built a utility out of the information we gathered. 

When people ask "Will I ever need to code?" or "Do I really need to know math for security?", they can be pointed here. The answer is nuanced. Both skills make you a better defender, and while AI can accelerate the work, it shouldn't replace thinking. We should still analyze, question, rework and argue with AI to get the results we want and most importantly, understand the context behind every decision made. 

The script is available here: [GitHub Script](https://github.com/sberdar/Detection-Rules/blob/main/capture%20analysis.py)