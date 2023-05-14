# adAPT Machine Learning Challenge Report

This is the report for adAPT machine learning challenge. This document will
* Describe the Challenge
* Describe the implemented Solution and Rationale
    * feature engineering
    * model selection
    * cross validation technique
    * evaluation
    * results
    * improvements upon my results
* A diagram of a pipeline for your model deployed in Elastic. Describe this diagram in a section of  your report.
  
## Challenge Description
In this challenge, I was asked to use network packet captures (pcap files) to classify malware using a machine learning model.

The full set of rules can be identified in [challenge.md](challenge.md) or [README.md](../README.md)

## Solution Implementation
This section will describe my solution and rationale. The time limit on this challenge forced me to make design decisions that were a working solution vs. a very robust working solution.

### Feature Engineering
TCP/IP network packets have a lot of inherent features by the nature of their structure and protocols. Some of those structural features were used directly in the feature engineering. Some were derived from the structural features. The table below describes the selected features and how they were generated.

I used `scapy` as my pcap parser which also has the notion of application layers. A DNS packet may have these layers
* IP
* UDP
* DNS
whereas an HTTP request packet may have
* IP
* TCP
* HTTP
* HTTPRequest

Feature Name | Raw / Derived | Possible Values | Selection Rationale | Notes
--- | --- | --- | --- | ---
protocol | derived | True / False (One-Hot Encoded) | Different software can utilize various IP protocols and this can identify likelihood of malware using one over the other | The protocol was derived from the `scapy` IP layer and describes IPv4, IPv6, and UDP
app_layer | derived | True / False (One-Hot Encoded) | Will help capture the application layer behavior of benign and malicious software | The protocol was derived from the `scapy` layers and custom classes in the feature generation
source_addr | raw | True / False (One-Hot Encoded) | An IOC that will probably be low-value but still lends to detection if the prediction is timely. This is a weak feature | The TCP/UDP source address. This value only includes IP addresses and feature generation discards packets that have other values
dest_addr | raw | True / False (One-Hot Encoded) | See `source_addr` | The same as `source_addr` except the destination IP address of the packet
source_port | raw | True / False (One-Hot Encoded) | If malware uses unique ports to communicate this feature will be valuable | The port from which the packet was sent
dest_port | raw | True / False (One-Hot Encoded) | See `source_port` | The port to which the packet was sent
proto_packet_length | raw | Continuous [0-1) | Different functions of software may have predictable packet lengths | The length of the packet as captured at the TCP/UDP `scapy` layer
ip_packet_length | raw | Continuous [0-1) | See `proto_packet_length` | The length of the packet as captured at the IP `scapy` layer
base_domain | derived | True / False (One-Hot Encoded) | The domain itself may lead to detection in a similar fashion as IP address. This is a poor implementation of a domain reputation service and a real service with a score would serve this purpose better | The Domain portion of a URL (e.g., "microsoft.com" from "www.microsoft.com")
host | derived | True / False (One-Hot Encoded) | The hostname of the URL (if present) might be repeated by threat actors and this will indicate that. It is a weak feature but may be useful | The Domain portion of a URL (e.g., "microsoft.com" from "www.microsoft.com")
tld | derived | True / False (One-Hot Encoded) | This is a poor implementation of TLD reputation. A real reputation service with a score for a given TLD would be more useful | The Domain portion of a URL (e.g., "microsoft.com" from "www.microsoft.com")
url_entropy | derived | Numeric >= 0 | The entropy of the URL may lead to discovery of generated (i.e., malicious) domains | The Shannon entropy of the URL string (if present, otherwise 0)
host_entropy | derived | Numeric >= 0 | Malware may utilize domains that are also widely used for legitimate purposes (think raw.githubusercontent.com) so analyzing just the host information can lead to identifying malware that uses this technique | The Shannon entropy of the Host portion of the URL string (if present, otherwise 0)
base_domain_entropy | derived | Numeric >= 0 | The base domain entropy is searching for the inverse of the `host_entropy` - when malware uses legitimate hostnames on malicious domains (e.g., www.evil.ga) | The Shannon entropy of the Domain portion of the URL string (if present, otherwise 0)
host_length | derived | Numeric >= 0 | The length of only the hostname may indicate certain strains of malware that use particularly long names | The Shannon entropy of the Domain portion of the URL string (if present, otherwise 0)
proto_packet_entropy | derived | Numeric >= 0 | The `scapy` packet contains the packet cache in bytes and I am making an assumption that this value can be used to capture smuggling of predictable data (low-entropy) by malware | The Shannon entropy of the TCP/UDP packet cache
source_ip_class_a | derived | True / False (One-Hot Encoded) | The source IP address first octet may indicate popular networks for malware (e.g., national infrastructure) | The first octet of the source IP address
source_ip_class_b | derived | True / False (One-Hot Encoded) | Similiar to `source_ip_class_a` rationale | The first 2 octets of the source IP address
source_ip_class_c | derived | True / False (One-Hot Encoded) | Similiar to `source_ip_class_a` rationale | The first 3 octets of the source IP address
dest_ip_class_a | derived | True / False (One-Hot Encoded) | The destination IP address first octet may indicate popular networks for malware (e.g., national infrastructure) | The first octet of the destination IP address
dest_ip_class_b | derived | True / False (One-Hot Encoded) | Similiar to `dest_ip_class_a` rationale | The first 2 octets of the destination IP address
dest_ip_class_c | derived | True / False (One-Hot Encoded) | Similiar to `dest_ip_class_a` rationale | The first 3 octets of the destination IP address

## Model Selection
Binary classification

## Cross Validation Technique
60, 20, 20

## Evaluation
97% classification accuracy

## Results

## Improvements Upon My Results
* Feature improvements
  * Fewer OHE features
  * Possibly removing IP addresses completely
  * URL features are not necessarily reliable
* Technique improvements
  * Probably performing better packet inspection will result in better results. For example, I did not inspect HTTP Response results because they were difficult to parse in the time alloted
