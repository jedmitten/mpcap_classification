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
For my model I opted for a supervised binary classification neural network. I chose this model because I already had labelled data and the challenge was to develop a model based on those data. I feel that an unsupervised model would sufficiently identify similar types of software, though it would better serve different questions such as classifying atypical software (anomaly detection) or software that behaves similarly (multi-class categorization).

I used `tensorflow` to implement the neural network.

## Cross Validation Technique
For cross-validation, I split the labelled data into 3 parts:
* 60% for training, 40% for testing and cross-validation
* Of the 40% for testing and cross-validation, an even split of 20% for each was generated

This technique was highlighted while taking courses on machine learning and this particular situation.

## Evaluation
97% classification accuracy

## Results
This challenge did not specify how to evaluate results and so I decided to train and test (on both testing and cross-validation sets) to identify whether the model was performing well or not. Finally, I ran the entire data set through the trained model to identify the accuracy of the model on this set of data. 

## Improvements Upon My Results
* Feature improvements
  * More derived features / Fewer OHE features - The number of features is currently almost 8000 which is a huge number and the value of all those one-hot encoded features is not necessarily high. That being said, it is what I chose to complete this challenge due to time constraints
  * Possibly removing IP addresses completely - The attacker IP addresses are most often disposable and only used briefly. IP addresses are appropriate for network detection, but perhaps not malware classification
  * URL features are not necessarily reliable - The host name is more disposable than even an IP address. The domain is difficult to classify though reputation engines do this at greater scale and utilizing that threat intelligence would be useful
  * Utilizing GeoIP to resolve autonomous system number and geographic region would provide stronger features than simply using IP addresses
  * More application layer protocols would provide a richer feature set
    * ssh
    * ftp
    * smtp
    * smb
* Technique improvements
  * I expect more in-depth analysis of the packet will result in better results. For example, I did not inspect HTTP Response results because they were difficult to parse in the time alloted. Also, HTTPS packets would help identify if a certificate was compromised and having a cert reputation engine would be useful
  * Integrate more threat intelligence - Integrating a WHOIS service would allow me to enrich the IP address data with stronger features including GeoIP and ASN, as well as potentially the registrar
* Evaluation improvements
  * I realize while writing this that I could have omitted one of the malicious data sets to determine if the model could generalize to detecting it as malware (without having been trained on that data). Further, I might identify additional pcaps of data sets to determine if the model properly classifies them. I did not perform these steps due to time constraints.