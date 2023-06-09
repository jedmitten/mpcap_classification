# Research Challenge: Malware Classification based on Network  Packet Captures 

## Background
This repository is part of the interview process of adAPT machine learning security researchers.  The challenge is described below. The Elastic model deployment pipeline that is part of the deliverables of this project is found at [this link](#diagram) (and below).

## Final Report
Please see [report.md](report.md) for the final report required by this exercise

# Running the code
## Virtual Environment Init
There are 2 ways to initialize the virtual environment I used
1. If you are on POSIX with `make`, you can run `make init` 
   * That will install virtual environment and install both `requirements.txt` and `requirements-dev.txt`
2. If you do not have access to the `make` system, simply run
   1. `python -m venv .venv`
   2. On POSIX: `./.venv/bin/activate` or on Windows: `.\.venv\Scripts\activate`
   3. `pip install -r requirements.txt`
3. Optionally you can install `requirements-dev.txt` for `pytest` and `black`. These libraries are installed with `make init`
## Feature generation
* Run the notebook `feature_generation.ipynb`, which implements all feature generation code (separated out from model generation)
  * Two files are created from this process that are subsequently read as input into `build_and_run_model.ipynb`)
    * `benign_features.pkl`
    * `malicious_features.pkl`
* This notebook takes approximately 1m 40s to run on my system
## Model generation
* Run the notebook `build_and_run_model.ipynb` to read inputs (above), create training sets, and train the model.
* The same notebook provides evaluation outputs at the end.
* The entire process takes significant time on my macbook pro
  * Cell 8 (~2.5 minutes): prepares the input data for use in a ML model. 
  * Cell 11 (~2.75 minutes): Creates training and testing data sets
  * Cell 16 (~2 minutes): Trains the model




# Testing
There is minimal testing included in this code base. It is primary to check if the pcap parsers functioned properly.

The tests either raise an exception or pass

## Introduction 
Brief overview of malware classifica0on 

Malware classification is a common problem in cybersecurity. It is defined as the issue of recognizing malicious vs benign software based on its characteristics and behavior. Malware classification can be performed with the following techniques: i. signature-based detection, ii. behavioral analysis, and iii. Machine Learning based detection. ML is a particularly attractive approach since there are daily new malware strains that cannot be detected by signatures, or their behavior pattern is unknown. However, the ML approach to solving the malware detection problem, is prone to false positives or negatives due to the unknown malware characteristics. 

### Importance of classification based on network packet captures 

In this challenge, we are asking you to use network packet captures (pcap files) to classify malware. Packet captures include packet information from the full OSI network stack. Packets can be captured and analyzed in real time by security sensors, and thus they are preferred for real time malware detection. However, they do not include the full picture of malware behavior, such as API calls and permissions, and therefore may cause inaccuracy in classification. 

## Research question: Can machine learning models be used to accurately classify malware based on packet captures? 

This is an important question to the field of cybersecurity because it can have a high impact on real time detection of threats and isolation of infected assets to minimize the effects of a cyber attack. The advantage of using network traffic is that if the malware engages in network activity, detection is performed in real time and prevention is rapid. However, if the malware does not engage in network activity, then a wealth of information is lacking from the packet capture data, such as API calls, permissions, and other characteristics of malware. 

**Note**: This is not a big data processing project. The purpose of this project is for you to demonstrate how you would approach a common cybersecurity problem with ML. We do not expect the perfect solution or a production grade solution. 

**You may use GPT assistants for your solution.** However, you need to fully test the solution, ensure you can analyze its details, and answer any technical question.

## Data 
### Description of the dataset 
The dataset provided was downloaded from two sources: 
1. https://www.malware-traffic-analysis.net/ stored in malware.zip. To unzip the malware pcap files you will need to use the password: “infected”  
2. https://weberblog.net/the-ultimate-pcap/ stored in benign.zip. 
The first dataset includes known malware and the second includes benign network traffic. You will find the datasets in this public repo: https://github.com/mundruid/challenge-datasets 
### Data preprocessing steps 
You will need to label the data based on the information given above and make sure that you have a Python library that can read pcap files. You may label a whole pcap sample with 1 for malicious and 0 for benign. You may choose not to label the data and use a different set of algorithms for classification. 
### Feature engineering techniques 
The data that we provide is raw, therefore you will have to perform your own feature engineering.  
## Methods 
### Overview of machine learning algorithms 
You can use more than one ML algorithms for classification. You may use supervised, unsupervised, or reinforcement learning. We are not looking for one solution fits all, just your unique way to approach the problem. 
### Evaluation metrics  
You will need to evaluate the accuracy of your model with any metrics that you consider appropriate. 
## ML Ops 
Design a pipeline for your model in Elastic. The pipeline should include the technologies that you will use, whether this is Elastic or others, for the following: 
- Feature registry, 
- Model registry, 
- Model Deployment, 
- Testing.

Submit a diagram of this pipeline. Use arrows to indicate data flow.  
Note: You do not need to submit an implementation of this pipeline. 
## Deliverables 
* A private GitHub or Gitlab repository that you will add Xenia as collaborator
   * **Xenia’s GitHub handle: mundruid, Xenia’s GitLab handle: drx42.**
   * The repo will include your code and documentation.
   * **Please send an email that your work is done, and you have added Xenia as collaborator by Monday, May 15, EOD (midnight UTC) to pmountrouidou@cyberadapt.com**
* **Python code** that you used to process the data and create your models. Please submit your code in the form of **Jupyter** notebooks with their output and a **requirements.txt** with all the packages that you used. Note: you may dockerize your solution. Include instructions in your README on how we can run your code.  
* The **report** should be in the file named: **report.md**. Your report needs to describe your solutions and rationale. Describe your solutions and justifications to the following: 
   * feature engineering,  
   * model selection,  
   * cross validation technique (if you used it), 
   * evaluation,  
   * results, and 
   * how you can improve upon your results. 
* A diagram of a pipeline for your model deployed in Elastic. Describe this diagram in a section of your report.

## Diagram
The diagram of the Elastic inference pipeline
```mermaid
flowchart LR
    subgraph Jupyter & Python: Feature Collection & Extraction
    NBD[(Network Batch Data)]
    NSD[/Network Streaming Data/]
    NBD --> FTG{{Feature Transforms / Generator}}
    NSD --> FTG
    end
    subgraph Feast: Feature Storage
    FTG --> FR[(Feature Registry)]
    FTG --> DL[(Data Lake storing network data </br> enriched with features)]
    end
    subgraph KubeFlow: Model Training, Deployment, & Registration 
    FR --> ModTrn{{Model Training}}
    ModTrn --> MR[(Model Registry)]
    MR --> MD[TensorFlow Model Service]
    MD --> PD{{Online Prediction Testing}}
    PD -- iterate --> MR
    end
    subgraph Elastic UI & Model Inference
    MR --> Elastic[Elastic]
    end
 ```
