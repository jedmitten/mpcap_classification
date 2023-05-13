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
