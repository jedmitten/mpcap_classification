# Running the code
## Virtual Environment Init
* `make init` 
* That will install virtual environment and install both `requirements.txt` and `requirements-dev.txt`
## Feature generation
* At the command prompt `make features`
* That will run `generate_features.py` and output files to `./data`
   * `benign_features.pkl`
   * `malicious_features.pkl`
* Those files are used by the notebook (`build_and_run_model.ipynb`)