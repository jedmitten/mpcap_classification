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


