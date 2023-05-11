from pathlib import Path
import pytest
import git

from scapy import all as sp

# https://stackoverflow.com/questions/22081209/find-the-root-of-the-git-repository-where-the-file-lives
def get_git_root(path):
        git_repo = git.Repo(path, search_parent_directories=True)
        git_root = git_repo.git.rev_parse("--show-toplevel")
        return git_root
    
data_dir = Path(get_git_root(".")) / "data"


@pytest.fixture(scope="module")
def http_response_packet():
    with open(data_dir / "HTTPResponse.pcap", "rb") as f:
        return sp.rdpcap(f)[0]


@pytest.fixture(scope="module")
def http_request_packet():
    with open(data_dir / "HTTPRequest.pcap", "rb") as f:
        return sp.rdpcap(f)[0]

@pytest.fixture(scope="module")
def dns_response_packet():
    with open(data_dir / "DNSRR.pcap", "rb") as f:
        return sp.rdpcap(f)[0]

@pytest.fixture(scope="module")
def dns_request_packet():
    with open(data_dir / "DNSQR.pcap", "rb") as f:
        return sp.rdpcap(f)[0]