import os
def test_marker():
    print("SYNTHETIC_B:" + os.environ["REPLICATION_CANARY"])
    assert os.environ["REPLICATION_CANARY"] == "synthetic-value-no-credential"
