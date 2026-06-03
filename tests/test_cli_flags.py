import subprocess
def test_scanner_help():
    r = subprocess.run(["python3","scanner/scan.py","-h"], capture_output=True, timeout=5)
    assert r.returncode == 0
