"""Exercise native CLI contracts and independently compare public fingerprints."""
import base64
from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory

binary = Path(sys.argv[1]).resolve()
root = Path(sys.argv[2]).resolve()
checks = 0

def run(*arguments, code=0, data=None):
    global checks
    result = subprocess.run([binary, *map(str, arguments)], input=data,
                            capture_output=True, text=True, timeout=20)
    assert result.returncode == code, (arguments, result.returncode, code, result.stdout, result.stderr)
    checks += 1
    return result.stdout

def inspect(path, *flags, code=0, data=None):
    return json.loads(run("inspect", "--input", path, "--format", "json", *flags, code=code, data=data))

def diff(before, after, *flags, code=0, data=None):
    return json.loads(run("diff", "--before", before, "--after", after, "--format", "json", *flags, code=code, data=data))

assert run("--version").strip() == "keyledger 0.1.0-preview"
assert "SSH" in run("--help")
before, after = root / "examples/before.keys", root / "examples/after.keys"
base = inspect(before, "--require-restrict", "--fail-on-warning")
assert len(base["entries"]) == 2 and not base["issues"]
change = diff(before, after, "--require-restrict", code=1)
assert change["changed"] and len(change["changes"]) == 1
assert change["changes"][0]["kind"] == "authorization-changed"
assert change["after_issues"][0]["code"] == "restrict-required"
assert not diff(before, root / "examples/equivalent.keys")["changed"]
assert inspect("-", data=before.read_text()) == base
assert diff(before, "-", code=1, data=after.read_text())["changed"]
run("diff", "--before", "-", "--after", "-", code=2, data=before.read_text())
run("inspect", "--input", "-", "--format", "xml", code=2, data=before.read_text())
run("inspect", "--input", "-", code=2, data="ssh-ed25519 malformed")
algorithm_report = inspect(root / "examples/algorithms.keys", "--fail-on-warning", code=1)
assert len(algorithm_report["entries"]) == 5
assert [issue["code"] for issue in algorithm_report["issues"]] == ["rsa-size"]
ssh_keygen = shutil.which("ssh-keygen")
oracle_checks = 0
with TemporaryDirectory() as directory:
    folder = Path(directory)
    for entry, row in zip(algorithm_report["entries"], (root / "examples/algorithms.keys").read_text().splitlines()):
        algorithm, encoded, *_ = row.split()
        fingerprint = "SHA256:" + base64.b64encode(sha256(base64.b64decode(encoded)).digest()).decode().rstrip("=")
        assert fingerprint == entry["fingerprint"] and algorithm == entry["algorithm"]
        checks += 1
        if ssh_keygen:
            key = folder / "public.key"
            key.write_text(row + "\n", encoding="ascii")
            output = subprocess.check_output([ssh_keygen, "-lf", key, "-E", "sha256"], text=True, timeout=10)
            assert output.split()[1] == fingerprint, output
            assert int(output.split()[0]) == entry["bits"], output
            oracle_checks += 1

    security=root/'examples/security-ed25519.keys'
    entry=inspect(security)['entries'][0]
    assert entry['algorithm']=='sk-ssh-ed25519@openssh.com' and entry['bits']==256
    public=security.read_text().split()[1]
    assert entry['fingerprint']=='SHA256:'+base64.b64encode(sha256(base64.b64decode(public)).digest()).decode().rstrip('=')
    if ssh_keygen:
        output=subprocess.check_output([ssh_keygen,'-lf',security,'-E','sha256'],text=True,timeout=10)
        assert output.split()[1]==entry['fingerprint'] and int(output.split()[0])==256,output
        oracle_checks+=1

    security=root/'examples/security-ecdsa.keys'
    entry=inspect(security)['entries'][0]
    assert entry['algorithm']=='sk-ecdsa-sha2-nistp256@openssh.com' and entry['bits']==256
    public=security.read_text().split()[1]
    assert entry['fingerprint']=='SHA256:'+base64.b64encode(sha256(base64.b64decode(public)).digest()).decode().rstrip('=')
    if ssh_keygen:
        output=subprocess.check_output([ssh_keygen,'-lf',security,'-E','sha256'],text=True,timeout=10)
        assert output.split()[1]==entry['fingerprint'] and int(output.split()[0])==256,output
        oracle_checks+=1
    empty = folder / "empty.keys"
    empty.write_text("# intentionally empty\n")
    added = diff(empty, before, code=1)
    removed = diff(before, empty, code=1)
    assert all(item["kind"] == "key-added" for item in added["changes"])
    assert all(item["kind"] == "key-removed" for item in removed["changes"])
    duplicate = folder / "duplicate.keys"
    duplicate.write_text(before.read_text() + before.read_text().splitlines()[0] + "\n")
    assert inspect(duplicate, "--fail-on-warning", code=1)["issues"][0]["code"] == "duplicate-key"
    assert diff(before, duplicate, code=1)["changes"][0]["kind"] == "authorization-changed"
    unknown = folder / "unknown.keys"
    unknown.write_text("future-flag " + (root / "examples/algorithms.keys").read_text().splitlines()[0] + "\n")
    assert inspect(unknown, "--fail-on-warning", code=1)["issues"][0]["code"] == "unknown-option"
    ca = folder / "ca.keys"
    ca.write_text("cert-authority " + (root / "examples/algorithms.keys").read_text().splitlines()[0] + "\n")
    assert inspect(ca, "--forbid-ca", "--fail-on-warning", code=1)["issues"][0]["code"] == "ca-forbidden"
    environment = folder / "environment.keys"
    environment.write_text('environment="MISSING_EQUALS" ' + (root / "examples/algorithms.keys").read_text().splitlines()[0] + "\n")
    assert inspect(environment, "--fail-on-warning", code=1)["issues"][0]["code"] == "environment-syntax"
    environment.write_text('environment="3_OK=has=equals" ' + (root / "examples/algorithms.keys").read_text().splitlines()[0] + "\n")
    assert inspect(environment, "--fail-on-warning")["issues"] == []
    environment.write_text('environment="A=one",environment="A=two" ' + (root / "examples/algorithms.keys").read_text().splitlines()[0] + "\n")
    assert inspect(environment, "--fail-on-warning", code=1)["issues"][0]["code"] == "environment-shadowed"
    environment.write_text('environment="A=one",environment="a=two" ' + (root / "examples/algorithms.keys").read_text().splitlines()[0] + "\n")
    assert inspect(environment, "--fail-on-warning")["issues"] == []
    malformed = folder / "malformed.keys"
    for value in ("ssh-ed25519 !", "ssh-dss AAAA", "# nul\0", "\ufeff# bom", "#" * 8193, 'command="unterminated'):
        malformed.write_text(value, encoding="utf-8")
        assert run("inspect", "--input", malformed, "--format", "json", code=2) == ""
    malformed.write_bytes(b"# invalid utf8 \xff")
    assert run("inspect", "--input", malformed, code=2) == ""
    run("inspect", "--input", folder, code=2)
    run("inspect", "--input", folder / "does-not-exist", code=2)
assert oracle_checks in (0, 7)
print(f"{checks} integration checks passed; {oracle_checks} OpenSSH fingerprint comparisons")
