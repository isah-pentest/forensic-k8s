"""Run an original repository script without modifying it.

The released scripts hard-code the authors' repository location
(/home/pentestnet/forensic-k8s). To keep every released file byte-identical
(and verifiable against INTEGRITY_SHA256SUMS), this wrapper copies the script
to a temporary directory, substitutes that one path with the actual repository
root (or $FORENSIC_K8S_ROOT), runs the copy, and deletes it. Nothing else in the
script is changed.

Usage: python3 run_original.py <path/to/script.py> [args...]
"""
import os, shutil, subprocess, sys, tempfile

ORIGINAL_ROOT = "/home/pentestnet/forensic-k8s"


def repo_root():
    return os.environ.get("FORENSIC_K8S_ROOT") or os.path.abspath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def rewritten_copy(script, dest_dir, root=None):
    """Write a copy of `script` into dest_dir with the hard-coded root replaced."""
    root = root or repo_root()
    src = open(script, encoding="utf-8").read()
    dst = os.path.join(dest_dir, os.path.basename(script))
    open(dst, "w", encoding="utf-8").write(src.replace(ORIGINAL_ROOT, root))
    return dst


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    tmp = tempfile.mkdtemp(prefix="fk8s_run_")
    try:
        copy = rewritten_copy(sys.argv[1], tmp)
        sys.exit(subprocess.run([sys.executable, copy, *sys.argv[2:]], cwd=repo_root()).returncode)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
