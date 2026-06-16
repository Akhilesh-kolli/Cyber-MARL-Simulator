import os
import sys

def find_string(root, target):
    for dirpath, dirnames, filenames in os.walk(root):
        # skip virtualenvs and large dirs
        if 'venv' in dirpath.split(os.sep):
            continue
        for fn in filenames:
            # search all text-like files (skip typical binaries)
            if fn.endswith(('.py', '.md', '.txt', '.html', '.json', '.rst', '.yml', '.yaml', '.ini', '.cfg', '.csv')):
                fp = os.path.join(dirpath, fn)
                try:
                    with open(fp, 'r', encoding='utf-8', errors='ignore') as f:
                        for i, line in enumerate(f, 1):
                            if target in line:
                                print(f"{fp}:{i}: {line.strip()}")
                except Exception as e:
                    print(f"ERROR reading {fp}: {e}", file=sys.stderr)

if __name__ == '__main__':
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    target = sys.argv[2] if len(sys.argv) > 2 else 'ATT&CK;'
    find_string(root, target)
