# my-project
Quick Start (using the already-installed venv)

# Activate the test virtual environment
source /tmp/cryptoviz-test-env/bin/activate

# Run on the good example
cryptoviz examples/aes_example.py

# Run on the bad example (shows errors)
cryptoviz examples/bad_crypto.py
This will open http://localhost:8765 in your browser automatically.

Fresh Install (for a new machine or permanent setup)

cd /Users/priyanshivyas/cryptoviz

# 1. Build the frontend (only needed once, or after frontend changes)
cd frontend && npm install && npm run build && cd ..

# 2. Create a virtual environment and install
python3 -m venv venv
source venv/bin/activate
pip install -e .

# 3. Run it
cryptoviz examples/aes_example.py
CLI Options

cryptoviz <file.py>              # analyze + open browser
cryptoviz <file.py> --no-browser # analyze + start server, no auto-open
cryptoviz <file.py> --port 9000  # use a different port
cryptoviz <file.py> --static-only  # skip runtime capture (faster, no exec)
What you'll see
The terminal prints node/edge counts and any detected issues
A browser tab opens with an interactive graph
Click any node → detail panel on the right shows algorithm, key size, runtime value, errors
Hover for the source snippet tooltip
Red nodes = errors, yellow = warnings
Try it with cryptoviz examples/bad_crypto.py first — it has a hardcoded key + ECB mode + MD5, so you'll see the error highlighting in action.

