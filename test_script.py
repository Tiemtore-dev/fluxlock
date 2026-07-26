import os, base64

secret = os.environ.get("SECRET", "")
try:
    decoded = base64.b64decode(secret).decode('utf-8')
except Exception:
    decoded = secret

if "untrusted comment:" in decoded:
    lines = decoded.split("untrusted comment:")
    if len(lines) > 1:
        key_part = lines[1].strip()
        if key_part.startswith("rsign encrypted secret key"):
            key_part = key_part[len("rsign encrypted secret key"):].strip()
        
        final_key = f"untrusted comment: rsign encrypted secret key\n{key_part}\n"
        with open("test.key", "w") as f:
            f.write(final_key)
        print("Done")
