"""Demo helper: print what is REALLY stored in data.db, to show it is ciphertext, not plaintext."""
import sqlite3

conn = sqlite3.connect("data.db")

# Users: only salts + password hash are stored, never the password itself
print("== users ==")
for name, pw_hash in conn.execute("SELECT username, hex(pw_hash) FROM users"):
    print(f"{name:15} pw_hash={pw_hash[:32]}...")

# Ciphertexts: first 32 bytes of each stored copy
print("\n== ciphertexts ==")
rows = conn.execute("""SELECT i.id, i.kind, i.filename, i.size, c.algo, length(c.data), hex(substr(c.data, 1, 32))
                       FROM items i JOIN ciphertexts c ON c.item_id = i.id ORDER BY i.id, c.algo""")
for iid, kind, fname, size, algo, ct_len, head in rows:
    print(f"#{iid:<3} {kind:8} {fname[:20]:20} {size:>9}B -> {algo} {ct_len:>9}B  {head}")
