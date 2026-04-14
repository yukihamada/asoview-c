with open("migrations/schema.sql") as f:
    sql = f.read()
lines = []
for line in sql.splitlines():
    escaped = line.replace('\\', '\\\\').replace('"', '\\"')
    lines.append('    "{}\\n"'.format(escaped))
with open("src/schema_embed.h", "w") as f:
    f.write('\n'.join(lines) + '\n')
print("src/schema_embed.h updated")
