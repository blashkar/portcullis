# The official filesystem MCP server with a made-up workspace baked in.
# Built with no build context (docker build - < this file), so nothing from
# the host can end up in the image. See sandbox/run.sh for how it's run.
ARG BASE
FROM ${BASE}

# /seed is copied into a fresh tmpfs at /workspace on every start, so the
# root filesystem can stay read-only and every session starts clean.
RUN mkdir -p /seed/project/docs /seed/project/src \
 && printf 'Meeting moved to Thursday 3pm.\n' > /seed/project/docs/meeting.txt \
 && printf '# Demo project\n\nA made-up project for trying portcullis.\n' > /seed/project/README.md \
 && printf 'package main\n\nfunc main() { println("hello") }\n' > /seed/project/src/main.go \
 && chown -R node:node /seed

USER node
ENTRYPOINT ["sh", "-c", "cp -a /seed/. /workspace/ && exec node /app/dist/index.js /workspace"]
