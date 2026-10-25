# The official "everything" MCP test server, which exercises every protocol
# feature. Built with no build context (docker build - < this file).
ARG BASE
FROM ${BASE}
USER node
ENTRYPOINT ["node", "/app/dist/index.js", "stdio"]
