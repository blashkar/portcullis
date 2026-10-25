# The official git MCP server with a throwaway repository baked in.
# Built with no build context (docker build - < this file).
ARG BASE
FROM ${BASE}

ENV GIT_AUTHOR_NAME=Demo GIT_AUTHOR_EMAIL=demo@example.com \
    GIT_COMMITTER_NAME=Demo GIT_COMMITTER_EMAIL=demo@example.com
RUN mkdir -p /seed/repo && cd /seed/repo \
 && git init -q -b main \
 && printf '# Demo repo\n' > README.md && git add . && git commit -q -m "Initial commit" \
 && printf 'TODO: write the parser\n' > TODO.md && git add . && git commit -q -m "Add TODO" \
 && chown -R app:app /seed \
 # Upstream's venv uses a Python under /root, which only root can enter.
 # Let other users pass through /root (but not list it) so the server
 # can run as the unprivileged app user.
 && chmod 711 /root

USER app
ENTRYPOINT ["sh", "-c", "cp -a /seed/. /workspace/ && exec mcp-server-git --repository /workspace/repo"]
