#!/bin/sh
# Entrypoint: fix ownership of any bind-mounted volumes, then drop to agent user.
# Runs as root so it can chown directories that the host created as root.
set -e

# Ensure the logs directory is writable by the agent user, regardless of
# whether it was created by Docker (as root) via a bind mount.
chown -R agent:agent /app/logs

# Drop privileges and exec the command as the non-root agent user.
exec gosu agent "$@"
