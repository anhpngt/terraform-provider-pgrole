FROM postgres:14-bullseye

# Install build dependencies and pgAudit extension
RUN apt-get update && apt-get install -y postgresql-14-pgaudit

# The rest of the setup will be done by the init scripts