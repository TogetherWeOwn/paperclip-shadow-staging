# mb-import: batch-only MusicBrainz dump import + replication applier.
# Interactive traffic never touches this image (ADR 0001/0007).
FROM postgres:16-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates python3 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /job
COPY import.sh /job/import.sh
COPY replicate.sh /job/replicate.sh
RUN chmod 0755 /job/import.sh /job/replicate.sh

# Default: show usage; the scheduler overrides CMD per run.
CMD ["bash", "/job/import.sh", "--help"]
