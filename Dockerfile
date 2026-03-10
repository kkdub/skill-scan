FROM python:3.13-slim

# Create non-root user for security
RUN groupadd --system scanner && useradd --system --gid scanner --create-home scanner

# Copy source and build metadata
COPY pyproject.toml README.md /app/
COPY src/ /app/src/

# Install skill-scan from source
RUN pip install --no-cache-dir "/app[remote]"

# Set working directory for scan targets (volume mount point)
WORKDIR /scan

# Run as non-root user
USER scanner

ENTRYPOINT ["skill-scan"]
