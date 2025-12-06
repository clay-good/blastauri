# Blastauri Docker Image
# Build: docker build -t blastauri .
# Run: docker run --rm blastauri --help

FROM python:3.11-slim

# Set labels
LABEL org.opencontainers.image.source="https://github.com/clay-good/blastauri"
LABEL org.opencontainers.image.description="Know what breaks before you merge"
LABEL org.opencontainers.image.licenses="MIT"

# Install git (required for GitPython)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash blastauri
USER blastauri
WORKDIR /home/blastauri

# Set up Python environment
ENV PATH="/home/blastauri/.local/bin:${PATH}"
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install blastauri
COPY --chown=blastauri:blastauri . /tmp/blastauri
RUN pip install --user --no-cache-dir /tmp/blastauri && \
    rm -rf /tmp/blastauri

# Set working directory for scanning
WORKDIR /workspace

# Default command
ENTRYPOINT ["blastauri"]
CMD ["--help"]
