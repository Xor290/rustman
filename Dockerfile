# ── Stage 1 : build ───────────────────────────────────────────────────────────
FROM rust:1-slim-bookworm AS builder

# Deps needed to compile eframe/egui (X11 + GL dev headers only, not runtime).
RUN apt-get update && apt-get install -y --no-install-recommends \
        pkg-config \
        libx11-dev \
        libxcursor-dev \
        libxrandr-dev \
        libxinerama-dev \
        libxi-dev \
        libxkbcommon-dev \
        libgl1-mesa-dev \
        libegl1-mesa-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── Dependency cache layer ─────────────────────────────────────────────────
# Copy manifests first so cargo can cache the dep compilation separately.
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY logo.png ./

# Dummy source to let cargo fetch and compile all deps before touching real src.
RUN mkdir src && echo 'fn main(){}' > src/main.rs \
    && cargo build --release 2>/dev/null || true \
    && rm -rf src

# ── Real build ─────────────────────────────────────────────────────────────
COPY src/ src/

# Touch main.rs so cargo rebuilds (dep cache is still warm).
RUN touch src/main.rs && cargo build --release

# ── Stage 2 : runtime ─────────────────────────────────────────────────────────
# The binary only needs glibc — x11-dl loads X11 lazily and CLI mode never
# triggers it, so no X11/GL packages are required at runtime.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/rustman /app/rustman
COPY payload/                                    /app/payload/

# Expose a /reports volume so pipeline jobs can retrieve generated files.
VOLUME ["/reports"]

ENTRYPOINT ["/app/rustman"]
CMD ["--help"]
