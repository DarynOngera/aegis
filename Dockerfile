# syntax=docker/dockerfile:1

# Base images are pinned by tag and digest. Renovate/Dependabot updates both
# together; a moving tag alone is not enough to make a build reproducible.

ARG ELIXIR_IMAGE=hexpm/elixir:1.18.4-erlang-27.3.4.16-debian-bookworm-20260824-slim@sha256:dde28876be197773dfc507426802bcedd2671bb411ad0517c33fc296aadf1f3f
ARG DEBIAN_IMAGE=debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8

FROM ${ELIXIR_IMAGE} AS build

ENV MIX_ENV=prod \
    LANG=C.UTF-8

WORKDIR /build

RUN mix local.hex --force && mix local.rebar --force

COPY mix.exs ./
COPY lib ./lib

RUN mix deps.get --only prod \
 && mix compile --warnings-as-errors \
 && mix release

FROM ${DEBIAN_IMAGE} AS runtime

ARG VERSION=0.2.0
ARG REVISION=unknown

LABEL org.opencontainers.image.title="dep_guard" \
      org.opencontainers.image.description="Standalone dependency scanner for Elixir projects" \
      org.opencontainers.image.source="https://github.com/DarynOngera/dep_guard" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

# ERTS needs libstdc++/ncurses/openssl; ca-certificates is required for the
# outbound HTTPS checks. git is deliberately absent: CI passes --base-lock.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      libncurses6 \
      libssl3 \
      libstdc++6 \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 depguard \
 && useradd --system --uid 10001 --gid depguard --home-dir /app --shell /usr/sbin/nologin depguard

WORKDIR /app
COPY --from=build --chown=depguard:depguard /build/_build/prod/rel/dep_guard/ ./
COPY --chmod=755 rel/dep_guard /usr/local/bin/dep_guard

USER depguard
ENV HOME=/app \
    XDG_CACHE_HOME=/cache \
    LANG=C.UTF-8

ENTRYPOINT ["/usr/local/bin/dep_guard"]
CMD ["help"]
