# Deno na produkcję (bez Node)
FROM denoland/deno:alpine-1.45.5

WORKDIR /app
# Opcjonalnie cache zależności (gdybyś importował URL-e)
# RUN deno cache main.ts

COPY . .
ENV PORT=8000
EXPOSE 8000

# Pełne uprawnienia (jak w Deno Deploy), jeśli potrzebujesz KV/crypto itp.
CMD ["run", "-A", "main.ts"]
