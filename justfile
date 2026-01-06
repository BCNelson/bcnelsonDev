# bcnelson.dev justfile

# Default recipe - list available commands
default:
    @just --list

# Install npm dependencies
install:
    npm install

# Start dev server (uses steam-run for NixOS workerd compatibility)
dev:
    steam-run npm run dev

# Build the Astro site
build:
    npm run build

# Preview built site locally
preview:
    steam-run npm run preview

# Deploy to Cloudflare Workers (requires CLOUDFLARE_API_TOKEN)
deploy: build
    npx wrangler deploy

# --- Pulumi Infrastructure ---

# Type check infrastructure code
infra-check:
    cd infrastructure && npm run check

# Preview infrastructure changes
infra-preview:
    cd infrastructure && pulumi preview -s prod

# Deploy infrastructure changes
infra-up:
    cd infrastructure && pulumi up -s prod

# Show infrastructure outputs
infra-outputs:
    cd infrastructure && pulumi stack output -s prod

# Refresh infrastructure state
infra-refresh:
    cd infrastructure && pulumi refresh -s prod

# --- Utilities ---

# Clean build artifacts
clean:
    rm -rf dist .astro node_modules/.cache

# Full clean including node_modules
clean-all: clean
    rm -rf node_modules

# Type check
check:
    npx astro check

# Format code with prettier (if configured)
fmt:
    npx prettier --write "src/**/*.{astro,ts,vue,css,md}"
