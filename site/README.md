# Declass website

Static Cloudflare Pages site for `declass.priezjev.com`. Plain HTML/CSS with no build step, client-side JavaScript, external fonts, analytics or form submissions. It introduces Declass and links the GitHub repository and its latest release.

Live at https://declass.priezjev.com, served by the Cloudflare Worker `declass-web` with static assets (`wrangler.toml`, `worker.js`). The Worker redirects plain HTTP to HTTPS and serves `public/` with the headers in `public/_headers`. Its custom domain gives `declass.priezjev.com` its DNS record and certificate, created by Cloudflare at deploy.

Preview from the repository root:

```sh
python3 -m http.server 8787 --directory site/public
```

Deploy (only `site/public` is published, never the repository root):

```sh
wrangler deploy --config site/wrangler.toml
```

The older Pages project `declass-site` (https://declass-site.pages.dev) holds the same files; `wrangler pages deploy site/public --project-name declass-site --branch main` updates it.

The site links the GitHub repository and its latest release: deploy it once the repository is public, or those links return 404. The licensing and security reporting policy stay in the main repository. Keep `public/LICENSE` and `public/NOTICE` in sync with the repository copies.
