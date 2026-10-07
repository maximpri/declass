# Declass website

Static Cloudflare Pages site for `declass.priezjev.com`. Plain HTML/CSS with no build step, client-side JavaScript, external fonts, analytics or form submissions. It introduces Declass and links the GitHub repository and its latest release.

Live Pages address: https://declass-site.pages.dev (project `declass-site`, production branch `main`). The custom domain `declass.priezjev.com` is registered with the project.

Preview from the repository root:

```sh
python3 -m http.server 8787 --directory site/public
```

Deploy only `site/public` (never the repository root):

```sh
wrangler pages deploy site/public --project-name declass-site --branch main
```

In Cloudflare DNS for `priezjev.com`, add a proxied CNAME named `declass` with target `declass-site.pages.dev`. Wait for the Pages custom-domain status to become active and verify HTTPS at `https://declass.priezjev.com`.

The site links the GitHub repository and its latest release: deploy it once the repository is public, or those links return 404. The licensing and security reporting policy stay in the main repository. Keep `public/LICENSE` and `public/NOTICE` in sync with the repository copies.
