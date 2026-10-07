// SPDX-License-Identifier: GPL-3.0-or-later
// Serves site/public over HTTPS only: plain HTTP is redirected permanently,
// everything else is the static assets (with the headers in public/_headers).
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.protocol === "http:") {
      url.protocol = "https:";
      return Response.redirect(url.toString(), 301);
    }
    return env.ASSETS.fetch(request);
  },
};
