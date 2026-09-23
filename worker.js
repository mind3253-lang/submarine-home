export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/admin-login" && request.method === "POST") {
      try {
        const data = await request.json();
        const configured = env.ADMIN_PASSWORD;
        if (!configured) {
          return Response.json({ ok: false, reason: "PASSWORD_NOT_CONFIGURED" }, { status: 503 });
        }
        const valid = data.id === "submarine" && String(data.password) === String(configured);
        return Response.json({ ok: valid }, { status: valid ? 200 : 401 });
      } catch {
        return Response.json({ ok: false, reason: "BAD_REQUEST" }, { status: 400 });
      }
    }

    const response = await env.ASSETS.fetch(request);
    if (url.pathname.endsWith(".html") || url.pathname === "/") {
      const fresh = new Response(response.body, response);
      fresh.headers.set("Cache-Control", "no-store, no-cache, must-revalidate");
      return fresh;
    }
    return response;
  }
};