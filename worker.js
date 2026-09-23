export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/admin-login" && request.method === "POST") {
      try {
        const data = await request.json();
        const valid = data.id === "submarine" && data.password === env.ADMIN_PASSWORD;
        return Response.json({ ok: valid }, { status: valid ? 200 : 401 });
      } catch {
        return Response.json({ ok: false }, { status: 400 });
      }
    }
    return env.ASSETS.fetch(request);
  }
};