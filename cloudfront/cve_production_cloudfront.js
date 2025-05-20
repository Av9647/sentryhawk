function handler(event) {
  const r = event.request;
  const host = r.headers.host && r.headers.host.value.toLowerCase();

  // 1) non‑www → www
  if (host === "sentryhawk.org") {
    return {
      statusCode: 301,
      statusDescription: "Moved Permanently",
      headers: {
        location: { value: "https://www.sentryhawk.org" }
      }
    };
  }

  // 2) homepage rewrite
  if (r.uri === "/") {
    r.uri = "/superset/index.html";  // or "/index.html" if your Origin Path is "/superset"
  }

  return r;
}
