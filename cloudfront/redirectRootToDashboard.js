function handler(event) {
    const request = event.request;
    const headers = request.headers;
    const host = headers.host && headers.host.value;
  
    // Redirect non-www to www
    if (host === "cveintel.org") {
      return {
        statusCode: 301,
        statusDescription: "Moved Permanently",
        headers: {
          location: { value: "https://www.cveintel.org" }
        }
      };
    }
  
    // Redirect root path (/) to dashboard permalink
    if (host === "www.cveintel.org" && request.uri === "/") {
      return {
        statusCode: 302,
        statusDescription: "Found",
        headers: {
          location: {
            value:
              "/superset/dashboard/2e01de8e-afed-4c24-86b3-89b33bb9f48e" +
              "?permalink_key=M0wVAq9ApQ1"
          }
        }
      };
    }
  
    return request;
  }
  