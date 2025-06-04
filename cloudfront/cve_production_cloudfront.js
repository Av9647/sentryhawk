function handler(event) {
  const r  = event.request;
  const h  = (r.headers.host && r.headers.host.value.toLowerCase()) || "";
  const u  = r.uri;               // e.g. "/login" or "/login/"
  const qs = r.querystring || ""; // e.g. "next=http://www.sentryhawk.org/superset/log/?explode=events&dashboard_id=5"

  // 1) Redirect apex “sentryhawk.org” → “www.sentryhawk.org”
  if (h === "sentryhawk.org") {
    return {
      statusCode:        301,
      statusDescription: "Moved Permanently",
      headers: {
        location: { value: "https://www.sentryhawk.org" }
      }
    };
  }

  // 2) Build the rotating “forbidden” messages
  const msgs = [
    "Access Forbidden. Nice Try :)", "Stick to what's available :/", "This path is reserved for fictional admins.",
    "You're being watched... by a static function", "Denied. But you already knew that.", "Nope. Not here.",
    "This isn't the endpoint you're looking for.", "The void stares back.", "You're lost. Go home.",
    "No entry. No exceptions.", "403. Because reasons.", "Move along, citizen.", "Nothing to see here, move along",
    "Permission denied by invisible gnome.", "You've reached a restricted memory segment.", "You tried. We noticed.",
    "Access denied. Go touch some grass.", "No access. Even the server's confused.", "Nope. Try again never.",
    "System: 'lol nope.'", "This area is guarded by a rubber duck.", "Nope. Not on our watch.", "Public-facing? Not this one.",
    "Nice curiosity. Bad endpoint.", "Keep exploring. Just... not here.", "This is the part where you get blocked.",
    "Debug mode: disabled.", "If you're reading this, you're blocked.", "This road leads nowhere.", "Under heavy protection.",
    "You're being rate-limited by fate.", "Denied. The code gods have spoken.", "Good instincts. Bad target.",
    "No thanks. We're good.", "Remember the kiss that happened in class?, I did love her ~back then.",
    "Turn back. There's dragons ahead.", "You tripped the silent alarm.", "Who told you this was okay?",
    "System integrity preserved. You, not so much.", "Cute request. Declined.", "Only bots go this way. Are you a bot?",
    "We're watching you debug yourself.", "Access rejected. Redirect your curiosity.", "Entry prohibited by higher powers.",
    "Authorized personnel only. You're not.", "No dice. Go back.", "You have wandered into the void.",
    "Access denied. Magic barriers ahead.", "Better luck elsewhere, champ.", "Blink twice if you need help. Still no.",
    "This endpoint is off limits. Period.", "Access blocked. Come back with cookies.", "Nice try, but access is restricted.",
    "You shall not pass.", "The gate remains closed.", "Error 403: HR said no.", "Locked out. Check your motives.",
    "Trying to be sneaky? We saw that.", "Your request was declined by fate.", "Out of bounds. Stay in line.",
    "Forbidden territory. Turn back.", "Access barred. Move along.", "Keep your distance. This is private.",
    "No unauthorized RFCs allowed.", "Code says no.", "The secrets are safe. Not for you.", "Denied. We're not sorry.",
    "404? No, 403: Forbidden.", "Access key required. You have none.", "Nice thought, bad idea.", "You've got the wrong address.",
    "Our logs are full. Stop.", "You've reached the error zone.", "Permission revoked. Enjoy your day.", "Forbidden. Just is.",
    "There's nothing behind this door.", "Interpretation: No.", "Redirecting to disappointment.", "Access Denied —Philosophy Department.",
    "Not even if you pay Bitcoin.", "You're seeing this because you have no access.", "Blocked by top-secret protocols.",
    "Failed to authenticate your will.", "The server doesn't approve.", "Your curiosity was appreciated, but denied.",
    "We'd tell you, but we'd have to kill your request.", "You're not clever. You're predictable. And we're already watching."
  ];
  const msg = msgs[Math.floor(Math.random() * msgs.length)];

  // 3) Define “hard block” lists
  const blockExact = [
    "/login", "/login/",
    "/superset/login", "/superset/login/",
    "/superset/welcome", "/superset/welcome/",
    "/api/v1/dashboard", "/api/v1/dashboard/",
    "/api/v1/chart", "/api/v1/chart/",
    "/api/v1/dataset", "/api/v1/dataset/",
    "/superset/chart", "/superset/chart/",
    "/superset/explore", "/superset/explore/",
    "/superset/csrf_token",
    "/superset/sqllab", "/superset/sqllab/",
    "/superset/sqllab_json", "/superset/sqllab_viz", "/superset/sqllab/query"
  ];
  const blockPrefix = [
    "/login/", "/superset/login/", "/superset/welcome/",
    "/superset/profile", "/superset/users", "/superset/roles",
    "/superset/security", "/superset/databases", "/superset/views"
  ];

  // 4) WHITELIST internal Superset login calls
  if (
    u.startsWith("/login") &&
    (
      qs.includes("next=http://www.sentryhawk.org/superset/") ||
      qs.includes("next=https://www.sentryhawk.org/superset/")
    )
  ) {
    return r;
  }

  // 5) If path matches blockExact or blockPrefix → return fake 200 + x-tripwire
  const isExactBlocked  = blockExact.indexOf(u) !== -1;
  const isPrefixBlocked = blockPrefix.some(prefix => u.startsWith(prefix));
  if (isExactBlocked || isPrefixBlocked) {
    return {
      statusCode:        200,
      statusDescription: "OK",
      headers:           {
        "content-type": { value: "text/html" },
        "x-tripwire":   { value: "probing" }
      },
      body: `<html><body><h2 style="font-family:sans-serif; text-align:center; margin-top:20%;">${msg}</h2></body></html>`
    };
  }

  // 6) Rewrite "/" → "/superset/index.html"
  if (u === "/") {
    r.uri = "/superset/index.html";
  }

  // 7) Otherwise, proxy everything else unchanged
  return r;
}