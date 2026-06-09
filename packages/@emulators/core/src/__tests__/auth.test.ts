import { describe, it, expect, beforeEach } from "vitest";
import { createPrivateKey, generateKeyPairSync } from "crypto";
import { SignJWT } from "jose";
import { Hono } from "../http.js";
import { authMiddleware, requireAuth, requireAppAuth, type TokenMap, type AppEnv } from "../middleware/auth.js";

async function signAppJwt(appId: number, privateKeyPem: string): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(String(appId))
    .setIssuedAt()
    .setExpirationTime("9m")
    .sign(createPrivateKey(privateKeyPem));
}

function appAuthTestApp(privateKeyPem: string, tokenMap: TokenMap) {
  const app = new Hono<AppEnv>();
  app.use(
    "*",
    authMiddleware(tokenMap, (appId) =>
      appId === 42 ? { privateKey: privateKeyPem, slug: "my-app", name: "My App" } : null,
    ),
  );
  app.get("/test", (c) => c.json({ app: c.get("authApp") ?? null }));
  return app;
}

describe("authMiddleware", () => {
  let tokenMap: TokenMap;

  beforeEach(() => {
    tokenMap = new Map();
  });

  it("sets authUser on context when the token exists in tokenMap", async () => {
    tokenMap.set("test-token", { login: "testuser", id: 1, scopes: ["repo"] });

    const app = new Hono<AppEnv>();
    app.use("*", authMiddleware(tokenMap));
    app.get("/test", (c) => c.json({ user: c.get("authUser") }));

    const res = await app.request("/test", {
      headers: { Authorization: "Bearer test-token" },
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { user: { login: string; id: number; scopes: string[] } };
    expect(body.user).toEqual({ login: "testuser", id: 1, scopes: ["repo"] });
  });

  it("maps unknown tokens to fallbackUser when configured", async () => {
    const fallbackUser = { login: "fallback", id: 99, scopes: ["read:org"] };

    const app = new Hono<AppEnv>();
    app.use("*", authMiddleware(tokenMap, undefined, fallbackUser));
    app.get("/test", (c) => c.json({ user: c.get("authUser") }));

    const res = await app.request("/test", {
      headers: { Authorization: "Bearer unknown-secret" },
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { user: { login: string; id: number; scopes: string[] } };
    expect(body.user).toEqual(fallbackUser);
    expect(tokenMap.has("unknown-secret")).toBe(false);
  });

  it("does not set authUser when there is no Authorization header", async () => {
    tokenMap.set("test-token", { login: "testuser", id: 1, scopes: ["repo"] });

    const app = new Hono<AppEnv>();
    app.use("*", authMiddleware(tokenMap));
    app.get("/test", (c) => c.json({ user: c.get("authUser") ?? null }));

    const res = await app.request("/test");

    expect(res.status).toBe(200);
    const body = (await res.json()) as { user: unknown };
    expect(body.user).toBeNull();
  });

  it("sets authApp for a valid app JWT signed with a PKCS#8 key", async () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();

    const app = appAuthTestApp(pem, tokenMap);
    const res = await app.request("/test", {
      headers: { Authorization: `Bearer ${await signAppJwt(42, pem)}` },
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { app: { appId: number; slug: string; name: string } };
    expect(body.app).toEqual({ appId: 42, slug: "my-app", name: "My App" });
  });

  it("sets authApp for a valid app JWT signed with a PKCS#1 key", async () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const pem = privateKey.export({ type: "pkcs1", format: "pem" }).toString();

    const app = appAuthTestApp(pem, tokenMap);
    const res = await app.request("/test", {
      headers: { Authorization: `Bearer ${await signAppJwt(42, pem)}` },
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { app: { appId: number } };
    expect(body.app?.appId).toBe(42);
  });

  it("does not set authApp for a JWT signed with a different key", async () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const { privateKey: otherKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const otherPem = otherKey.export({ type: "pkcs8", format: "pem" }).toString();

    const app = appAuthTestApp(pem, tokenMap);
    const res = await app.request("/test", {
      headers: { Authorization: `Bearer ${await signAppJwt(42, otherPem)}` },
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { app: unknown };
    expect(body.app).toBeNull();
  });
});

describe("requireAuth", () => {
  let tokenMap: TokenMap;

  beforeEach(() => {
    tokenMap = new Map();
    tokenMap.set("ok-token", { login: "alice", id: 1, scopes: [] });
  });

  it("returns 401 when authUser is not set", async () => {
    const app = new Hono<AppEnv>();
    app.use("*", authMiddleware(tokenMap));
    app.use("*", requireAuth());
    app.get("/protected", (c) => c.json({ ok: true }));

    const res = await app.request("/protected");

    expect(res.status).toBe(401);
    const body = (await res.json()) as { message: string; documentation_url: string };
    expect(body.message).toBe("Requires authentication");
    expect(body.documentation_url).toBe("https://emulate.dev");
  });

  it("passes through when authUser exists", async () => {
    const app = new Hono<AppEnv>();
    app.use("*", authMiddleware(tokenMap));
    app.use("*", requireAuth());
    app.get("/protected", (c) => c.json({ user: c.get("authUser") }));

    const res = await app.request("/protected", {
      headers: { Authorization: "Bearer ok-token" },
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { user: { login: string } };
    expect(body.user?.login).toBe("alice");
  });
});

describe("requireAppAuth", () => {
  it("returns 401 when authApp is not set", async () => {
    const app = new Hono<AppEnv>();
    app.use("*", requireAppAuth());
    app.get("/app-route", (c) => c.json({ ok: true }));

    const res = await app.request("/app-route");

    expect(res.status).toBe(401);
    const body = (await res.json()) as { message: string; documentation_url: string };
    expect(body.message).toBe("A JSON web token could not be decoded");
    expect(body.documentation_url).toBe("https://emulate.dev");
  });

  it("passes through when authApp exists", async () => {
    const app = new Hono<AppEnv>();
    app.use("*", async (c, next) => {
      c.set("authApp", { appId: 42, slug: "my-app", name: "My App" });
      await next();
    });
    app.use("*", requireAppAuth());
    app.get("/app-route", (c) => c.json({ app: c.get("authApp") }));

    const res = await app.request("/app-route");

    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      app: { appId: number; slug: string; name: string };
    };
    expect(body.app).toEqual({ appId: 42, slug: "my-app", name: "My App" });
  });
});
