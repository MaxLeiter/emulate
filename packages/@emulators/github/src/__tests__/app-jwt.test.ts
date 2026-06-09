import { createPrivateKey, generateKeyPairSync } from "crypto";
import { describe, it, expect } from "vitest";
import { SignJWT } from "jose";
import { Hono } from "@emulators/core";
import { Store, WebhookDispatcher } from "@emulators/core";
import { authMiddleware, createApiErrorHandler, createErrorHandler, type AppEnv, type TokenMap } from "@emulators/core";
import { githubPlugin, seedFromConfig, getGitHubStore } from "../index.js";

const base = "http://localhost:4000";

const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const privateKeyPem = privateKey.export({ type: "pkcs1", format: "pem" }).toString();

async function appJwt(appId: number, pem: string): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(String(appId))
    .setIssuedAt()
    .setExpirationTime("9m")
    .sign(createPrivateKey(pem));
}

function createTestApp() {
  const store = new Store();
  const webhooks = new WebhookDispatcher();
  const tokenMap: TokenMap = new Map();

  const app = new Hono<AppEnv>();
  app.onError(createApiErrorHandler());
  app.use("*", createErrorHandler());
  app.use(
    "*",
    authMiddleware(tokenMap, (appId) => {
      const gh = getGitHubStore(store);
      const ghApp = gh.apps.all().find((a) => a.app_id === appId);
      if (!ghApp) return null;
      return { privateKey: ghApp.private_key, slug: ghApp.slug, name: ghApp.name };
    }),
  );
  githubPlugin.register(app, store, webhooks, base, tokenMap);
  githubPlugin.seed?.(store, base);
  seedFromConfig(store, base, {
    users: [{ login: "octocat" }],
    repos: [{ owner: "octocat", name: "hello-world" }],
    apps: [
      {
        app_id: 12345,
        slug: "jwt-app",
        name: "JWT App",
        private_key: privateKeyPem,
        permissions: { contents: "read" },
        events: ["push"],
        installations: [
          {
            installation_id: 7,
            account: "octocat",
            repository_selection: "all",
          },
        ],
      },
    ],
  });

  return { app, store, webhooks, tokenMap };
}

describe("GitHub App JWT auth", () => {
  it("authenticates the app from a signed JWT", async () => {
    const { app } = createTestApp();
    const jwt = await appJwt(12345, privateKeyPem);

    const res = await app.request(`${base}/app`, {
      method: "GET",
      headers: { Authorization: `Bearer ${jwt}` },
    });

    expect(res.status).toBe(200);
    const body = (await res.json()) as { id: number; slug: string };
    expect(body.id).toBe(12345);
    expect(body.slug).toBe("jwt-app");
  });

  it("mints an installation token from a signed JWT and accepts it on the API", async () => {
    const { app } = createTestApp();
    const jwt = await appJwt(12345, privateKeyPem);

    const mintRes = await app.request(`${base}/app/installations/7/access_tokens`, {
      method: "POST",
      headers: { Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    expect(mintRes.status).toBe(201);
    const minted = (await mintRes.json()) as { token: string };
    expect(minted.token).toMatch(/^ghs_/);

    const userRes = await app.request(`${base}/user`, {
      method: "GET",
      headers: { Authorization: `Bearer ${minted.token}` },
    });

    expect(userRes.status).toBe(200);
    const user = (await userRes.json()) as { login: string };
    expect(user.login).toBe("octocat");
  });

  it("rejects a JWT signed with a different key", async () => {
    const { app } = createTestApp();
    const { privateKey: otherKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const otherPem = otherKey.export({ type: "pkcs8", format: "pem" }).toString();
    const jwt = await appJwt(12345, otherPem);

    const res = await app.request(`${base}/app/installations/7/access_tokens`, {
      method: "POST",
      headers: { Authorization: `Bearer ${jwt}`, "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });

    expect(res.status).toBe(401);
  });
});
