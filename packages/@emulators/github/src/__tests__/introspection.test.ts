import { describe, it, expect } from "vitest";
import { Hono } from "@emulators/core";
import { Store, WebhookDispatcher } from "@emulators/core";
import { authMiddleware, createApiErrorHandler, createErrorHandler, type AppEnv, type TokenMap } from "@emulators/core";
import { githubPlugin, seedFromConfig } from "../index.js";

const base = "http://localhost:4000";

function createTestApp(seedConfig?: Parameters<typeof seedFromConfig>[2]) {
  const store = new Store();
  const webhooks = new WebhookDispatcher();
  const tokenMap: TokenMap = new Map();
  tokenMap.set("test-token", { login: "octocat", id: 1, scopes: ["repo", "user", "admin:org"] });

  const app = new Hono<AppEnv>();
  app.onError(createApiErrorHandler());
  app.use("*", createErrorHandler());
  app.use("*", authMiddleware(tokenMap));
  // App JWT verification requires an appKeyResolver wired by the server, so set authApp directly.
  app.use("*", async (c, next) => {
    const appId = c.req.header("X-Test-App-Id");
    if (appId) {
      c.set("authApp", { appId: parseInt(appId, 10), slug: "test-app", name: "Test App" });
    }
    await next();
  });
  githubPlugin.register(app, store, webhooks, base, tokenMap);
  githubPlugin.seed?.(store, base);
  seedFromConfig(
    store,
    base,
    seedConfig ?? {
      users: [{ login: "octocat" }],
      repos: [{ owner: "octocat", name: "hello-world" }],
    },
  );

  return { app, store, webhooks, tokenMap };
}

function authHeaders(): Record<string, string> {
  return { Authorization: "Bearer test-token" };
}

function seedWithApp(): Parameters<typeof seedFromConfig>[2] {
  return {
    users: [{ login: "octocat" }],
    repos: [
      { owner: "octocat", name: "hello-world" },
      { owner: "octocat", name: "other-repo" },
    ],
    apps: [
      {
        app_id: 100,
        slug: "test-app",
        name: "Test App",
        private_key: "fake-key",
        permissions: { contents: "read" },
        events: ["push"],
        installations: [
          {
            installation_id: 42,
            account: "octocat",
            repository_selection: "selected",
            repositories: ["hello-world"],
          },
        ],
      },
    ],
  };
}

describe("state introspection", () => {
  it("reflects an installation token mint immediately", async () => {
    const { app } = createTestApp(seedWithApp());

    let res = await app.request(`${base}/_emulate/github/state`, { method: "GET" });
    expect(res.status).toBe(200);
    let state = (await res.json()) as { installation_tokens: unknown[] };
    expect(state.installation_tokens).toEqual([]);

    const repoRes = await app.request(`${base}/repos/octocat/hello-world`, {
      method: "GET",
      headers: authHeaders(),
    });
    const repo = (await repoRes.json()) as { id: number };

    const mintRes = await app.request(`${base}/app/installations/42/access_tokens`, {
      method: "POST",
      headers: { "X-Test-App-Id": "100", "Content-Type": "application/json" },
      body: JSON.stringify({ repository_ids: [repo.id] }),
    });
    expect(mintRes.status).toBe(201);
    const minted = (await mintRes.json()) as { token: string; repositories: Array<{ id: number }> };
    expect(minted.token).toMatch(/^ghs_/);
    expect(minted.repositories.map((r) => r.id)).toEqual([repo.id]);

    res = await app.request(`${base}/_emulate/github/state`, { method: "GET" });
    expect(res.status).toBe(200);
    state = (await res.json()) as { installation_tokens: unknown[] };
    expect(state.installation_tokens).toHaveLength(1);

    const mint = state.installation_tokens[0] as {
      token: string;
      installation_id: number;
      app_id: number;
      permissions: Record<string, string>;
      repository_ids: number[];
      created_at: string;
      expires_at: string;
    };
    expect(mint.token).toBe(minted.token);
    expect(mint.installation_id).toBe(42);
    expect(mint.app_id).toBe(100);
    expect(mint.permissions).toEqual({ contents: "read" });
    expect(mint.repository_ids).toEqual([repo.id]);
    expect(mint.created_at).toBeTruthy();
    expect(mint.expires_at).toBeTruthy();
  });

  it("scopes minted tokens to repository ids that match the repo routes", async () => {
    const { app } = createTestApp(seedWithApp());

    const byName = await app.request(`${base}/repos/octocat/hello-world`, {
      method: "GET",
      headers: authHeaders(),
    });
    const named = (await byName.json()) as { id: number; full_name: string };

    const byId = await app.request(`${base}/repositories/${named.id}`, {
      method: "GET",
      headers: authHeaders(),
    });
    expect(byId.status).toBe(200);
    const idRepo = (await byId.json()) as { id: number; full_name: string };
    expect(idRepo.id).toBe(named.id);
    expect(idRepo.full_name).toBe(named.full_name);

    const mintRes = await app.request(`${base}/app/installations/42/access_tokens`, {
      method: "POST",
      headers: { "X-Test-App-Id": "100", "Content-Type": "application/json" },
      body: JSON.stringify({ repository_ids: [named.id] }),
    });
    expect(mintRes.status).toBe(201);
    const minted = (await mintRes.json()) as { repositories: Array<{ id: number; full_name: string }> };
    expect(minted.repositories).toHaveLength(1);
    expect(minted.repositories[0]!.id).toBe(named.id);
    expect(minted.repositories[0]!.full_name).toBe("octocat/hello-world");

    const stateRes = await app.request(`${base}/_emulate/github/state`, { method: "GET" });
    const state = (await stateRes.json()) as { installation_tokens: Array<{ repository_ids: number[] }> };
    expect(state.installation_tokens[0]!.repository_ids).toEqual([named.id]);
  });
});
