import type { RouteContext } from "@emulators/core";
import { getGitHubStore } from "../store.js";

export function introspectionRoutes({ app, store }: RouteContext): void {
  const gh = getGitHubStore(store);

  app.get("/_emulate/github/state", (c) => {
    return c.json({
      installation_tokens: gh.installationTokens.all().map((t) => ({
        token: t.token,
        installation_id: t.installation_id,
        app_id: t.app_id,
        permissions: t.permissions,
        repository_selection: t.repository_selection,
        repository_ids: t.repository_ids,
        expires_at: t.expires_at,
        created_at: t.created_at,
      })),
    });
  });
}
