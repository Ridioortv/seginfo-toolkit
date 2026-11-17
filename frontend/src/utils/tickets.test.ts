import { describe, expect, it } from "vitest";
import { buildTicketingConfig, hasActiveTicket, ticketErrorText, webhookUrl, type TicketLink } from "./tickets";

const link = (state: TicketLink["state"]) => ({ state } as TicketLink);
const base = { provider: "jira" as const, baseUrl: " https://acme.atlassian.net ", email: " bot@acme.com ", username: "", secret: "tok", projectKey: " SEC ",
  issueType: "", table: "", priorities: { critical: "Highest", high: "", medium: "Medium" }, notifyChannelIds: [] as string[] };

describe("tickets helpers", () => {
  it("knows when a ticket is still in progress", () => {
    expect(hasActiveTicket([])).toBe(false);
    expect(hasActiveTicket([link("resolved"), link("closed_no_fix")])).toBe(false);
    expect(hasActiveTicket([link("resolved"), link("open")])).toBe(true);
    expect(hasActiveTicket([link("simulated")])).toBe(true);
  });

  it("reads the API error either as text or as an object", () => {
    expect(ticketErrorText("Ya hay un ticket", "x")).toBe("Ya hay un ticket");
    expect(ticketErrorText({ message: "Ya hay un ticket abierto", link_id: "1" }, "x")).toBe("Ya hay un ticket abierto");
    expect(ticketErrorText(undefined, "No se pudo")).toBe("No se pudo");
  });

  it("builds a Jira config without empty priorities and with defaults", () => {
    expect(buildTicketingConfig(base)).toEqual({ provider: "jira", base_url: "https://acme.atlassian.net", email: "bot@acme.com", api_token: "tok",
      project_key: "SEC", issue_type: "Task", priority_map: { critical: "Highest", medium: "Medium" } });
  });

  it("builds a ServiceNow config and includes chat channels only when chosen", () => {
    const c = buildTicketingConfig({ ...base, provider: "servicenow", username: " tero ", notifyChannelIds: ["c1"] });
    expect(c).toEqual({ provider: "servicenow", base_url: "https://acme.atlassian.net", username: "tero", api_token: "tok", table: "incident", notify_channel_ids: ["c1"] });
    expect(c).not.toHaveProperty("email");
  });

  it("joins the webhook URL without double slashes", () => {
    expect(webhookUrl("https://tero.acme.com:8011/", "/public/ticket-webhooks/a/b")).toBe("https://tero.acme.com:8011/public/ticket-webhooks/a/b");
  });
});
