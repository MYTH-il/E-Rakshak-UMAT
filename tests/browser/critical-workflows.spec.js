import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const password = "browser-verification-password";

async function login(page, role = "analyst") {
  await page.goto("/login");
  await page.getByLabel("Username").fill(`browser-${role}`);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Authenticate" }).click();
  await expect(page).toHaveURL(/\/cases$/);
}

async function expectAccessible(page) {
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations, JSON.stringify(results.violations, null, 2)).toEqual([]);
}

test("login, intake, duplicate confirmation, rerun, and cancellation", async ({ page }) => {
  await page.goto("/login");
  await expectAccessible(page);
  await page.getByLabel("Username").fill("browser-analyst");
  await page.getByLabel("Password").fill("incorrect-password");
  await page.getByRole("button", { name: "Authenticate" }).click();
  await expect(page.getByText("invalid username or password")).toBeVisible();

  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Authenticate" }).click();
  await expect(page).toHaveURL(/\/cases$/);
  await expect(page.locator('link[rel="stylesheet"]')).toHaveAttribute("href", "/assets/app.css?v=20260815.2");
  await expectAccessible(page);

  const upload = async (title) => {
    await page.goto("/submit");
    await page.getByLabel("Case title").fill(title);
    await page.getByLabel("Sample file").setInputFiles("tests/fixtures/case-object.json");
    await page.getByRole("button", { name: "Create case and analyze" }).click();
    await expect(page.getByRole("heading", { name: title })).toBeVisible();
  };

  await upload("Browser intake workflow");
  const firstCaseUrl = page.url();
  await expect(page.getByRole("button", { name: "Cancel run" })).toBeVisible();

  await upload("Browser duplicate workflow");
  await expect(page.getByText("Duplicate sample detected.")).toBeVisible();
  await page.getByRole("button", { name: "Confirm new analysis" }).click();
  await expect(page.getByText("Analysis confirmed and queued.")).toBeVisible();

  await page.goto(firstCaseUrl);
  await page.getByRole("button", { name: "Queue additional run" }).click();
  await expect(page.getByText("Additional run queued.")).toBeVisible();
  await page.getByRole("button", { name: "Cancel run" }).click();
  await expect(page.getByText("Cancellation requested.")).toBeVisible();
});

test("report selection and exports use the selected immutable report", async ({ page }) => {
  await login(page, "analyst");
  await page.getByLabel("Search title, reference, ID or headline").fill("BROWSER-REPORT");
  await page.getByRole("link", { name: /Browser report selection/ }).click();
  await expect(page.getByText("Second browser report")).toBeVisible();
  const caseId = page.url().split("/").pop();
  const firstRunId = await page.evaluate(async ({ selectedCaseId }) => {
    const detail = await fetch(`/api/v1/cases/${selectedCaseId}`).then((response) => response.json());
    for (const run of detail.analysis_runs) {
      const response = await fetch(`/api/v1/cases/${selectedCaseId}/report?run_id=${run.id}`);
      if (!response.ok) continue;
      const snapshot = await response.json();
      if (snapshot.report.headline === "First browser report") return run.id;
    }
    return null;
  }, { selectedCaseId: caseId });
  expect(firstRunId).not.toBeNull();
  await page.locator(".case-row").filter({ hasText: firstRunId }).getByRole("button", { name: "Show report" }).click();
  await expect(page.getByText("First browser report")).toBeVisible();
  await expectAccessible(page);

  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export JSON" }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toMatch(/^umat-report-.*\.json$/);
});

test("officer, analyst, and administrator controls are role-appropriate", async ({ page }) => {
  await login(page, "officer");
  await page.getByLabel("Search title, reference, ID or headline").fill("BROWSER-REPORT");
  await page.getByRole("link", { name: /Browser report selection/ }).click();
  await expect(page.getByRole("button", { name: "L2 Findings" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Run this sample again" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Users & roles" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Windows profiles" })).toHaveCount(0);

  await page.getByRole("button", { name: "Sign out" }).click();
  await login(page, "analyst");
  await page.getByLabel("Search title, reference, ID or headline").fill("BROWSER-REPORT");
  await page.getByRole("link", { name: /Browser report selection/ }).click();
  await expect(page.getByRole("button", { name: "L2 Findings" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Run this sample again" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Windows profiles" })).toHaveCount(0);

  await page.getByRole("button", { name: "Sign out" }).click();
  await login(page, "administrator");
  await expect(page.getByRole("link", { name: "Users & roles" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Windows profiles" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Android profiles" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Workers" })).toBeVisible();

  await page.getByRole("link", { name: "Users & roles" }).click();
  await expect(page.getByRole("heading", { name: "Users & roles", level: 2 })).toBeVisible();
  await expect(page.getByRole("button", { name: "Create user" })).toBeVisible();
  await page.getByRole("link", { name: "Windows profiles" }).click();
  await expect(page.getByRole("heading", { name: "Windows VM profiles", level: 2 })).toBeVisible();
  await page.getByRole("link", { name: "Android profiles" }).click();
  await expect(page.getByRole("heading", { name: "Android emulator profiles", level: 2 })).toBeVisible();
});

test("responsive rail keeps workspace navigation operable", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await login(page, "officer");
  const menu = page.getByRole("button", { name: "Menu" });
  await expect(menu).toHaveAttribute("aria-expanded", "false");
  await menu.click();
  await expect(menu).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByRole("navigation", { name: "Workspace" })).toBeVisible();
  await page.getByRole("link", { name: "Recent runs" }).click();
  await expect(page).toHaveURL(/\/runs$/);
  await expect(page.getByRole("heading", { name: "Recent runs", level: 2 })).toBeVisible();
  await expectAccessible(page);
});

test("operations console supports case changes, run diagnosis, retry, and worker inventory", async ({ page }) => {
  await login(page, "analyst");
  await page.getByRole("link", { name: "Recent runs" }).click();
  await page.getByLabel("Search case, reference, filename or SHA-256").fill("BROWSER-FAILED");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await expect(page.getByRole("link", { name: "Browser failed analysis" }).first()).toBeVisible();
  const failedRun = page.locator("section.card").filter({ has: page.getByRole("link", { name: "Browser failed analysis" }) }).first();
  await failedRun.getByText("Stage diagnostics").click();
  await expect(failedRun.locator("details .case-row").first()).toBeVisible();
  page.once("dialog", (dialog) => dialog.accept("browser verification retry"));
  await failedRun.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByText("Retry queued.")).toBeVisible();

  await page.getByLabel("Search case, reference, filename or SHA-256").fill("BROWSER-REPORT");
  await page.getByRole("button", { name: "Apply filters" }).click();
  await page.getByRole("link", { name: "Browser report selection" }).first().click();
  await page.getByLabel("Case reference").fill("BROWSER-REPORT-UPDATED");
  await page.getByRole("button", { name: "Save case metadata" }).click();
  await expect(page.getByText("Case metadata updated and audited.")).toBeVisible();
  await page.getByLabel("Additional sample").setInputFiles({
    name: "additional-browser.exe",
    mimeType: "application/octet-stream",
    buffer: Buffer.from("MZ unique browser additional submission"),
  });
  await page.getByRole("button", { name: "Add submission and analyze" }).click();
  await expect(page.getByText("Submission added and queued.")).toBeVisible();
  await expectAccessible(page);

  await page.getByRole("button", { name: "Sign out" }).click();
  await login(page, "administrator");
  await page.getByRole("link", { name: "Workers" }).click();
  await expect(page.getByRole("heading", { name: "Workers", level: 2 })).toBeVisible();
  await page.getByText("Capabilities and leases").first().click();
  const codeBlock = page.locator(".code-block").first();
  await expect(codeBlock).toBeVisible();
  await expect(codeBlock).toHaveCSS("white-space", "pre-wrap");
  await expect(codeBlock).toHaveCSS("overflow-wrap", "anywhere");
  await expectAccessible(page);
});
