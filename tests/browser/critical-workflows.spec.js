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
  await page.getByRole("button", { name: "Show report" }).last().click();
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
  await expect(page.getByRole("link", { name: "Windows profiles" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Android profiles" })).toBeVisible();
});
