import { expect, test } from "@playwright/test";

/**
 * REQ-UI-002, REQ-UI-003, REQ-UI-004 — panel smoke against running compose.
 * Requires stack at BASE_URL and an admin account.
 */
const adminEmail = process.env.E2E_ADMIN_EMAIL || "admin@example.com";
const adminPass = process.env.E2E_ADMIN_PASS || "super-secret-12";

test.describe("P01 panel smoke", () => {
  test("login, switch language, open hosts and config", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByRole("heading")).toBeVisible();

    // i18n (REQ-UI-002)
    await page.getByLabel(/Dil|Language/i).selectOption("en");
    await expect(page.getByRole("button", { name: /Sign in|Initial admin/i })).toBeVisible();
    await page.getByLabel(/Dil|Language/i).selectOption("tr");

    await page.getByLabel(/E-posta|Email/i).fill(adminEmail);
    await page.getByLabel(/Parola|Password/i).fill(adminPass);
    await page.getByRole("button", { name: /Giriş|Sign in|Kurulum|Initial/i }).click();

    // Dashboard may be home; hosts UI is at /hosts (REQ-UI-003)
    await page.locator(".side-nav").getByRole("link", { name: /Proxy host/i }).click();
    await expect(page.locator("main").getByRole("heading", { name: /Proxy host/i })).toBeVisible({
      timeout: 15_000,
    });

    // Create host form visible (REQ-UI-003)
    await expect(page.locator("#domain")).toBeVisible();
    const domain = `e2e-${Date.now()}.example.com`;
    await page.locator("#domain").fill(domain);
    await page.locator("#uphost").fill("example.com");
    await page.getByRole("button", { name: /Kaydet|Save/i }).click();
    await expect(page.getByRole("cell", { name: domain })).toBeVisible({ timeout: 10_000 });

    // Config page (REQ-UI-004)
    await page.locator(".side-nav").getByRole("link", { name: /Konfigürasyon|Configuration/i }).click();
    await expect(page.getByRole("button", { name: /Doğrula|Validate/i })).toBeVisible();
    await page.getByRole("button", { name: /Doğrula|Validate/i }).click();
    await expect(page.locator(".ok, .error").first()).toBeVisible({ timeout: 15_000 });
  });
});
