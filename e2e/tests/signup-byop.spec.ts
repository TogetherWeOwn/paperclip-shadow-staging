import { test, expect } from '@playwright/test';
import { TESTIDS, uniqueTestEmail } from '../helpers/contract.js';
import { stagingBaseUrl } from '../helpers/access.js';
import {
  applyAccountToPage,
  completeByopWizard,
  tryMintTestAccount,
  type TestAccount,
} from '../helpers/accounts.js';

// Serial file: the signup test shares its account with the BYOP test so the
// wizard runs authenticated. Retries re-run a single test, so the BYOP test
// mints a fallback account when no shared one exists.
let sharedAccount: TestAccount | null = null;

// Golden path part 1: signup → BYOP wizard pointing at the synthetic NNTP
// endpoint. Each run mints a fresh account so reruns never collide.
//
// File-level skip: pre-deploy (no STAGING_BASE_URL) the whole file skips
// without launching a browser. See health.spec.ts.
test.skip(
  !process.env.STAGING_BASE_URL,
  'STAGING_BASE_URL not configured (pre-deploy) — see e2e/README.md.',
);

test.describe.serial('signup → BYOP wizard', () => {
  test('signup creates an account and lands on the BYOP wizard', async ({ page, request }) => {
    const baseURL = stagingBaseUrl('skip', 'signup');
    if (!baseURL) {
      test.skip(true, 'STAGING_BASE_URL not configured (pre-deploy) — see e2e/README.md.');
      return;
    }
    const minted = await tryMintTestAccount(request, baseURL);
    // Authenticate before the first navigation: the origin-scoped route
    // applies to subsequent loads only, so this must precede every goto.
    await applyAccountToPage(page, minted, baseURL);
    sharedAccount = minted;
    if (minted?.viaApi) {
      // API seam minted the account; the wizard must still be reachable.
      await page.goto(`${baseURL}/onboarding/byop`, {
        waitUntil: 'domcontentloaded',
        timeout: 30_000,
      });
      await expect(
        page.getByTestId(TESTIDS.byopHost),
        'BYOP wizard not reachable after API signup',
      ).toBeVisible({ timeout: 15_000 });
      return;
    }

    const email = uniqueTestEmail();
    await page.goto(`${baseURL}/signup`, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    await expect(page.getByTestId(TESTIDS.signupEmail)).toBeVisible({ timeout: 15_000 });
    await page.getByTestId(TESTIDS.signupEmail).fill(email);
    await page.getByTestId(TESTIDS.signupSubmit).click();
    // Either we land on the wizard, or an inline error explains why.
    const wizard = page.getByTestId(TESTIDS.byopHost);
    const error = page.getByTestId(TESTIDS.signupError);
    await expect(async () => {
      const onWizard = await wizard.isVisible().catch(() => false);
      const onError = await error.isVisible().catch(() => false);
      expect(onWizard || onError, 'neither BYOP wizard nor signup error appeared').toBe(true);
    }).toPass({ timeout: 30_000 });
    expect(await error.isVisible().catch(() => false), 'signup rejected the test mailbox').toBe(
      false,
    );
    expect(page.url()).toContain('/onboarding/byop');
  });

  test('BYOP wizard connects to the synthetic NNTP endpoint and saves', async ({
    page,
    request,
  }) => {
    const baseURL = stagingBaseUrl('skip', 'byop');
    if (!baseURL) {
      test.skip(true, 'STAGING_BASE_URL not configured (pre-deploy) — see e2e/README.md.');
      return;
    }
    // Prefer the signup test's account; mint a fallback on retry isolation.
    const account = sharedAccount ?? (await tryMintTestAccount(request, baseURL));
    await applyAccountToPage(page, account, baseURL);
    // Shared helper (also used by the ingest spec): connects the synthetic
    // endpoint, asserts test-connection success, saves into the library.
    // Fails closed when SYNTHETIC_NNTP_PASS is missing.
    await completeByopWizard(page, baseURL);
  });
});
