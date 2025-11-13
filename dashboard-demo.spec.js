const { test, expect } = require('@playwright/test');

test('Dashboard Demo Recording', async ({ page }) => {
  // Set viewport size optimized for GitHub README display
  await page.setViewportSize({ width: 1000, height: 800 });

  console.log('🌐 Navigating to dashboard...');
  await page.goto('http://localhost:8081');

  console.log('⏳ Waiting for dashboard to load...');
  // Wait for dashboard title and data to load
  await page.waitForSelector('h1:has-text("Cluster Attestation Dashboard")', { timeout: 10000 });
  await page.waitForSelector('text=Total Clients', { timeout: 10000 });
  await page.waitForTimeout(2000);

  console.log('📊 Scene 1: Overview - showing metrics (3 seconds)');
  await page.waitForTimeout(3000);

  console.log('🖱️  Scene 2: Hovering over Denial Reasons bars (4 seconds)');
  // Hover over different bars in the Denial Reasons chart to show tooltips
  const denialBars = await page.locator('.recharts-bar-rectangle').all();
  if (denialBars.length > 0) {
    await denialBars[0].hover();
    await page.waitForTimeout(1500);
    if (denialBars.length > 1) {
      await denialBars[1].hover();
      await page.waitForTimeout(1500);
    }
  }
  await page.waitForTimeout(1000);

  console.log('🖱️  Scene 3: Hovering over pie chart slices (3 seconds)');
  const pieSlices = await page.locator('.recharts-pie-sector').all();
  if (pieSlices.length > 0) {
    await pieSlices[0].hover();
    await page.waitForTimeout(1500);
    if (pieSlices.length > 1) {
      await pieSlices[1].hover();
      await page.waitForTimeout(1500);
    }
  }

  console.log('📜 Scene 4: Scrolling to attestation records table (2 seconds)');
  await page.evaluate(() => {
    window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
  });
  await page.waitForTimeout(2000);

  console.log('🖱️  Scene 5: Hovering over DENIED status to show tooltip (3 seconds)');
  const deniedStatus = await page.locator('.bg-red-100').first();
  if (await deniedStatus.isVisible()) {
    await deniedStatus.hover();
    await page.waitForTimeout(3000);
  }

  console.log('👆 Scene 6: Clicking Next button for pagination (2 seconds)');
  const nextButton = await page.getByRole('button', { name: 'Next' });
  if (await nextButton.isEnabled()) {
    await nextButton.click();
    await page.waitForTimeout(2000);
  }

  console.log('📊 Scene 7: Scrolling back to top (2 seconds)');
  await page.evaluate(() => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
  await page.waitForTimeout(2000);

  console.log('✅ Demo complete!');
});
