#!/usr/bin/env node

/**
 * Automated Dashboard GIF Recorder
 * Uses Puppeteer to automate browser interactions and puppeteer-recorder to create GIF
 */

const puppeteer = require('puppeteer');
const fs = require('fs');

const DASHBOARD_URL = 'http://localhost:9090';
const OUTPUT_DIR = './dashboard-recording';
const SCREENSHOT_INTERVAL = 100; // milliseconds between frames
const DURATION = 30000; // 30 seconds total

async function recordDashboard() {
    console.log('🎬 Starting automated dashboard recording...\n');

    // Create output directory
    if (!fs.existsSync(OUTPUT_DIR)) {
        fs.mkdirSync(OUTPUT_DIR);
    }

    console.log('📦 Launching browser...');
    const browser = await puppeteer.launch({
        headless: false, // Show browser so you can see what's happening
        defaultViewport: {
            width: 1280,
            height: 900
        }
    });

    const page = await browser.newPage();

    console.log('🌐 Navigating to dashboard:', DASHBOARD_URL);
    await page.goto(DASHBOARD_URL, { waitUntil: 'networkidle2' });

    console.log('⏳ Waiting for dashboard to load...');
    await page.waitForSelector('#totalClients', { timeout: 10000 });
    await page.waitForTimeout(2000); // Wait for initial data load

    console.log('📸 Starting screenshot capture...\n');
    console.log('Recording will demonstrate:');
    console.log('  1. Overview of metrics');
    console.log('  2. Hovering over charts');
    console.log('  3. Table pagination');
    console.log('  4. Live data refresh\n');

    let frameNumber = 0;
    const screenshots = [];

    // Helper function to capture frame
    async function captureFrame(description) {
        const filename = `${OUTPUT_DIR}/frame-${String(frameNumber).padStart(4, '0')}.png`;
        await page.screenshot({ path: filename });
        screenshots.push(filename);
        frameNumber++;
        if (description && frameNumber % 10 === 0) {
            process.stdout.write(`\r📸 Frame ${frameNumber}: ${description}...`);
        }
    }

    // Scene 1: Show overview (3 seconds)
    console.log('Scene 1: Overview...');
    for (let i = 0; i < 30; i++) {
        await captureFrame('Overview');
        await page.waitForTimeout(SCREENSHOT_INTERVAL);
    }

    // Scene 2: Hover over bar chart (4 seconds)
    console.log('\nScene 2: Hovering over bar chart...');
    const barChart = await page.$('#measurementChart');
    if (barChart) {
        const box = await barChart.boundingBox();
        if (box) {
            // Move mouse to chart
            await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
            for (let i = 0; i < 40; i++) {
                await captureFrame('Bar chart hover');
                await page.waitForTimeout(SCREENSHOT_INTERVAL);
            }
        }
    }

    // Scene 3: Hover over pie chart (4 seconds)
    console.log('\nScene 3: Hovering over pie chart...');
    const pieChart = await page.$('#proxyChart');
    if (pieChart) {
        const box = await pieChart.boundingBox();
        if (box) {
            await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
            for (let i = 0; i < 40; i++) {
                await captureFrame('Pie chart hover');
                await page.waitForTimeout(SCREENSHOT_INTERVAL);
            }
        }
    }

    // Scene 4: Scroll to table (2 seconds)
    console.log('\nScene 4: Scrolling to table...');
    await page.evaluate(() => {
        document.querySelector('#clientsTable').scrollIntoView({ behavior: 'smooth' });
    });
    for (let i = 0; i < 20; i++) {
        await captureFrame('Scroll to table');
        await page.waitForTimeout(SCREENSHOT_INTERVAL);
    }

    // Scene 5: Click Next button (3 seconds)
    console.log('\nScene 5: Clicking pagination...');
    const nextButton = await page.$('#nextPage');
    if (nextButton) {
        await nextButton.click();
        for (let i = 0; i < 30; i++) {
            await captureFrame('Page 2');
            await page.waitForTimeout(SCREENSHOT_INTERVAL);
        }

        // Click Previous
        const prevButton = await page.$('#prevPage');
        if (prevButton) {
            await prevButton.click();
            for (let i = 0; i < 30; i++) {
                await captureFrame('Back to page 1');
                await page.waitForTimeout(SCREENSHOT_INTERVAL);
            }
        }
    }

    // Scene 6: Show live refresh (remaining time)
    console.log('\nScene 6: Waiting for auto-refresh...');
    const remainingFrames = Math.floor((DURATION - frameNumber * SCREENSHOT_INTERVAL) / SCREENSHOT_INTERVAL);
    for (let i = 0; i < remainingFrames; i++) {
        await captureFrame('Live refresh');
        await page.waitForTimeout(SCREENSHOT_INTERVAL);
    }

    console.log(`\n\n✅ Captured ${frameNumber} frames`);
    console.log(`📁 Screenshots saved to: ${OUTPUT_DIR}/\n`);

    await browser.close();

    // Generate conversion command
    console.log('🎞️  To create GIF, run one of these commands:\n');

    console.log('Option 1: Using ffmpeg (high quality):');
    console.log(`  ffmpeg -framerate 10 -pattern_type glob -i '${OUTPUT_DIR}/frame-*.png' \\`);
    console.log(`    -vf "fps=10,scale=1024:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse" \\`);
    console.log(`    -loop 0 dashboard-demo.gif\n`);

    console.log('Option 2: Using ImageMagick (simpler):');
    console.log(`  convert -delay 10 -loop 0 ${OUTPUT_DIR}/frame-*.png dashboard-demo.gif\n`);

    console.log('Option 3: Using gifski (best quality):');
    console.log(`  gifski -o dashboard-demo.gif --fps 10 ${OUTPUT_DIR}/frame-*.png\n`);

    console.log('💡 Install tools:');
    console.log('  brew install ffmpeg imagemagick gifski\n');
}

// Run the recorder
recordDashboard().catch(error => {
    console.error('❌ Error:', error);
    process.exit(1);
});
