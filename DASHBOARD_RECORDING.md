# Creating a Dashboard Demo GIF

This guide will help you create an animated GIF demonstration of the Attestation Dashboard.

## Prerequisites

The dashboard must be running at `http://localhost:9090`. If not, start it with:

```bash
./run-cluster-demo.sh
```

## Quick Start

1. **Open the demo guide** (should already be open in your browser):
   ```bash
   open dashboard-demo.html
   ```

2. **Install a screen recording tool** (choose one):

   ### Option A: LICEcap (Recommended for GIF)
   ```bash
   brew install --cask licecap
   ```
   - Simple, lightweight, records directly to GIF
   - Good for small, focused recordings
   - File size: ~500KB - 2MB for 10-30 second clips

   ### Option B: Kap (Modern & Feature-Rich)
   ```bash
   brew install --cask kap
   ```
   - Modern UI, exports to GIF/MP4/WebM
   - Includes editing and trimming
   - Better quality, larger file sizes

   ### Option C: Built-in macOS Screenshot (Free)
   - Press `⌘ + Shift + 5`
   - Records to `.mov` file
   - Convert to GIF using online tool: https://cloudconvert.com/mov-to-gif

## Recording Steps

### 1. Prepare the Dashboard

```bash
# Open the dashboard
open "http://localhost:9090"

# Position your browser window to show:
# - All 4 metric cards at top
# - Both charts side-by-side
# - The attestation table with pagination controls
```

### 2. Generate Activity (Optional)

To show live data updates, run test clients in another terminal:

```bash
# Terminal 2: Run test clients
cd /Users/souravsarangi/go/src/github.com/cockroachdb/attested-tls-proxy-cockroach
go run tests/integration/helpers/testclient/connect_to_cluster.go
```

This will:
- Create 10 new attestation records
- Trigger dashboard auto-refresh (every 5 seconds)
- Update charts and table in real-time

### 3. Start Recording

**Using LICEcap:**
1. Launch LICEcap
2. Resize the recording frame to fit the dashboard
3. Set FPS to 10-15 (smaller file size)
4. Click "Record" and choose save location
5. Perform your demo actions (see below)
6. Click "Stop" when done

**Using Kap:**
1. Launch Kap
2. Click the record button
3. Select the area or window to record
4. Perform your demo actions
5. Click stop and export as GIF

**Using macOS Built-in:**
1. Press `⌘ + Shift + 5`
2. Choose "Record Selected Portion" or "Record Entire Screen"
3. Select the dashboard window
4. Click "Record"
5. Stop from menu bar
6. Convert `.mov` to `.gif` using CloudConvert

### 4. Demo Actions to Record

Demonstrate these features in order (~20-30 seconds total):

1. **Overview** (3 sec)
   - Show the full dashboard with all metrics

2. **Live Data** (5 sec)
   - Wait for "Last updated" timestamp to change
   - Show metrics updating in real-time

3. **Charts** (5 sec)
   - Hover over bar chart to show tooltip with measurement data
   - Hover over pie chart to show proxy node distribution

4. **Table Navigation** (10 sec)
   - Scroll through the attestation records table
   - Click "Next" button to go to page 2
   - Click "Previous" to return to page 1
   - Show page info updating (e.g., "Page 1 of 2")

5. **Data Details** (5 sec)
   - Hover over or highlight interesting fields:
     - Client ID
     - Measurement (truncated)
     - TCB Version
     - Verification result (allowed/denied)
     - Timestamp

## Recording Settings

### Recommended Settings for Small File Size
- **FPS:** 10-15 (smoother = larger file)
- **Duration:** 20-30 seconds max
- **Resolution:** 1280x720 or 1024x768
- **Target file size:** < 5 MB

### Recommended Settings for High Quality
- **FPS:** 24-30
- **Duration:** 30-60 seconds
- **Resolution:** 1920x1080
- **Format:** Record as MP4, then convert to optimized GIF

## Post-Processing

### Optimize GIF Size (if needed)

Using ImageMagick (install with `brew install imagemagick`):

```bash
# Reduce file size by decreasing colors and FPS
convert input.gif -fuzz 10% -layers Optimize output.gif

# Further optimization
gifsicle -O3 --colors 128 input.gif -o output.gif
```

Using ffmpeg (install with `brew install ffmpeg`):

```bash
# Convert MP4 to optimized GIF
ffmpeg -i recording.mov -vf "fps=10,scale=1024:-1:flags=lanczos" \
  -c:v palgif output.gif
```

### Online Optimization Tools
- https://ezgif.com/optimize (resize, optimize, crop)
- https://cloudconvert.com/gif-converter
- https://gifcompressor.com/

## Example Workflow

```bash
# 1. Ensure dashboard is running
curl http://localhost:9090 > /dev/null && echo "✓ Dashboard is running"

# 2. Open demo guide
open dashboard-demo.html

# 3. Install LICEcap (if not installed)
brew install --cask licecap

# 4. In another terminal, prepare to run test clients
# (Don't run yet - run during recording)

# 5. Start LICEcap recording

# 6. Open dashboard in browser
open "http://localhost:9090"

# 7. Wait 2 seconds, then run test clients
sleep 2 && go run tests/integration/helpers/testclient/connect_to_cluster.go

# 8. Demonstrate dashboard features for 20-30 seconds

# 9. Stop LICEcap recording

# 10. Save as: dashboard-demo.gif
```

## Troubleshooting

### Dashboard not loading?
```bash
# Check if dashboard is running
ps aux | grep dashboard | grep -v grep

# Check proxy nodes
curl http://localhost:8081/api/v1/stats/overview
curl http://localhost:8082/api/v1/stats/overview
curl http://localhost:8083/api/v1/stats/overview

# Restart if needed
./run-cluster-demo.sh
```

### No data showing?
```bash
# Run test clients to generate data
go run tests/integration/helpers/testclient/connect_to_cluster.go

# Check dashboard data
curl http://localhost:9090/api/aggregated | python3 -m json.tool
```

### GIF file too large?
- Reduce FPS (10 instead of 30)
- Reduce resolution (1024x768 instead of 1920x1080)
- Shorten duration (20 seconds instead of 60)
- Use fewer colors (128 instead of 256)
- Optimize with gifsicle or ezgif.com

## Sample Output

Your final GIF should demonstrate:
- ✓ Dashboard loads and displays metrics
- ✓ Charts render with data (bar chart and pie chart)
- ✓ Table shows attestation records
- ✓ Pagination works (Next/Previous buttons)
- ✓ Live data refresh (timestamp updates)
- ✓ Responsive UI interactions

Expected file size: **1-5 MB** for a 20-30 second recording at 10-15 FPS.

## Alternative: Create a Video Instead

If GIF file size is too large, consider creating an MP4 video:

```bash
# Record with macOS built-in (⌘ + Shift + 5)
# Or use QuickTime Player > File > New Screen Recording

# Result: smaller file size, better quality
# Example: 30-second MP4 = ~500KB vs 5MB GIF
```

You can embed MP4 in GitHub README with:
```markdown
https://user-images.githubusercontent.com/your-video.mp4
```

---

**Ready to record?** Open the demo guide and follow along:
```bash
open dashboard-demo.html
```
