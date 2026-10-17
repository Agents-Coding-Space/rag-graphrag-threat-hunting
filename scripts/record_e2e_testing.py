"""Automated end-to-end browser testing and screen video recording with Playwright."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import time
from playwright.sync_api import sync_playwright


ROOT = Path(__file__).resolve().parents[1]
VIDEOS_DIR = ROOT / "outputs/videos"
DOCS_VIDEOS_DIR = ROOT / "docs/videos"


def record_test(video_filename: str = "e2e_test_recording_v2_upgraded.webm") -> Path:
    VIDEOS_DIR.mkdir(parents=True, exist_ok=True)
    DOCS_VIDEOS_DIR.mkdir(parents=True, exist_ok=True)

    target_video_path = VIDEOS_DIR / video_filename
    temp_video_dir = VIDEOS_DIR / f"temp_{int(time.time())}"
    temp_video_dir.mkdir(parents=True, exist_ok=True)

    print(f"🎬 Starting Playwright automated testing and video recording -> {video_filename}...")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            record_video_dir=str(temp_video_dir),
            record_video_size={"width": 1366, "height": 768},
            viewport={"width": 1366, "height": 768},
        )
        page = context.new_page()

        # 1. Navigate to SOC Dashboard
        print("1. Navigating to http://127.0.0.1:5173/...")
        page.goto("http://127.0.0.1:5173/")
        page.wait_for_selector("main", timeout=15000)
        time.sleep(2)

        # 2. Test switching scenarios (MSHTA -> PurpleSharp -> Regsvr32 -> MSHTA)
        print("2. Testing scenario switching (MSHTA -> PurpleSharp -> Regsvr32)...")
        combobox = page.locator("select")
        combobox.select_option("purplesharp-ad")
        time.sleep(2)

        combobox.select_option("regsvr32-c2")
        time.sleep(2)

        combobox.select_option("mshta-powershell")
        time.sleep(1.5)

        # 3. Test graph controls
        print("3. Testing Cytoscape graph controls (Zoom In, Zoom Out, Fit)...")
        page.locator('button[title="Phóng to"]').click()
        time.sleep(0.5)
        page.locator('button[title="Phóng to"]').click()
        time.sleep(0.5)
        page.locator('button[title="Thu nhỏ"]').click()
        time.sleep(0.5)
        page.locator('button[title="Toàn cảnh"]').click()
        time.sleep(1)

        # 4. Test exact user query with typo: "Có kỹ thuật MITRE ATT$CK nào trong kia"
        print("4. Testing exact user query: 'Có kỹ thuật MITRE ATT$CK nào trong kia'...")
        input_box = page.locator('input[type="text"]')
        input_box.fill("Có kỹ thuật MITRE ATT$CK nào trong kia")
        time.sleep(1)
        page.locator('button[type="submit"]').click()
        time.sleep(4)

        # Verify Gate PASSED
        passed_badge = page.locator('text="Gate: PASSED"')
        assert passed_badge.count() > 0, "Gate must pass for MITRE query"
        print("   ✅ Gate PASSED for user MITRE query!")

        # 5. Test unrelated query to verify defensive rejection
        print("5. Submitting unrelated query to verify defensive gate rejection...")
        input_box.fill("Thời tiết ngày mai ở Hà Nội thế nào?")
        time.sleep(1)
        page.locator('button[type="submit"]').click()
        time.sleep(3)

        rejected_badge = page.locator('text="Truy vấn bị từ chối bởi Two-Stage Gate"')
        assert rejected_badge.count() > 0, "Gate must reject unrelated query"
        print("   ✅ Gate correctly rejected unrelated query!")

        # 6. Test theme switching (Dark -> Light -> Dark)
        print("6. Testing Theme switching (Dark -> Light -> Dark)...")
        theme_btn = page.locator('button[title*="Chuyển sang Giao diện"]')
        theme_btn.click()
        time.sleep(2)
        theme_btn.click()
        time.sleep(1.5)

        # 7. Test Export Markdown report
        print("7. Testing Export Markdown Report button...")
        export_btn = page.locator('button[title*="Xuất MD"]')
        if export_btn.count() > 0:
            export_btn.first.click()
            time.sleep(1)

        time.sleep(2)

        # Close page & context to flush video file
        page_video = page.video
        page.close()
        context.close()
        browser.close()

        # Locate generated video file
        if page_video:
            recorded_path = Path(page_video.path())
            if recorded_path.is_file():
                shutil.copy2(recorded_path, target_video_path)
                shutil.copy2(recorded_path, DOCS_VIDEOS_DIR / video_filename)
                print(f"✅ Video recorded successfully: {target_video_path} ({target_video_path.stat().st_size / 1024:.1f} KB)")
                shutil.rmtree(temp_video_dir, ignore_errors=True)
                return target_video_path

    raise RuntimeError("Failed to capture video recording")


if __name__ == "__main__":
    import sys
    name = sys.argv[1] if len(sys.argv) > 1 else "e2e_test_recording_v2_upgraded.webm"
    out_path = record_test(name)
    print(f"Completed video recording: {out_path}")
