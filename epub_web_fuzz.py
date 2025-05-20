import os
import shutil
import zipfile
import signal
import sys
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from playwright.sync_api import sync_playwright

# 配置路径
EPUB_GEN_ROOT = Path(r".\epub_gen_data\epub_gen")
CAPTURE_DIR = Path(r".\epub_gen_data\captured_payloads")
TEST_INTERFACE_URL = "http://localhost:8080/examples/input.html" #epub.js  npm start
MAX_WORKERS = 16  # 并行测试线程数
stop_requested = False

def signal_handler(sig, frame):
    global stop_requested
    print("\n🛑 检测到 Ctrl+C，正在安全关闭...\n")
    stop_requested = True

signal.signal(signal.SIGINT, signal_handler)

def test_epub_upload(epub_path: str):
    """测试单个EPUB文件并保存结果到对应目录，包括XSS和恶意链接检测"""
    if stop_requested:
        print(f"🛑 跳过文件 {epub_path}，因用户请求中止")
        return

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(accept_downloads=True)
        page = context.new_page()

        console_errors = []
        alert_messages = []
        external_requests = []  # 用于检测外部链接访问

        # 注册监听器
        page.on('console', lambda msg: console_errors.append(msg.text) if msg.type == 'error' else None)
        page.on('dialog', lambda dialog: (alert_messages.append(dialog.message), dialog.dismiss()))
        page.on('request', lambda req: external_requests.append(req.url) if not req.url.startswith(TEST_INTERFACE_URL) else None)

        try:
            print(f"🌐 正在访问测试页面: {TEST_INTERFACE_URL}")
            page.goto(TEST_INTERFACE_URL)

            # 上传EPUB文件
            print(f"📤 上传文件: {epub_path}")
            page.locator('#input').set_input_files(epub_path)
            page.wait_for_timeout(3000)

            # 1. XSS 弹窗检测
            if alert_messages:
                _save_evidence(epub_path, alert_messages, page,"alert_messages")

            # 2. JS 错误检测
            if console_errors:
                print(f"❌ 控制台错误 {epub_path}:")
                for err in console_errors:
                    print(f"   → {err}")
                _save_evidence(epub_path, console_errors, page, "console_errors")

            # 3. 恶意链接访问检测
            # malicious = [url for url in set(external_requests) if url and not url.startswith('http://localhost')]
            # if malicious:
            #     print(f"🚨 检测到外部请求 {epub_path}:")
            #     for url in malicious:
            #         print(f"   → {url}")

        except Exception as e:
            print(f"⚠️ 测试异常 {epub_path}: {e}")
        finally:
            context.close()
            browser.close()

def _save_evidence(epub_path: str, alert_messages: list, page, type=None):
    """保存弹窗截图和EPUB至与原始路径相同的上级结构，包括Text所在目录"""
    # 计算相对于EPUB_GEN_ROOT的路径
    relative = Path(epub_path).relative_to(EPUB_GEN_ROOT)
    # 提取上级目录两级结构
    parent_structure = relative.parent.parent / relative.parent.name
    dest_dir = CAPTURE_DIR / (type or 'unknown') / parent_structure
    dest_dir.mkdir(parents=True, exist_ok=True)
    # 构建目标文件路径
    dest_png = dest_dir / (relative.stem + '.png')
    dest_epub = dest_dir / relative.name
    dest_log = dest_dir / (relative.stem + '.log')

    # 保存截图
    page.screenshot(path=str(dest_png))
    print(f"🖼️ 截图保存: {dest_png}")
        # 复制整目录（EPUB及相关文件）
    parent_dir = Path(epub_path).parent
    target_dir = dest_dir / parent_dir.name
    shutil.copytree(parent_dir, target_dir)
    print(f"📦 目录复制: {target_dir}")
    # 保存日志
    with open(dest_log, 'w', encoding='utf-8') as f:
        for msg in alert_messages:
            f.write(f"{msg}\n")
    print(f"📝 日志保存: {dest_log}")


def main():
    EPUB_GEN_ROOT.mkdir(parents=True, exist_ok=True)
    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

    epub_files = list(EPUB_GEN_ROOT.rglob('*.epub'))
    print(f"🔍 共发现 {len(epub_files)} 个 EPUB 待测试")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_epub_upload, str(path)): path for path in epub_files}
        try:
            for fut in as_completed(futures):
                path = futures[fut]
                if stop_requested:
                    break
                try:
                    fut.result()
                except Exception as e:
                    print(f"❗ 并行测试出错 {path}: {e}")
        except KeyboardInterrupt:
            print("🛑 用户中断，终止测试...")

if __name__ == '__main__':
    main()
