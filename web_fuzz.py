from playwright.sync_api import sync_playwright
import pytest
import faker
import random
import zipfile
import os

# 模糊测试数据生成器
def generate_fuzz_cases():

    return True


def extract_epub(epub_path, extract_dir):
    with zipfile.ZipFile(epub_path, 'r') as epub_zip:
        epub_zip.extractall(extract_dir)
    return {
        "opf_files": [f for f in os.listdir(extract_dir) if f.endswith('.opf')],
        "html_files": [f for f in os.listdir(extract_dir) if f.endswith('.html')],
        "svg_files": [f for f in os.listdir(extract_dir) if f.endswith('.svg')],
        "image_files": [f for f in os.listdir(extract_dir) if f.split('.')[-1] in ('png', 'jpg', 'gif')]
    }

def intercept_requests(route, request):
    # 记录可疑请求特征
    danger_patterns = ["../", "<script>", "UNION SELECT"]
    if any(p in request.url for p in danger_patterns):
        print(f"[!] 检测到可疑请求: {request.url}")
        route.abort()  # 拦截请求
    else:
        route.continue_()

def handle_dialog(dialog):
    print(f"[!] 出现弹窗警报: {dialog.message}")
    dialog.accept()

def test_epub_reader_fuzzing():
    with sync_playwright() as p:
        # 启动Chromium无头浏览器
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(accept_downloads=True)
        page = context.new_page()
        
        # 设置请求拦截和弹窗处理
        page.route("**/*", intercept_requests)
        page.on("dialog", handle_dialog)

        # 访问目标网页
        page.goto("https://your-epub-reader-url.com")

        # 执行文件上传模糊测试
        for case in generate_fuzz_cases():
            try:
                # 定位上传元素（根据实际页面调整选择器）
                with page.expect_file_chooser() as fc_info:
                    page.click("#upload-button")
                file_chooser = fc_info.value
                
                # 上传测试文件（需提前准备测试用例文件）
                file_chooser.set_files(case if case else "")
                
                # 等待处理完成（根据实际页面调整）
                page.wait_for_timeout(2000)
                
                # 检查错误提示（根据实际页面元素调整）
                error_msg = page.query_selector(".error-message")
                if error_msg:
                    print(f"[+] 触发有效防御：{case}")

            except Exception as e:
                print(f"[!] 异常崩溃：{case} | 错误：{str(e)}")

        # 网络漏洞检测
        def check_response(response):
            if response.status >= 400:
                print(f"[!] 错误响应 {response.status}：{response.url}")
            if "password" in response.text().lower():
                print(f"[!] 检测到敏感信息泄露：{response.url}")

        page.on("response", check_response)

        # 关闭浏览器
        context.close()
        browser.close()

if __name__ == "__main__":
    pytest.main(["-s", "test_epub_reader.py"])