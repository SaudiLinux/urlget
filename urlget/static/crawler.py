#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import logging
from urllib.parse import urljoin, urlparse
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
from colorama import Fore, Style
from tqdm import tqdm

from urlget.utils import setup_logger

class ChromeCrawler:
    """فئة للزحف القائم على Chrome للعثور على نقاط الضعف في تطبيقات الويب"""
    
    def __init__(self, url, depth=2, login_enabled=False, username=None, password=None, verbose=False):
        """تهيئة الزاحف"""
        self.url = url
        self.depth = depth
        self.login_enabled = login_enabled
        self.username = username
        self.password = password
        self.verbose = verbose
        
        # إعداد السجل
        self.logger = setup_logger("ChromeCrawler", level=logging.DEBUG if verbose else logging.INFO)
        
        # قوائم لتخزين البيانات
        self.visited_urls = set()
        self.forms = []
        self.links = []
        self.resources = []
        
        # إعداد متصفح Chrome
        self.driver = None
        
    def setup_driver(self):
        """إعداد متصفح Chrome"""
        self.logger.info("إعداد متصفح Chrome...")
        
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        
        try:
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            self.logger.info("تم إعداد متصفح Chrome بنجاح")
        except Exception as e:
            self.logger.error(f"فشل في إعداد متصفح Chrome: {str(e)}")
            raise
    
    def login(self):
        """تسجيل الدخول إلى الموقع إذا تم تمكين هذه الميزة"""
        if not self.login_enabled or not self.username or not self.password:
            return False
        
        self.logger.info("محاولة تسجيل الدخول...")
        
        try:
            # هذه مجرد محاولة عامة للتسجيل، قد تحتاج إلى تخصيصها حسب الموقع
            self.driver.get(self.url)
            
            # البحث عن حقول تسجيل الدخول
            username_field = self.driver.find_element(By.XPATH, "//input[@type='text' or @type='email']")
            password_field = self.driver.find_element(By.XPATH, "//input[@type='password']")
            submit_button = self.driver.find_element(By.XPATH, "//button[@type='submit'] | //input[@type='submit']")
            
            # ملء النموذج وإرساله
            username_field.send_keys(self.username)
            password_field.send_keys(self.password)
            submit_button.click()
            
            # انتظار تحميل الصفحة
            time.sleep(3)
            
            self.logger.info("تم تسجيل الدخول بنجاح")
            return True
            
        except Exception as e:
            self.logger.error(f"فشل في تسجيل الدخول: {str(e)}")
            return False
    
    def extract_links(self, url):
        """استخراج الروابط من صفحة الويب"""
        self.logger.debug(f"استخراج الروابط من: {url}")
        
        try:
            self.driver.get(url)
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # الحصول على محتوى HTML
            page_source = self.driver.page_source
            soup = BeautifulSoup(page_source, 'lxml')
            
            # استخراج الروابط
            base_url = "{0.scheme}://{0.netloc}".format(urlparse(url))
            links = []
            
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                full_url = urljoin(base_url, href)
                
                # تجاهل الروابط الخارجية والروابط الخاصة
                if urlparse(full_url).netloc == urlparse(base_url).netloc and not full_url.startswith(('javascript:', 'mailto:', 'tel:')):
                    links.append(full_url)
            
            # استخراج النماذج
            forms = []
            for form in soup.find_all('form'):
                form_data = {
                    'action': urljoin(base_url, form.get('action', '')),
                    'method': form.get('method', 'get').upper(),
                    'inputs': []
                }
                
                for input_field in form.find_all(['input', 'textarea', 'select']):
                    input_data = {
                        'name': input_field.get('name', ''),
                        'type': input_field.get('type', 'text'),
                        'value': input_field.get('value', '')
                    }
                    form_data['inputs'].append(input_data)
                
                forms.append(form_data)
            
            return links, forms
            
        except TimeoutException:
            self.logger.warning(f"انتهت مهلة تحميل الصفحة: {url}")
            return [], []
        except WebDriverException as e:
            self.logger.error(f"خطأ في متصفح الويب: {str(e)}")
            return [], []
        except Exception as e:
            self.logger.error(f"خطأ أثناء استخراج الروابط: {str(e)}")
            return [], []
    
    def crawl(self, url, current_depth=0):
        """زحف الموقع بشكل متكرر"""
        if current_depth > self.depth or url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        self.logger.info(f"زحف: {url} (العمق: {current_depth}/{self.depth})")
        
        links, forms = self.extract_links(url)
        
        # إضافة النماذج المكتشفة
        for form in forms:
            if form not in self.forms:
                self.forms.append(form)
                if self.verbose:
                    self.logger.debug(f"تم العثور على نموذج: {form['action']} ({form['method']})")
        
        # إضافة الروابط المكتشفة
        for link in links:
            if link not in self.links:
                self.links.append(link)
        
        # زحف الروابط بشكل متكرر
        for link in links:
            if link not in self.visited_urls:
                self.crawl(link, current_depth + 1)
    
    def analyze_security(self):
        """تحليل الموقع للبحث عن مشكلات أمنية محتملة"""
        self.logger.info("تحليل الموقع للبحث عن مشكلات أمنية...")
        
        security_issues = []
        
        # فحص النماذج للبحث عن مشكلات أمنية
        for form in self.forms:
            # التحقق من طريقة النموذج
            if form['method'] == 'GET' and any(input_field['type'] == 'password' for input_field in form['inputs']):
                issue = f"نموذج يستخدم طريقة GET مع حقل كلمة مرور: {form['action']}"
                security_issues.append(issue)
                self.logger.warning(issue)
            
            # التحقق من وجود حقول مخفية
            hidden_inputs = [input_field for input_field in form['inputs'] if input_field['type'] == 'hidden']
            if hidden_inputs:
                issue = f"نموذج يحتوي على {len(hidden_inputs)} حقول مخفية: {form['action']}"
                security_issues.append(issue)
                self.logger.debug(issue)
        
        return security_issues
    
    def start(self):
        """بدء عملية الزحف"""
        print(f"{Fore.GREEN}[+] بدء الزحف باستخدام Chrome...{Style.RESET_ALL}")
        
        try:
            self.setup_driver()
            
            if self.login_enabled:
                self.login()
            
            # بدء الزحف من العنوان URL الأصلي
            self.crawl(self.url)
            
            # تحليل المشكلات الأمنية
            security_issues = self.analyze_security()
            
            # عرض النتائج
            print(f"\n{Fore.GREEN}[+] اكتمل الزحف!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] تمت زيارة {len(self.visited_urls)} عناوين URL{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] تم العثور على {len(self.forms)} نماذج{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] تم العثور على {len(security_issues)} مشكلات أمنية محتملة{Style.RESET_ALL}")
            
            if security_issues and self.verbose:
                print(f"\n{Fore.YELLOW}[!] المشكلات الأمنية المحتملة:{Style.RESET_ALL}")
                for issue in security_issues:
                    print(f"  - {issue}")
            
        except Exception as e:
            self.logger.error(f"خطأ أثناء الزحف: {str(e)}")
            print(f"{Fore.RED}[!] خطأ: {str(e)}{Style.RESET_ALL}")
        
        finally:
            # إغلاق المتصفح
            if self.driver:
                self.driver.quit()
                self.logger.info("تم إغلاق متصفح Chrome")
        
        return {
            'visited_urls': list(self.visited_urls),
            'forms': self.forms,
            'security_issues': security_issues
        }