#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import logging
import pyfiglet
from colorama import Fore, Style
from datetime import datetime

def setup_logger(name, log_file=None, level=logging.INFO):
    """إعداد مسجل الأحداث"""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # إنشاء منسق السجل
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # إضافة معالج لعرض السجلات في وحدة التحكم
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # إضافة معالج لحفظ السجلات في ملف إذا تم تحديده
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

def banner():
    """عرض شعار الأداة"""
    logo = pyfiglet.figlet_format("URLGET", font="slant")
    print(f"{Fore.RED}{logo}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}أداة اختبار أمان الويب متعددة الوظائف{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}تم تطويرها بواسطة: {Fore.CYAN}SayerLinux{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}الموقع: {Fore.CYAN}https://github.com/SaudiLinux{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}البريد الإلكتروني: {Fore.CYAN}SaudiLinux1@gmail.com{Style.RESET_ALL}")
    print("-" * 60)

def save_results(results, output_file=None):
    """حفظ النتائج في ملف"""
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"urlget_results_{timestamp}.txt"
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 60 + "\n")
        f.write(f"URLGET - نتائج الفحص\n")
        f.write(f"التاريخ: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        
        for result in results:
            f.write(f"{result}\n")
    
    return output_file

def check_linux():
    """التحقق من أن النظام هو لينكس"""
    if sys.platform != "linux":
        print(f"{Fore.RED}[!] هذه الأداة تعمل فقط على نظام لينكس{Style.RESET_ALL}")
        return False
    return True

def check_root():
    """التحقق من صلاحيات الجذر"""
    if os.geteuid() != 0:
        print(f"{Fore.YELLOW}[!] بعض الميزات قد تتطلب صلاحيات الجذر (root){Style.RESET_ALL}")
        return False
    return True

def create_logo_ascii():
    """إنشاء شعار ASCII للأداة"""
    logo = """
    _    _ _____  _      _____ ______ _______ 
   | |  | |  __ \\| |    / ____|  ____|__   __|
   | |  | | |__) | |   | |  __| |__     | |   
   | |  | |  _  /| |   | | |_ |  __|    | |   
   | |__| | | \\ \\| |___| |__| | |____   | |   
    \\____/|_|  \\_\\______\\_____|______|  |_|   
                                             
    """
    return logo