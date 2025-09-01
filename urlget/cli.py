#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
import os
from colorama import init, Fore, Style
import pyfiglet

from urlget.crawler import ChromeCrawler
from urlget.fuzzer import HTTPFuzzer
from urlget.xss import XSSScanner
from urlget.csrf import CSRFGenerator
from urlget.dns_hijack import DNSHijacker
from urlget.updater import check_and_update
from urlget.utils import banner
from urlget import __version__

def main():
    """نقطة الدخول الرئيسية لأداة urlget"""
    # تهيئة colorama
    init(autoreset=True)
    
    # التحقق من وجود تحديثات
    check_and_update(__version__, auto_update=True, silent=False, verbose=False)
    
    # عرض الشعار
    banner()
    
    # إنشاء محلل الوسائط
    parser = argparse.ArgumentParser(
        description=f"{Fore.GREEN}urlget - أداة اختبار أمان الويب متعددة الوظائف{Style.RESET_ALL}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # إضافة الوسائط العامة
    parser.add_argument("-u", "--url", help="عنوان URL المستهدف")
    parser.add_argument("-o", "--output", help="ملف لحفظ النتائج")
    parser.add_argument("-v", "--verbose", action="store_true", help="عرض معلومات تفصيلية")
    
    # إنشاء مجموعات الوسائط للأوامر الفرعية
    subparsers = parser.add_subparsers(dest="command", help="الأوامر المتاحة")
    
    # أمر التحديث
    update_parser = subparsers.add_parser("update", help="تحديث الأداة إلى أحدث إصدار")
    update_parser.add_argument("--check-only", action="store_true", help="التحقق فقط من وجود تحديثات دون تثبيتها")
    update_parser.add_argument("--force", action="store_true", help="إجبار التحديث حتى لو كان الإصدار الحالي هو الأحدث")
    
    # أمر الزحف
    crawl_parser = subparsers.add_parser("crawl", help="زحف الموقع باستخدام Chrome")
    crawl_parser.add_argument("-d", "--depth", type=int, default=2, help="عمق الزحف")
    crawl_parser.add_argument("--login", action="store_true", help="تمكين تسجيل الدخول")
    crawl_parser.add_argument("--username", help="اسم المستخدم للتسجيل")
    crawl_parser.add_argument("--password", help="كلمة المرور للتسجيل")
    
    # أمر القوة الغاشمة والتشويش
    fuzz_parser = subparsers.add_parser("fuzz", help="تشويش وقوة غاشمة لطلبات HTTP")
    fuzz_parser.add_argument("-p", "--payloads", help="ملف يحتوي على الحمولات")
    fuzz_parser.add_argument("-m", "--method", choices=["GET", "POST", "PUT", "DELETE"], default="GET", help="طريقة HTTP")
    fuzz_parser.add_argument("-t", "--threads", type=int, default=10, help="عدد المواضيع")
    
    # أمر اختبار XSS
    xss_parser = subparsers.add_parser("xss", help="اختبار ثغرات XSS")
    xss_parser.add_argument("-p", "--payloads", help="ملف يحتوي على حمولات XSS")
    xss_parser.add_argument("--params", help="المعلمات المستهدفة للاختبار")
    
    # أمر إنشاء استغلالات CSRF
    csrf_parser = subparsers.add_parser("csrf", help="إنشاء استغلالات CSRF")
    csrf_parser.add_argument("-r", "--request", help="ملف طلب HTTP لإنشاء استغلال CSRF")
    csrf_parser.add_argument("--output-html", help="ملف HTML للاستغلال")
    
    # أمر اختطاف DNS
    dns_parser = subparsers.add_parser("dns", help="اختطاف نظام أسماء النطاقات")
    dns_parser.add_argument("-d", "--domain", help="النطاق المستهدف")
    dns_parser.add_argument("-i", "--interface", help="واجهة الشبكة")
    dns_parser.add_argument("--redirect", help="عنوان IP للتحويل")
    
    # تحليل الوسائط
    args = parser.parse_args()
    
    # التحقق من وجود أوامر
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # تنفيذ الأمر المطلوب
    try:
        if args.command == "update":
            from urlget.updater import Updater
            updater = Updater(__version__, verbose=args.verbose)
            if args.check_only:
                update_info = updater.check_for_updates(force=args.force)
                if update_info:
                    print(f"\n{Fore.GREEN}[+] تم العثور على إصدار جديد: {update_info['version']} (الحالي: {__version__}){Style.RESET_ALL}")
                    print(f"\nملاحظات الإصدار:")
                    print(f"{update_info['release_notes']}")
                else:
                    print(f"\n{Fore.GREEN}[+] أنت تستخدم أحدث إصدار ({__version__}){Style.RESET_ALL}")
            else:
                update_info = updater.check_for_updates(force=args.force)
                if update_info:
                    updater.update(update_info)
                else:
                    print(f"\n{Fore.GREEN}[+] أنت تستخدم أحدث إصدار ({__version__}){Style.RESET_ALL}")
        
        elif args.command == "crawl":
            crawler = ChromeCrawler(
                url=args.url,
                depth=args.depth,
                login_enabled=args.login,
                username=args.username,
                password=args.password,
                verbose=args.verbose
            )
            crawler.start()
            
        elif args.command == "fuzz":
            fuzzer = HTTPFuzzer(
                url=args.url,
                method=args.method,
                payloads_file=args.payloads,
                threads=args.threads,
                verbose=args.verbose
            )
            fuzzer.start()
            
        elif args.command == "xss":
            scanner = XSSScanner(
                url=args.url,
                payloads_file=args.payloads,
                params=args.params,
                verbose=args.verbose
            )
            scanner.start()
            
        elif args.command == "csrf":
            generator = CSRFGenerator(
                request_file=args.request,
                output_html=args.output_html,
                verbose=args.verbose
            )
            generator.generate()
            
        elif args.command == "dns":
            hijacker = DNSHijacker(
                domain=args.domain,
                interface=args.interface,
                redirect_ip=args.redirect,
                verbose=args.verbose
            )
            hijacker.start()
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] تم إلغاء العملية بواسطة المستخدم{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] خطأ: {str(e)}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    # التحقق من نظام التشغيل مع تحذير بدلاً من المنع
    if sys.platform != "linux":
        print(f"{Fore.YELLOW}[!] تحذير: بعض الميزات قد لا تعمل بشكل كامل على نظام {sys.platform}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] للحصول على أفضل أداء، يُنصح باستخدام نظام لينكس{Style.RESET_ALL}")
    
    main()