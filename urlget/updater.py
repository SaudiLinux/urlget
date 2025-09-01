#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
وحدة التحديث التلقائي لأداة urlget
المؤلف: SayerLinux (SaudiLinux1@gmail.com)
الموقع: https://github.com/SaudiLinux
"""

import os
import sys
import json
import time
import logging
import platform
import subprocess
import pkg_resources
import requests
from datetime import datetime, timedelta
from packaging import version

from urlget.utils import setup_logger

# عنوان مستودع GitHub
GITHUB_REPO = "SaudiLinux/urlget"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}"
GITHUB_RELEASES_URL = f"{GITHUB_API_URL}/releases/latest"
GITHUB_TAGS_URL = f"{GITHUB_API_URL}/tags"

# ملف تكوين التحديث
UPDATE_CONFIG_FILE = os.path.expanduser("~/.urlget/update_config.json")

class Updater:
    """فئة للتحديث التلقائي للأداة"""
    
    def __init__(self, current_version, auto_update=True, check_interval=24, log_file=None, verbose=False):
        """
        تهيئة فئة Updater
        
        المعلمات:
            current_version (str): الإصدار الحالي للأداة
            auto_update (bool): تمكين التحديث التلقائي
            check_interval (int): الفاصل الزمني بالساعات للتحقق من التحديثات
            log_file (str): مسار ملف السجل
            verbose (bool): عرض معلومات تفصيلية
        """
        self.logger = setup_logger("Updater", log_file, verbose)
        self.current_version = current_version
        self.auto_update = auto_update
        self.check_interval = check_interval
        
        # إنشاء مجلد التكوين إذا لم يكن موجودًا
        os.makedirs(os.path.dirname(UPDATE_CONFIG_FILE), exist_ok=True)
        
        # تحميل تكوين التحديث
        self.config = self._load_config()
        
        self.logger.info(f"تم تهيئة Updater (الإصدار الحالي: {current_version}, التحديث التلقائي: {auto_update})")
    
    def _load_config(self):
        """تحميل تكوين التحديث من الملف"""
        default_config = {
            "last_check": None,
            "auto_update": self.auto_update,
            "check_interval": self.check_interval,
            "skip_version": None
        }
        
        try:
            if os.path.exists(UPDATE_CONFIG_FILE):
                with open(UPDATE_CONFIG_FILE, 'r') as f:
                    config = json.load(f)
                    # دمج التكوين المحمل مع التكوين الافتراضي
                    for key, value in default_config.items():
                        if key not in config:
                            config[key] = value
                    return config
        except Exception as e:
            self.logger.error(f"خطأ في تحميل تكوين التحديث: {e}")
        
        return default_config
    
    def _save_config(self):
        """حفظ تكوين التحديث إلى الملف"""
        try:
            with open(UPDATE_CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            self.logger.error(f"خطأ في حفظ تكوين التحديث: {e}")
    
    def should_check_update(self):
        """التحقق مما إذا كان يجب التحقق من التحديثات"""
        if not self.config["auto_update"]:
            return False
        
        last_check = self.config["last_check"]
        if last_check is None:
            return True
        
        # تحويل التاريخ من النص إلى كائن datetime
        last_check_date = datetime.fromisoformat(last_check)
        check_interval = timedelta(hours=self.config["check_interval"])
        
        return datetime.now() > last_check_date + check_interval
    
    def check_for_updates(self, force=False):
        """
        التحقق من وجود تحديثات
        
        المعلمات:
            force (bool): إجبار التحقق من التحديثات بغض النظر عن الفاصل الزمني
        
        العائد:
            dict: معلومات التحديث أو None إذا لم يكن هناك تحديث
        """
        if not force and not self.should_check_update():
            self.logger.debug("تم التحقق من التحديثات مؤخرًا، تخطي...")
            return None
        
        self.logger.info("التحقق من وجود تحديثات...")
        
        # تحديث وقت آخر فحص
        self.config["last_check"] = datetime.now().isoformat()
        self._save_config()
        
        try:
            # التحقق من أحدث إصدار
            response = requests.get(GITHUB_RELEASES_URL, timeout=10)
            response.raise_for_status()
            release_info = response.json()
            
            latest_version = release_info["tag_name"].lstrip('v')
            download_url = release_info["zipball_url"]
            release_notes = release_info["body"]
            
            # مقارنة الإصدارات
            if version.parse(latest_version) > version.parse(self.current_version):
                # التحقق مما إذا كان المستخدم قد تخطى هذا الإصدار
                if self.config["skip_version"] == latest_version:
                    self.logger.info(f"تم تخطي الإصدار {latest_version} بناءً على تفضيلات المستخدم")
                    return None
                
                self.logger.info(f"تم العثور على إصدار جديد: {latest_version} (الحالي: {self.current_version})")
                
                return {
                    "version": latest_version,
                    "download_url": download_url,
                    "release_notes": release_notes,
                    "release_date": release_info["published_at"]
                }
            else:
                self.logger.info(f"أنت تستخدم أحدث إصدار ({self.current_version})")
                return None
        
        except Exception as e:
            self.logger.error(f"خطأ في التحقق من التحديثات: {e}")
            return None
    
    def update(self, update_info=None):
        """
        تحديث الأداة إلى أحدث إصدار
        
        المعلمات:
            update_info (dict): معلومات التحديث (إذا كانت متوفرة بالفعل)
        
        العائد:
            bool: نجاح أو فشل التحديث
        """
        if update_info is None:
            update_info = self.check_for_updates(force=True)
            
            if update_info is None:
                self.logger.info("لا توجد تحديثات متاحة")
                return False
        
        self.logger.info(f"بدء التحديث إلى الإصدار {update_info['version']}...")
        
        try:
            # استخدام pip لتحديث الحزمة
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", f"urlget=={update_info['version']}"])
            
            self.logger.info(f"تم التحديث بنجاح إلى الإصدار {update_info['version']}")
            return True
        
        except subprocess.CalledProcessError as e:
            self.logger.error(f"فشل التحديث: {e}")
            
            # محاولة التثبيت من GitHub مباشرة
            try:
                self.logger.info("محاولة التثبيت من GitHub مباشرة...")
                subprocess.check_call([
                    sys.executable, "-m", "pip", "install", "--upgrade",
                    f"git+https://github.com/{GITHUB_REPO}.git@v{update_info['version']}"
                ])
                
                self.logger.info(f"تم التحديث بنجاح إلى الإصدار {update_info['version']} من GitHub")
                return True
            
            except subprocess.CalledProcessError as e2:
                self.logger.error(f"فشل التحديث من GitHub: {e2}")
                return False
        
        except Exception as e:
            self.logger.error(f"خطأ غير متوقع أثناء التحديث: {e}")
            return False
    
    def skip_version(self, version):
        """
        تخطي إصدار معين للتحديث
        
        المعلمات:
            version (str): الإصدار المراد تخطيه
        """
        self.config["skip_version"] = version
        self._save_config()
        self.logger.info(f"تم تعيين الإصدار {version} للتخطي")
    
    def set_auto_update(self, enabled):
        """
        تمكين أو تعطيل التحديث التلقائي
        
        المعلمات:
            enabled (bool): تمكين التحديث التلقائي
        """
        self.config["auto_update"] = enabled
        self._save_config()
        self.logger.info(f"تم {'تمكين' if enabled else 'تعطيل'} التحديث التلقائي")
    
    def set_check_interval(self, hours):
        """
        تعيين الفاصل الزمني للتحقق من التحديثات
        
        المعلمات:
            hours (int): الفاصل الزمني بالساعات
        """
        self.config["check_interval"] = hours
        self._save_config()
        self.logger.info(f"تم تعيين فاصل التحقق من التحديثات إلى {hours} ساعة")
    
    def get_update_status(self):
        """
        الحصول على حالة التحديث الحالية
        
        العائد:
            dict: حالة التحديث
        """
        return {
            "current_version": self.current_version,
            "auto_update": self.config["auto_update"],
            "check_interval": self.config["check_interval"],
            "last_check": self.config["last_check"],
            "skip_version": self.config["skip_version"]
        }


def check_and_update(current_version, auto_update=True, silent=False, log_file=None, verbose=False):
    """
    التحقق من وجود تحديثات وتثبيتها إذا كانت متوفرة
    
    المعلمات:
        current_version (str): الإصدار الحالي للأداة
        auto_update (bool): تمكين التحديث التلقائي
        silent (bool): عدم عرض رسائل للمستخدم
        log_file (str): مسار ملف السجل
        verbose (bool): عرض معلومات تفصيلية
    
    العائد:
        bool: ما إذا كان التحديث قد تم تثبيته
    """
    updater = Updater(current_version, auto_update, log_file=log_file, verbose=verbose)
    
    if not updater.should_check_update():
        return False
    
    update_info = updater.check_for_updates()
    
    if update_info is None:
        return False
    
    if silent:
        # التحديث التلقائي بدون تفاعل المستخدم
        return updater.update(update_info)
    
    # عرض معلومات التحديث للمستخدم
    print("\n" + "=" * 60)
    print(f"تم العثور على إصدار جديد من urlget: {update_info['version']}")
    print(f"الإصدار الحالي: {current_version}")
    print(f"تاريخ الإصدار: {update_info['release_date']}")
    print("\nملاحظات الإصدار:")
    print(update_info['release_notes'])
    print("=" * 60)
    
    while True:
        choice = input("\nهل تريد التحديث الآن؟ (y/n/s - نعم/لا/تخطي هذا الإصدار): ").lower()
        
        if choice == 'y':
            return updater.update(update_info)
        elif choice == 'n':
            print("تم إلغاء التحديث. سيتم التحقق مرة أخرى في المرة القادمة.")
            return False
        elif choice == 's':
            updater.skip_version(update_info['version'])
            print(f"تم تخطي الإصدار {update_info['version']}. لن يتم التذكير به مرة أخرى.")
            return False


if __name__ == "__main__":
    print("هذا الملف مخصص للاستيراد وليس للتشغيل المباشر")