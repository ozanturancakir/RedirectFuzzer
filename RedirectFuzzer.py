#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys
import concurrent.futures
import requests
import urllib.parse
from termcolor import colored
import pyfiglet
import time

# requests SSL uyarılarını kapat
requests.packages.urllib3.disable_warnings()

# --- Konfigürasyon ---
DEFAULT_WORKERS = 50
DEFAULT_TIMEOUT = 10
# Sadece raporlama için, parametreleri önceliklendirmeye gerek yok, ama yine de bırakıyorum
REDIRECT_KEYWORDS = ["go", "return", "r_url", "returnurl", "returnuri", "locationurl", "goto", "return_url", "return_uri", "ref", "referrer", "backurl", "returnto", "successurl", "redirect", "redirect_url", "redirecturi", "url", "next", "target", "site", "page", "returnUrl", "returnUri", "r_Url", "locationUrl", "return_Url", "return_Uri", "redirect_Url", "redirectUri", "redirectUrl", "redirect_uri"]


def banner():
    """Aracın başlığını basar."""
    text = pyfiglet.figlet_format("Redirect Fuzzer", font="slant")
    print(colored(text, 'magenta'))
    print(colored("   			Open Redirect Zafiyet Denetleyicisi", 'yellow') + "\n")
    print(colored("       				   Ozan Turan Çakır", 'yellow') + "\n")
    print("-" * 50)

def run_fuzzing(parsed_url, param_to_fuzz, payload_encoded, payload_target, timeout, temp_query_params):
    """Gerçek HTTP isteğini gönderen yardımcı fonksiyon."""
    
    # Yeni sorgu dizesini oluştur (Parametreyi Payload ile değiştir)
    temp_query_params[param_to_fuzz] = [payload_encoded]
    new_query = urllib.parse.urlencode(temp_query_params, doseq=True)
    test_url = parsed_url._replace(query=new_query).geturl()
    
    try:
        response = requests.get(
            test_url, 
            timeout=timeout, 
            allow_redirects=True, 
            verify=False, 
            headers={'User-Agent': 'RedirectFuzzer-AllParams/1.0'}
        )
        
        # Başarı Kriteri: Yönlendirme gerçekleşti VE nihai hedef bizim payload'ımızla başlıyor
        if response.history and response.url.startswith(payload_target):
            first_status_code = response.history[0].status_code
            
            # Raporlama için temiz URL oluştur (payload yerine 'PAYLOAD_HERE' yaz)
            original_clean_url = parsed_url._replace(query=urllib.parse.urlencode(temp_query_params, doseq=True)).geturl().replace(f"{param_to_fuzz}={payload_encoded}", f"{param_to_fuzz}=PAYLOAD_HERE")
            
            return {
                'status': 'SUCCESS',
                'url': original_clean_url,
                'param': param_to_fuzz,
                'code': first_status_code,
                'payload_used': payload_target
            }
            
    except requests.exceptions.RequestException:
        pass 
    except Exception:
        pass
        
    return None


def test_redirect(url, all_payloads_to_test, timeout):
    """
    Verilen URL'yi alıp, TÜM sorgu parametrelerine tüm payload'ları dener.
    """
    
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
    
    if not query_params:
        return None

    # --- 1. Parametreleri Sırala (Hassas olanlar önce) ---
    all_params = list(query_params.keys())
    
    # Önce hassas isimli parametreleri (redirect, url, next vb.) deniyoruz.
    priority_params = [
        p for p in all_params 
        if any(kw in p.lower() for kw in REDIRECT_KEYWORDS)
    ]
    # Hassas parametreler + diğerleri (tekrarsız)
    sorted_params = list(dict.fromkeys(priority_params + all_params))
    
    # --- 2. TÜM PARAMETRELER ÜZERİNDE DÖNGÜ BAŞLAT ---
    for param_to_fuzz in sorted_params:
        
        # Orijinal sorgu parametrelerinin kopyası
        temp_query_params = query_params.copy()
        
        # --- 3. Her parametre için TÜM PAYLOAD'LARI DENE ---
        for payload_data in all_payloads_to_test:
            
            payload_target = payload_data['target']
            payload_encoded = payload_data['encoded']
            
            # Fuzzing işlemini gerçekleştir
            result = run_fuzzing(parsed_url, param_to_fuzz, payload_encoded, payload_target, timeout, temp_query_params.copy())
            
            if result:
                # Başarılı sonuç bulunduğunda hemen dön
                return result
                
    return None 

def main():
    banner()
    
    parser = argparse.ArgumentParser(
        description=colored('RedirectFuzzer.py: Open Redirect zafiyetlerini dener.', 'cyan'),
        epilog=colored('Kullanım Örneği: python3 RedirectFuzzer.py -i redirect.txt --payload-file targetdomains.txt -o sonuç.txt', 'yellow'),
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('-i', '--input', type=str, required=True, 
                        help=colored('Potansiyel Open Redirect URL\'lerini içeren dosya.', 'green'))
    
    parser.add_argument('--payload-file', type=str, required=True,
                        help=colored('Denenecek(Yönlendirmesini istediğimiz) hedef liste(Örneğin, targetdomains.txt)', 'red'))
                        
    parser.add_argument('-w', '--workers', type=int, default=DEFAULT_WORKERS, 
                        help=f'Eş zamanlı iş parçacığı sayısı (varsayılan: {DEFAULT_WORKERS}).')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT, 
                        help=f'Bağlantı zaman aşımı sn (varsayılan: {DEFAULT_TIMEOUT}).')
    parser.add_argument('-o', '--output', type=str, default=None, 
                        help='Başarılı sonuçların yazılacağı dosya.')
    
    args = parser.parse_args()

    # --- Dosya Okuma ve Payload Hazırlığı ---
    try:
        with open(args.input, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(colored(f"\n[HATA] Girdi URL dosyası '{args.input}' bulunamadı.", 'red'))
        sys.exit(1)
        
    try:
        with open(args.payload_file, 'r') as f:
            raw_payloads = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(colored(f"\n[HATA] Payload dosyası '{args.payload_file}' bulunamadı.", 'red'))
        sys.exit(1)

    # Payloadları Toplama
    all_payloads_to_test = []
    
    for payload in raw_payloads:
        # 1. Normal (Tek Kodlanmış)
        all_payloads_to_test.append({
            'target': payload,
            'encoded': urllib.parse.quote_plus(payload)
        })
        # 2. Çift Kodlanmış 
        all_payloads_to_test.append({
            'target': payload,
            'encoded': urllib.parse.quote_plus(urllib.parse.quote_plus(payload))
        })
        
        # NOT: Bypass varyasyonları burada OLUŞTURULMUYOR (Bu kontrol sizde kalıyor.)

    # Toplam deneme bilgisi
    total_targets = len(targets)
    total_payload_types = len(raw_payloads)
    total_payload_count = len(all_payloads_to_test) # (Temel payload sayısı x 2)
    
    print(colored(f"[+] Toplam {total_targets} hedef URL yüklendi.", 'blue'))
    print(colored(f"[+] {total_payload_types} temel payload'dan {total_payload_count} varyasyon (tek ve çift kodlu) hazırlandı.", 'blue'))
    print(colored(f"[!] {args.workers} iş parçacığı ile tarama başlatılıyor...", 'yellow'))
    
    successful_redirects = []
    
    # --- Paralel Çalıştırma ---
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_to_url = {
            executor.submit(test_redirect, url, all_payloads_to_test, args.timeout): url 
            for url in targets
        }
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_url)):
            result_data = future.result()
            
            # İlerleme raporu (URL bazlı)
            progress = (i + 1) / total_targets * 100
            sys.stdout.write(f"\r[Taraniyor: {int(progress)}%] {i+1}/{total_targets} URL denendi.")
            sys.stdout.flush()
            
            if result_data and result_data['status'] == 'SUCCESS':
                successful_redirects.append(result_data)
                
                # Başarılı sonuçları anında ekrana bas
                sys.stdout.write('\n')
                print(colored('[BAŞARILI YÖNLENDİRME]', 'red', attrs=['bold']) + 
                      f" -> Kod: {result_data['code']} - Parametre: {result_data['param']} - Kullanılan Payload: {result_data['payload_used']} - URL: {result_data['url']}")
                # İlerleme çubuğunu tekrar yaz
                sys.stdout.write(f"[Taraniyor: {int(progress)}%] {i+1}/{total_targets} URL denendi.")
                sys.stdout.flush()

    # Temiz bir bitiş için ilerleme çubuğunu temizle
    sys.stdout.write('\n')
    
    # Final Raporlama
    print(colored("\n--------------------------------------------------", 'cyan'))
    print(colored("[***] Denetim Tamamlandı.", 'cyan'))
    print(colored(f"[i] Toplam {len(successful_redirects)} aktif Open Redirect zafiyeti bulundu.", 'red', attrs=['bold']))

    if args.output and successful_redirects:
        try:
            with open(args.output, 'w') as out_file:
                out_file.write("Working_URL,Parameter,StatusCode,Payload_Used\n")
                
                for item in successful_redirects:
                    out_file.write(f"{item['url']},{item['param']},{item['code']},{item['payload_used']}\n")

            print(colored(f"[+] Başarılı sonuçlar başarıyla dosyaya yazıldı: {args.output}", 'green'))
            
        except Exception as file_e:
            print(colored(f"[HATA] Çıktı dosyası yazılırken hata oluştu: {file_e}", 'red'))

    print(colored("--------------------------------------------------", 'cyan'))


if __name__ == "__main__":
    main()
