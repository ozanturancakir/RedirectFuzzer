import argparse
import requests
import pyfiglet
from termcolor import colored
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import sys

# Konfigürasyon ve Varsayılan Değerler
DEFAULT_WORKERS = 10
DEFAULT_TIMEOUT = 10

def banner():
    """Aracın başlığını basar."""
    text = pyfiglet.figlet_format("Redirect Fuzzer", font="slant")
    print(colored(text, 'magenta'))
    print(colored("            Open Redirect Vulnerability Scanner", 'yellow') + "\n")
    print(colored("                        Ozan Turan Çakır", 'yellow') + "\n")
    print("-" * 50)

def test_url(url, payload, timeout):
    """Geliştirilmiş ve hatasız yönlendirme testi."""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False, verify=False)
        
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            
            if payload.strip() and payload.strip() in location:
                return True, url, location
                
    except Exception:
        pass
    return False, None, None

def generate_variants(url, payload):
    """URL parametrelerini sırayla değiştirir, diğer parametreleri sabit tutar."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        return []

    variants = []
    # Hem ham payload hem de URL encoded hali
    payload_variants = [payload, quote(payload)]
    
    # Tüm parametre isimlerini al
    all_param_names = list(params.keys())

    for p_name in all_param_names:
        for p_val in payload_variants:
            # Mevcut parametrelerin bir kopyasını al
            temp_params = dict(params)
            # Sadece hedef parametreyi güncelle (liste yapısını koru)
            temp_params[p_name] = [p_val]
            
            # Yeni query string oluştur ve URL'i birleştir
            new_query = urlencode(temp_params, doseq=True)
            new_url = urlunparse(parsed._replace(query=new_query))
            variants.append((new_url, p_val))
            
    return variants

def main():
    banner()
    
    parser = argparse.ArgumentParser(
        description=colored('RedirectFuzzer.py: Tests for Open Redirect vulnerabilities.', 'cyan'),
        epilog=colored('Example Usage: python3 RedirectFuzzer.py -i redirect_urls.txt --payload-file redirect_payloads.txt -w 20 -o results.txt', 'yellow'),
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS,
                        help='show this help message and exit')
    
    parser.add_argument('-i', '--input', type=str, required=True, 
                        help=colored('File containing potential Open Redirect URLs.', 'green'))
    
    parser.add_argument('--payload-file', type=str, required=True,
                        help=colored('File containing target domains to test redirection against (e.g., payloads.txt).', 'red'))
                        
    parser.add_argument('-w', '--workers', type=int, default=DEFAULT_WORKERS, 
                        help=f'Number of concurrent threads (default: {DEFAULT_WORKERS}).')
    
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT, 
                        help=f'Connection timeout in seconds (default: {DEFAULT_TIMEOUT}).')
    
    parser.add_argument('-o', '--output', type=str, default=None, 
                        help='File to write successful results into.')
    
    args = parser.parse_args()

    try:
        with open(args.input, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        with open(args.payload_file, 'r') as f:
            base_payloads = [line.strip() for line in f if line.strip()]
    except FileNotFoundError as e:
        print(colored(f"[-] Hata: Dosya bulunamadı! {e}", "red"))
        return

    total_targets = len(urls)
    total_payload_types = len(base_payloads)
    total_payload_count = total_payload_types * 2

    print(colored(f"[+] Toplam {total_targets} hedef URL yüklendi.", 'blue'))
    print(colored(f"[+] {total_payload_types} temel payload'dan {total_payload_count} varyasyon (tek ve çift kodlu) hazırlandı.", 'blue'))
    print(colored(f"[!] {args.workers} iş parçacığı ile tarama başlatılıyor...", 'yellow'))

    successful_redirects = []
    tasks = []
    
    for url in urls:
        for payload in base_payloads:
            variants = generate_variants(url, payload)
            for v_url, p_val in variants:
                tasks.append((v_url, p_val))

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        pbar = tqdm(total=len(tasks), desc="Scanning", unit="req", leave=False)
        
        future_to_url = {executor.submit(test_url, t[0], t[1], args.timeout): t for t in tasks}
        
        for future in as_completed(future_to_url):
            is_vulnerable, v_url, loc = future.result()
            if is_vulnerable:
                pbar.clear()
                print(colored(f"[VULNERABLE] {v_url} -> {loc}", 'green', attrs=['bold']))
                successful_redirects.append(v_url)
                pbar.refresh()
            
            pbar.update(1)
        
        pbar.close()

    print(colored("\n--------------------------------------------------", 'cyan'))
    print(colored("[***] Denetim Tamamlandı.", 'cyan'))
    print(colored(f"[i] Toplam {len(successful_redirects)} aktif Open Redirect zafiyeti bulundu.", 'red', attrs=['bold']))

    if args.output and successful_redirects:
        with open(args.output, 'w') as f:
            for res in successful_redirects:
                f.write(res + "\n")
        print(colored(f"[+] Sonuçlar {args.output} dosyasına kaydedildi.", 'green'))

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()
