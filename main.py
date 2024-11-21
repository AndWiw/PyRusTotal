import sys
import subprocess

def install_package(package):
    """Install a single package using pip"""
    try:
        print(f"Installing {package}...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', package], 
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        print(f"Failed to install {package}")
        return False

def install_prerequisites():
    """Install required packages before running the script"""
    prerequisites = [
        'requests',
        'configparser'
    ]
    
    all_installed = True
    for package in prerequisites:
        if not install_package(package):
            all_installed = False
    
    if not all_installed:
        print("Failed to install one or more required packages.")
        print("Please try manually installing them using:")
        print("pip install requests configparser")
        sys.exit(1)
    
    print("All prerequisites installed successfully!")
    return True

def create_config():
    """Create configuration file if it doesn't exist"""
    try:
        import configparser
        import os
        
        config_path = 'config.ini'
        if not os.path.exists(config_path):
            config = configparser.ConfigParser()
            config['VirusTotal'] = {
                'api_key': 'YOUR_VIRUSTOTAL_API_KEY_HERE'
            }
            with open(config_path, 'w') as configfile:
                config.write(configfile)
            print(f"Created {config_path}. Please add your VirusTotal API key.")
            sys.exit(0)
    except Exception as e:
        print(f"Error creating config file: {e}")
        sys.exit(1)

def main():
    # First, install prerequisites
    if not install_prerequisites():
        return
    
    # Now we can safely import these
    import os
    import time
    import hashlib
    import requests
    import configparser
    
    # Check config file exists
    create_config()
    
    class VirusTotalScanner:
        def __init__(self, config_path='config.ini'):
            """Initialize with VirusTotal API configuration"""
            config = configparser.ConfigParser()
            config.read(config_path)
            
            self.api_key = config.get('VirusTotal', 'api_key')
            if self.api_key == 'YOUR_VIRUSTOTAL_API_KEY_HERE':
                print("Please update config.ini with your VirusTotal API key.")
                sys.exit(1)
            
            self.base_url = 'https://www.virustotal.com/vtapi/v2/file/report'
            
            # Rate limit tracking
            self.last_request_time = 0
            self.request_interval = 15  # Seconds between requests
        
        def _rate_limit_delay(self):
            """Enforce API rate limiting"""
            current_time = time.time()
            elapsed = current_time - self.last_request_time
            if elapsed < self.request_interval:
                time.sleep(self.request_interval - elapsed)
            self.last_request_time = time.time()
        
        def check_file_hash(self, file_hash):
            """Check file hash against VirusTotal database"""
            self._rate_limit_delay()
            
            params = {
                'apikey': self.api_key,
                'resource': file_hash
            }
            
            try:
                response = requests.get(self.base_url, params=params)
                result = response.json()
                
                if result['response_code'] == 1:
                    return {
                        'positives': result.get('positives', 0),
                        'total': result.get('total', 0),
                        'scan_date': result.get('scan_date', 'Unknown'),
                        'permalink': result.get('permalink', '')
                    }
                return None
            
            except requests.RequestException as e:
                print(f"VirusTotal API error: {e}")
                return None
        
        def scan_directory(self, directory):
            """Scan directory and check hashes against VirusTotal"""
            if not os.path.exists(directory):
                print(f"Directory not found: {directory}")
                return []
                
            results = []
            print(f"Scanning directory: {directory}")
            for root, _, files in os.walk(directory):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    print(f"Scanning: {filepath}")
                    file_hash = self._calculate_file_hash(filepath)
                    vt_result = self.check_file_hash(file_hash)
                    
                    results.append({
                        'filepath': filepath,
                        'hash': file_hash,
                        'virustotal_result': vt_result
                    })
            return results
        
        def _calculate_file_hash(self, filepath):
            """Calculate SHA-256 hash of file"""
            hasher = hashlib.sha256()
            try:
                with open(filepath, 'rb') as f:
                    while chunk := f.read(4096):
                        hasher.update(chunk)
                return hasher.hexdigest()
            except Exception as e:
                print(f"Error reading file {filepath}: {e}")
                return None

    # Get directory to scan from user input
    scan_dir = input("Enter directory path to scan: ").strip()
    
    # Scan directory
    scanner = VirusTotalScanner()
    results = scanner.scan_directory(scan_dir)
    
    # Print results
    print("\nScan Results:")
    print("-" * 50)
    for result in results:
        print(f"File: {result['filepath']}")
        print(f"Hash: {result['hash']}")
        
        if result['virustotal_result']:
            vt = result['virustotal_result']
            print(f"Detections: {vt['positives']}/{vt['total']}")
            print(f"Scan Date: {vt['scan_date']}")
            print(f"Details: {vt['permalink']}")
        else:
            print("No VirusTotal results found")
        print("-" * 50)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)