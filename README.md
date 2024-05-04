---

# Advanced Network Scanner

![image](https://github.com/Cipherkrish69x/advanced-network-Scanner/assets/91202271/fc5de48a-df7c-4a33-82b3-573d0422cbf3)



Welcome to the Advanced Network Scanner, a versatile tool developed by Cipherkrish69x for advanced network scanning capabilities.

## Features

- **Network Discovery and Host Scanning**:
  - Use ARP scanning to discover live hosts within a specified IP range.

- **Port Scanning with Service Version Detection**:
  - Scan open ports on discovered hosts and detect the services running on those ports.

- **ARP Spoofing Detection**:
  - Identify potential ARP spoofing attacks by comparing ARP responses.

- **Banner Grabbing for Specific Services**:
  - Retrieve banners from specific services like HTTP and FTP to gather more information about running services.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Cipherkrish69x/advanced-network-Scanner.git
   ```

2. **Install Dependencies**:
   - Ensure you have Python installed on your system.
   - Install required Python packages using pip:
     ```bash
     pip install -r requirements.txt
     ```

## Usage

1. **Navigate to the Directory**:
   ```bash
   cd advanced-network-Scanner
   ```

2. **Run the Tool**:
   ```bash
   python advanced_network_scanner.py
   ```

3. **Enter IP Range**:
   - Provide the IP range (e.g., 192.168.1.1/24) to scan for live hosts.

4. **View Results**:
   - The tool will display live hosts, detect ARP spoofing, and scan open ports with service details.

## Features in Detail

- **Network Discovery**:
  - Utilizes ARP requests to discover live hosts within a specified IP range.

- **Port Scanning**:
  - Performs port scans on discovered hosts to identify open ports.

- **Service Version Detection**:
  - Detects the services running on open ports and retrieves version information.

- **ARP Spoofing Detection**:
  - Checks for potential ARP spoofing by comparing ARP responses.

- **Banner Grabbing**:
  - Retrieves banners from specific services (e.g., HTTP, FTP) to gather additional information.

## Contributing

Contributions are welcome! If you have any suggestions, improvements, or feature requests, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).

## Author

- **Cipherkrish69x** - [GitHub](https://github.com/Cipherkrish69x)

---
