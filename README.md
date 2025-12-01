# NetGuard - PCAP Analysis Tool

A modern, full-stack network packet analysis tool that provides real-time threat detection and visualization for network security monitoring. NetGuard analyzes PCAP files to identify malicious activity, suspicious patterns, and security threats with an intuitive dashboard interface.

## Features

### Network Analysis
- **PCAP File Analysis**: Support for `.pcap`, `.pcapng`, and `.cap` file formats
- **Protocol Detection**: Automatic identification and categorization of network protocols
- **Traffic Statistics**: Comprehensive packet count, source/destination IP tracking
- **Threat Detection**: Identifies various types of malicious activity including:
  - SQL Injection attempts
  - XSS (Cross-Site Scripting) attacks
  - Command Injection
  - Port scanning activity
  - Suspicious payloads
  - Encrypted traffic analysis

### Security Intelligence (SIEM)
- **Risk Scoring**: Automated risk assessment for detected threats
- **Severity Classification**: HIGH, MEDIUM, LOW severity levels
- **MITRE ATT&CK Mapping**: Categorization by tactics and techniques
- **Threat Categories**: Organized threat classification system

### Visualization & Reporting
- **Interactive Dashboard**: Real-time data visualization with charts and graphs
- **Security Alerts**: Detailed alert cards with packet information
- **Packet Viewer**: Deep packet inspection with hex and ASCII dump views
- **Analysis History**: Track and review previous scans
- **Copy-to-Clipboard**: Quick copy functionality for IPs, payloads, and packet data

### Modern UI/UX
- Sleek dark mode interface with glassmorphism effects
- Responsive design with smooth animations (Framer Motion)
- Interactive charts (Recharts)
- Collapsible sections and scrollable containers
- Icon-based navigation (Lucide React)

## Tech Stack

### Backend
- **Framework**: Flask (Python)
- **Database**: SQLAlchemy with SQLite
- **Packet Analysis**: PyShark (TShark/Wireshark wrapper)
- **CORS**: Flask-CORS for cross-origin requests

### Frontend
- **Framework**: React 18
- **Build Tool**: Vite
- **Styling**: Tailwind CSS with custom design system
- **Animations**: Framer Motion
- **Charts**: Recharts
- **Icons**: Lucide React
- **HTTP Client**: Axios

## Prerequisites

- **Python**: 3.8 or higher
- **Node.js**: 16.x or higher
- **npm**: 8.x or higher
- **TShark/Wireshark**: Required for packet analysis

### Installing TShark

#### Ubuntu/Debian
```bash
sudo apt update
sudo apt install tshark
```

#### macOS
```bash
brew install wireshark
```

#### Fedora/RHEL
```bash
sudo dnf install wireshark-cli
```

## Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd Responsi
```

### 2. Backend Setup

#### Create Python Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

#### Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 3. Frontend Setup

```bash
cd frontend
npm install
```

## Running the Application

### Start the Backend Server

From the root directory:
```bash
source venv/bin/activate  # On Windows: venv\Scripts\activate
python app.py
```

The backend API will be available at `http://localhost:8080`

### Start the Frontend Development Server

In a new terminal, from the `frontend` directory:
```bash
cd frontend
npm run dev
```

The frontend will be available at `http://localhost:5173` (or the port Vite assigns)

## Usage

1. **Upload PCAP File**
   - Navigate to the Dashboard
   - Click the upload area or drag and drop a PCAP file
   - Supported formats: `.pcap`, `.pcapng`, `.cap`
   - Maximum file size: 16MB

2. **View Analysis Results**
   - Automatic threat detection and classification
   - Protocol breakdown and statistics
   - Source and destination IP tracking
   - Security alert cards with severity levels

3. **Inspect Packets**
   - Click on any security alert to view detailed packet information
   - View hex and ASCII dumps
   - Copy packet details to clipboard

4. **Review History**
   - Access previous scans from the History tab
   - View detailed reports for past analyses
   - Compare results across different captures

## Project Structure

```
Responsi/
├── app.py                  # Flask backend application
├── requirements.txt        # Python dependencies
├── utils/
│   └── analysis.py        # PCAP analysis logic
├── uploads/               # Uploaded PCAP files
├── instance/              # SQLite database
├── Example-Files/         # Sample PCAP files for testing
├── frontend/
│   ├── package.json       # Frontend dependencies
│   ├── vite.config.js     # Vite configuration
│   ├── src/
│   │   ├── App.jsx        # Main app component
│   │   ├── main.jsx       # Entry point
│   │   ├── index.css      # Global styles
│   │   └── components/
│   │       ├── Dashboard.jsx      # Main dashboard view
│   │       ├── History.jsx        # Scan history view
│   │       ├── PacketViewer.jsx   # Packet details modal
│   │       └── Sidebar.jsx        # Navigation sidebar
│   └── ...
├── static/                # Static assets
└── templates/             # HTML templates (if used)
```

## API Endpoints

### `GET /`
Health check endpoint
- **Response**: `{"status": "NetGuard API is running", "version": "2.0"}`

### `POST /api/upload`
Upload and analyze a PCAP file
- **Request**: Multipart form data with `file` field
- **Response**: Analysis results including packets, protocols, threats

### `GET /api/history`
Retrieve all previous scans
- **Response**: Array of scan objects with metadata

### `GET /api/report/<scan_id>`
Get detailed report for a specific scan
- **Response**: Complete scan data with all alerts

## Development

### Backend Development

The backend uses Flask with SQLAlchemy ORM. Database models:

- **Scan**: Stores scan metadata and statistics
- **Alert**: Stores individual security alerts/threats

To modify analysis logic, edit `/utils/analysis.py`

### Frontend Development

The frontend is built with React and Vite. Key components:

- `Dashboard.jsx`: Main analysis view with file upload
- `History.jsx`: Previous scans listing
- `PacketViewer.jsx`: Detailed packet inspection modal
- `Sidebar.jsx`: Navigation component

### Building for Production

```bash
cd frontend
npm run build
```

Build output will be in `frontend/dist/`

## Testing

### Sample PCAP Files
Example PCAP files are provided in the `Example-Files/` directory for testing various attack scenarios.

### Generate Test Data
Scripts to generate malicious traffic samples:
- `Example-Files/generate_malicious.py`
- `Example-Files/generate_malicious_payload.py`

## Security Considerations

- File size limited to 16MB to prevent DoS
- Secure filename handling with `werkzeug.secure_filename`
- CORS enabled for development (configure appropriately for production)
- Uploaded files stored in `uploads/` directory

## Database Schema

### Scan Table
- Filename, timestamp, packet counts
- Protocol distribution, IP statistics
- Related alerts (one-to-many relationship)

### Alert Table
- Threat type, severity, risk score
- Source/destination IPs and ports
- Packet payload, hex dump, ASCII dump
- MITRE ATT&CK classification
- Packet details (JSON)

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

[Specify your license here]

## Authors

- **Shazaw** - Initial work

## Acknowledgments

- **PyShark** for packet analysis capabilities
- **Wireshark/TShark** for the underlying packet capture engine
- **MITRE ATT&CK** framework for threat categorization
- **React** and **Vite** communities for excellent tooling

## Contact

For questions or support, please open an issue in the repository.

---

**Note**: This tool is designed for educational and legitimate security research purposes. Always ensure you have proper authorization before analyzing network traffic.
