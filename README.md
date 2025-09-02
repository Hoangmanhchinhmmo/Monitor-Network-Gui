# 🌐 Network & Web Monitor Suite - Công Cụ Giám Sát Mạng Chuyên Nghiệp

**Network & Web Monitor Suite** là bộ công cụ giám sát mạng toàn diện được phát triển bằng Python, cho phép theo dõi và phân tích các kết nối mạng cũng như hoạt động web trên máy tính của bạn một cách chi tiết và trực quan.

![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

## 🚀 Tính Năng Nổi Bật

### 📊 Network Monitor (CLI & GUI)
- **Giám sát kết nối mạng real-time**: Theo dõi tất cả các kết nối TCP/UDP đang hoạt động
- **Thông tin process chi tiết**: Hiển thị tên process, đường dẫn executable, command line
- **Lịch sử kết nối**: Lưu trữ và theo dõi lịch sử các kết nối mạng
- **Thống kê tổng quan**: Phân tích số lượng kết nối theo protocol, trạng thái
- **Export dữ liệu**: Xuất báo cáo dưới định dạng CSV và JSON

### 🌍 Web Address Monitor (CLI & GUI)
- **Giám sát web traffic chuyên biệt**: Tập trung vào các kết nối web (HTTP/HTTPS)
- **Phân loại website tự động**: Tự động phân loại các trang web theo danh mục
- **Theo dõi browser activity**: Giám sát hoạt động của các trình duyệt web
- **Resolve IP to Domain**: Tự động chuyển đổi địa chỉ IP thành tên miền
- **Lọc và tìm kiếm**: Công cụ lọc mạnh mẽ để tìm kiếm thông tin cụ thể

### 🎨 Giao Diện Người Dùng
- **GUI hiện đại**: Giao diện tkinter thân thiện và dễ sử dụng
- **Multi-tab interface**: Tổ chức thông tin theo các tab chuyên biệt
- **Real-time updates**: Cập nhật dữ liệu theo thời gian thực
- **Customizable monitoring**: Tùy chỉnh interval và duration giám sát

## 📋 Yêu Cầu Hệ Thống

### Phần Mềm Cần Thiết
- **Python**: 3.7 hoặc cao hơn
- **Hệ điều hành**: Windows 10+, Linux (Ubuntu 18.04+), macOS 10.14+
- **RAM**: Tối thiểu 512MB (khuyến nghị 1GB+)
- **Dung lượng**: 50MB trống

### Python Dependencies
```bash
psutil>=5.8.0
requests>=2.25.0
```

## 🛠️ Hướng Dẫn Cài Đặt

### Bước 1: Clone Repository
```bash
git clone https://github.com/yourusername/network-monitor-suite.git
cd network-monitor-suite
```

### Bước 2: Cài Đặt Dependencies
```bash
# Sử dụng pip
pip install psutil requests

# Hoặc sử dụng requirements.txt (nếu có)
pip install -r requirements.txt
```

### Bước 3: Kiểm Tra Cài Đặt
```bash
python network_monitor.py --help
```

## 📖 Hướng Dẫn Sử Dụng

### Network Monitor (Command Line)
```bash
# Giám sát cơ bản với interval 5 giây
python network_monitor.py

# Giám sát với tham số tùy chỉnh
python network_monitor.py --interval 3 --duration 300

# Hiển thị kết nối hiện tại
python network_monitor.py --show-current

# Export dữ liệu
python network_monitor.py --export-csv connections.csv
```

### Network Monitor GUI
```bash
# Khởi chạy giao diện đồ họa
python network_monitor_gui.py
```

**Các thao tác trong GUI:**
1. Click **"Start Monitoring"** để bắt đầu giám sát
2. Sử dụng các tab để xem thông tin chi tiết:
   - **Current**: Kết nối đang hoạt động
   - **Process**: Thông tin process
   - **History**: Lịch sử kết nối
   - **Statistics**: Thống kê tổng quan
3. Click **"Export"** để xuất dữ liệu
4. Click **"Clear History"** để xóa lịch sử

### Web Address Monitor (Command Line)
```bash
# Giám sát web traffic
python web_monitor.py

# Giám sát với interval tùy chỉnh
python web_monitor.py --interval 2 --duration 600

# Hiển thị hoạt động web hiện tại
python web_monitor.py --show-current
```

### Web Monitor GUI
```bash
# Khởi chạy giao diện web monitor
python web_monitor_gui.py
```

**Tính năng đặc biệt của Web Monitor:**
- **Active Websites**: Danh sách website đang truy cập
- **Domains**: Thống kê theo tên miền
- **Categories**: Phân loại website (Social, News, Shopping, etc.)
- **Browsers**: Hoạt động theo từng trình duyệt
- **History**: Lịch sử truy cập web chi tiết

## 🔧 Cấu Hình Nâng Cao

### Tùy Chỉnh Web Ports
Trong file `web_monitor.py`, bạn có thể tùy chỉnh các port được coi là web traffic:
```python
self.web_ports = {80, 443, 8080, 8443, 3000, 5000, 8000, 9000}
```

### Thêm Browser Mới
Để thêm trình duyệt mới vào danh sách theo dõi:
```python
self.browsers = {
    'chrome.exe', 'firefox.exe', 'msedge.exe', 'your_browser.exe'
}
```

## 📊 Định Dạng Dữ Liệu Export

### CSV Format
```csv
Timestamp,Local Address,Remote Address,Status,Protocol,Process Name,PID
2024-01-15 10:30:25,192.168.1.100:12345,93.184.216.34:443,ESTABLISHED,TCP,chrome.exe,1234
```

### JSON Format
```json
{
  "timestamp": "2024-01-15 10:30:25",
  "local_address": "192.168.1.100:12345",
  "remote_address": "93.184.216.34:443",
  "status": "ESTABLISHED",
  "protocol": "TCP",
  "process_info": {
    "name": "chrome.exe",
    "pid": 1234,
    "exe": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
  }
}
```

## 🤝 Đóng Góp (Contributing)

Chúng tôi hoan nghênh mọi đóng góp từ cộng đồng! Để đóng góp:

### Quy Trình Đóng Góp
1. **Fork** repository này
2. Tạo **feature branch**: `git checkout -b feature/AmazingFeature`
3. **Commit** thay đổi: `git commit -m 'Add some AmazingFeature'`
4. **Push** lên branch: `git push origin feature/AmazingFeature`
5. Tạo **Pull Request**

### Hướng Dẫn Phát Triển
- Tuân thủ **PEP 8** coding style
- Thêm **docstring** cho các function mới
- Viết **unit tests** cho các tính năng mới
- Cập nhật **documentation** khi cần thiết

### Báo Lỗi (Bug Reports)
Khi báo lỗi, vui lòng bao gồm:
- Mô tả chi tiết lỗi
- Các bước tái tạo lỗi
- Thông tin hệ thống (OS, Python version)
- Log files (nếu có)

## 📄 Giấy Phép (License)

Dự án này được phân phối dưới **MIT License**. Xem file [LICENSE](LICENSE) để biết thêm chi tiết.

```
MIT License

Copyright (c) 2024 Network Monitor Suite

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

## 👨‍💻 Thông Tin Tác Giả & Liên Hệ

### Tác Giả
- **Tên**: Network Monitor Suite Team
- **Email**: contact@networkmonitor.dev
- **GitHub**: [@networkmonitor](https://github.com/networkmonitor)

### Liên Hệ & Hỗ Trợ
- **📧 Email**: support@networkmonitor.dev
- **🐛 Bug Reports**: [GitHub Issues](https://github.com/yourusername/network-monitor-suite/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/yourusername/network-monitor-suite/discussions)
- **📖 Documentation**: [Wiki](https://github.com/yourusername/network-monitor-suite/wiki)

### Social Media
- **Twitter**: [@NetworkMonitorSuite](https://twitter.com/NetworkMonitorSuite)
- **LinkedIn**: [Network Monitor Suite](https://linkedin.com/company/network-monitor-suite)

---

## 🌟 Đánh Giá & Chia Sẻ

Nếu bạn thấy dự án này hữu ích, hãy:
- ⭐ **Star** repository này trên GitHub
- 🍴 **Fork** để phát triển thêm
- 📢 **Chia sẻ** với bạn bè và đồng nghiệp
- 💬 **Feedback** để chúng tôi cải thiện

**Cảm ơn bạn đã sử dụng Network & Web Monitor Suite!** 🚀

---

*Được phát triển với ❤️ bởi Network Monitor Suite Team*