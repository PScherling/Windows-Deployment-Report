# Windows Deployment Report for MDT
<img width="1056" height="786" alt="image" src="https://github.com/user-attachments/assets/b18b2ac3-66b6-426f-9b74-5191702bcc81" />

The report is HTML first, then converted to PDF, and include detailed system, security, storage, services, drivers, and configuration information collected immediately after OS deployment.
This repository contains a PowerShell-based reporting solution for Windows Client and Windows Server (Backup Server profile) systems. It includes:

- **Report:** `custom_create-deployment-report.ps1` — Generates a comprehensive post-deployment report
- **Uploader:** `custom_copy-deployment-report.ps1` — Uploads generated reports to a central file share (typically your MDT server)


The main purpose of this script package is to integrate with Microsoft Deployment Toolkit (MDT) and automatically generate a detailed system report once deployment finishes.
As a secondary use case, the reporting script can also be run manually on existing systems to audit configuration, security compliance, service states, firewall configuration, WinRM settings, and many other system properties.

The script automatically detects whether it is running on a client or server OS and adjusts its checks accordingly.

The generated report is created in HTML, converted to PDF, and includes extensive information covering:
- System hardware & OS details
- Security configuration and compliance
- Network and firewall settings
- Storage, volumes, BitLocker, and VSS
- User accounts and groups
- Installed software and drivers
- Running services
- Power configuration
- Server-specific roles & backup-security checks (when applicable)

---

## Sponsorship

If you like my work, please support me:  https://github.com/sponsors/PScherling

---

## ✨ Features

### Common (Client & Server)
- Creates an HTML report in `C:\_psc\DeploymentReport\` with a version banner and timestamp.
- Copies CSS and images from an MDT share into `C:\_psc\DeploymentReport\Media\`.
- Writes a comprehensive execution log to `C:\_psc` and uploads the log to `\\<SrvIP>\Logs$\Custom\Configuration`.
- Progress UI via `Write-Progress` throughout collection and rendering steps.
- (Expected) Converts report to PDF via a `ConvertToPDF` helper function.
- Cleans up variables via `FlushVariables`.

### Sections captured in the report
- **System Information:** Hostname, system type, manufacturer, model, serial; full CPU topology (supports multi‑CPU), RAM; OS product, version, build, release.
- **OS Security Configuration:** UAC, TLS (SSL/TLS protocol states), **EnableCertPaddingCheck**, LLMNR, WDigest, LSASS PPL, SMBv1/v3 (signing/encryption), local Administrator state, `localadm` password settings, RDP status & authentication, Location Service, Network Localization, WinRM, SNMP.
- **Firewall Configuration:** RDP, ICMP rules, overall Windows Firewall status.
- **OS Adjustments:** IPv6 state, First‑Logon animation, delayed desktop switch, WSUS server and options, OEM info, power plan, detailed power configuration.
- **Storage Information:** Volumes, BitLocker (client script), VSS.
- **Local Users & Groups:** Enumerations and membership.
- **Software & Windows Features:** Installed software (both), plus **Roles & Features** (server script).
- **System Services:** Default running services.
- **Installed Drivers:** Drivers and firmware data.

### Backup Server–only extras
- Additional hardening checks: **Windows Script Host**, **NetBIOS**, **WinHttpAutoProxy**, **WinRM/RemoteRegistry/RDP service states**.

### Uploader (`custom_copy-deployment-report.ps1`)
- Waits for report creation to finish, validates/restarts **LanmanWorkstation**.
- Mounts `\\<SrvIP>\Reports` via **New‑PSDrive** (credentialed).
- Copies the newest `.html` and `.pdf` if the destination filename **doesn't already exist**.
- Shows copy progress; removes the PSDrive; uploads & deletes the local execution log.

---

## 📂 File Layout (runtime)

```
C:\_psc\
├── DeploymentReport\
│   ├── <HOSTNAME>_WDSReport_<dd-MM-yyyy_HH-mm>.html
│   ├── <HOSTNAME>_WDSReport_<dd-MM-yyyy_HH-mm>.pdf
│   └── Media\   # Copied from \\<SrvIP>\DeploymentShare$\Scripts\Custom\DeploymentReport\Media
│       ├── styles.css
│       └── images...
└── Configure_<ConfigName>_<Computer>_<yyyy-MM-dd_HH-mm-ss>.log
```

> **Note:** The scripts assume an MDT‑style share layout and will copy `Media` (CSS/images) from `\\<SrvIP>\DeploymentShare$\Scripts\Custom\DeploymentReport\Media`.

---

## ✅ Prerequisites

- PowerShell 5.1+ (Windows).
- Run in an **elevated** session.
- Network access to:
  - `\\<SrvIP>\DeploymentShare$` (read) for report assets,
  - `\\<SrvIP>\Logs$` (write) for logs,
  - `\\<SrvIP>\Reports` (write) for output (uploader).

---

## ⚙️ Configuration

Each script contains inline configuration variables:
- **Report scripts:**
  - `$SrvIP` — MDT/Share server address.
  - Several `$global:*` runtime paths (do not change unless needed).
- **Uploader:**
  - `$SrvIP` — same as above.
  - `$user`, `$securePassword` — credentials for the `Reports`/`Logs$` shares.
  - `$MountPoint` — temporary PSDrive letter (default: `U`).
  - `$source`, `$dest` — source and destination folders.

> 🔐 **Security:** Avoid hard‑coding plaintext passwords. Prefer Windows Credential Manager, or domain/Kerberos auth.

---

## 🚀 Usage

### Generate a report
```powershell
# Elevated session
Set-ExecutionPolicy Bypass
.\custom_create-deployment-report.ps1
```

### Generate a report with BAckup Server Security Compliance Checks
```powershell
# Elevated session
Set-ExecutionPolicy Bypass
.\custom_create-deployment-report.ps1 -IsBackupSrv
```

### Generate a report and upload local log file to server
```powershell
# Elevated session
Set-ExecutionPolicy Bypass
.\custom_create-deployment-report.ps1 -UploadLocalLog
```

### Generate a report and delete local logfile in the end
```powershell
# Elevated session
Set-ExecutionPolicy Bypass
.\custom_create-deployment-report.ps1 -DeleteLocalLog
```

### Upload the report to the share
```powershell
# Elevated session
Set-ExecutionPolicy Bypass
.\custom_copy-deployment-report.ps1
```

> The uploader waits briefly, mounts `\\<SrvIP>\Reports`, and copies the **.html** and **.pdf** if not already present.

---

## 🛠 Troubleshooting

- **No PDF generated:** Ensure `ConvertToPDF` exists and can access the msedge application.
- **“Access denied” to shares:** Confirm credentials and share/NTFS permissions. Try mapping the share manually.
- **LanmanWorkstation service issues:** The uploader restarts the service; if it fails, check dependent services and event logs.
- **Blank sections in report:** Some checks are OS/role dependent. Make sure required cmdlets/roles are installed (e.g., `Get-WindowsFeature` on Server).

---

## 🧾 Appendix: High‑Level Checks

**Security & Hardening:** UAC, TLS/SSL states (SSL2/3/TLS1.0/1.1/1.2/1.3), CertPaddingCheck, LLMNR, WDigest, LSASS PPL, SMBv1 disable, SMBv3 signing/encryption, local Administrator state, RDP status/authentication, WinRM, SNMP.

**Backup Server extras:** Windows Script Host, NetBIOS, WinHttpAutoProxy, WinRM/RemoteRegistry/RDP service checks.

**System & Config:** OS/product/version/build, CPU (multi‑CPU aware), RAM, WSUS server/options, OEM info, IPv6 state, First‑Logon animation, delayed desktop switch, power plan & detailed power configuration.

**Storage:** Volumes, BitLocker (client), VSS.

**Inventory:** Local users & groups, installed software, roles & features (server), default running services, installed drivers/firmware.

---

## 👤 Author

**Author:** Patrick Scherling  
**Contact:** @Patrick Scherling  

---

> ⚡ *“Automate. Standardize. Simplify.”*  
> Part of Patrick Scherling’s IT automation suite for modern Windows Server infrastructure management.
