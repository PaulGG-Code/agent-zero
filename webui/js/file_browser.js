const fileBrowserModalProxy = {
  isOpen: false,
  isLoading: false,
  uploadProgress: null,

  browser: {
    title: "File Browser",
    currentPath: "",
    entries: [],
    parentPath: "",
    sortBy: "name",
    sortDirection: "asc",
  },

  // Initialize navigation history
  history: [],

  // Security scanning state
  securityScan: {
    isScanning: false,
    scannedFiles: new Set(),
    secureFiles: new Set(),
    vulnerableFiles: new Set(),
    criticalFiles: new Set()
  },

  async openModal(path) {
    const modalEl = document.getElementById("fileBrowserModal");
    const modalAD = Alpine.$data(modalEl);

    modalAD.isOpen = true;
    modalAD.isLoading = true;
    modalAD.history = []; // reset history when opening modal

    // Initialize currentPath to root if it's empty
    if (path) modalAD.browser.currentPath = path;
    else if (!modalAD.browser.currentPath)
      modalAD.browser.currentPath = "$WORK_DIR";

    await modalAD.fetchFiles(modalAD.browser.currentPath);
  },

  isArchive(filename) {
    const archiveExts = ["zip", "tar", "gz", "rar", "7z"];
    const ext = filename.split(".").pop().toLowerCase();
    return archiveExts.includes(ext);
  },

  // Enhanced file type detection with security assessment
  getFileSecurityLevel(file) {
    const ext = file.name.split(".").pop().toLowerCase();
    
    // Critical file types (executables, scripts)
    const criticalExts = ["exe", "bat", "cmd", "ps1", "sh", "py", "js", "php", "rb", "pl"];
    if (criticalExts.includes(ext)) return "critical";
    
    // Vulnerable file types (documents, archives)
    const vulnerableExts = ["doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "zip", "rar", "7z"];
    if (vulnerableExts.includes(ext)) return "vulnerable";
    
    // Secure file types (text, images, data)
    const secureExts = ["txt", "md", "json", "xml", "csv", "png", "jpg", "jpeg", "gif", "svg"];
    if (secureExts.includes(ext)) return "secure";
    
    return "unknown";
  },

  // Get appropriate icon for file type
  getFileIcon(file) {
    if (file.is_dir) {
      return this.getFileSecurityLevel(file) === "secure" ? "folder-secure" : "folder";
    }
    
    const securityLevel = this.getFileSecurityLevel(file);
    if (this.isArchive(file.name)) {
      return securityLevel === "secure" ? "archive-secure" : "archive";
    }
    
    if (securityLevel === "secure") {
      return "file-secure";
    }
    
    return file.type === 'unknown' ? 'file' : file.type;
  },

  async fetchFiles(path = "") {
    this.isLoading = true;
    try {
      const response = await fetch(
        `/get_work_dir_files?path=${encodeURIComponent(path)}`
      );

      if (response.ok) {
        const data = await response.json();
        this.browser.entries = data.data.entries.map(entry => ({
          ...entry,
          securityLevel: this.getFileSecurityLevel(entry),
          icon: this.getFileIcon(entry)
        }));
        this.browser.currentPath = data.data.current_path;
        this.browser.parentPath = data.data.parent_path;
        
        // Start security scan for new files
        this.startSecurityScan();
      } else {
        console.error("Error fetching files:", await response.text());
        this.browser.entries = [];
      }
    } catch (error) {
      window.toastFetchError("Error fetching files", error);
      this.browser.entries = [];
    } finally {
      this.isLoading = false;
    }
  },

  // Security scanning simulation
  async startSecurityScan() {
    if (this.securityScan.isScanning) return;
    
    this.securityScan.isScanning = true;
    const unscannedFiles = this.browser.entries.filter(
      file => !this.securityScan.scannedFiles.has(file.path)
    );
    
    for (const file of unscannedFiles) {
      await this.scanFile(file);
      await new Promise(resolve => setTimeout(resolve, 100)); // Simulate scan time
    }
    
    this.securityScan.isScanning = false;
  },

  async scanFile(file) {
    // Simulate security scanning
    const securityLevel = this.getFileSecurityLevel(file);
    this.securityScan.scannedFiles.add(file.path);
    
    // Update file security status
    const fileIndex = this.browser.entries.findIndex(f => f.path === file.path);
    if (fileIndex !== -1) {
      this.browser.entries[fileIndex].securityLevel = securityLevel;
      this.browser.entries[fileIndex].scanned = true;
    }
  },

  async navigateToFolder(path) {
    // Push current path to history before navigating
    if (this.browser.currentPath !== path) {
      this.history.push(this.browser.currentPath);
    }
    await this.fetchFiles(path);
  },

  async navigateUp() {
    if (this.browser.parentPath !== "") {
      // Push current path to history before navigating up
      this.history.push(this.browser.currentPath);
      await this.fetchFiles(this.browser.parentPath);
    }
  },

  sortFiles(entries) {
    return [...entries].sort((a, b) => {
      // Folders always come first
      if (a.is_dir !== b.is_dir) {
        return a.is_dir ? -1 : 1;
      }

      const direction = this.browser.sortDirection === "asc" ? 1 : -1;
      switch (this.browser.sortBy) {
        case "name":
          return direction * a.name.localeCompare(b.name);
        case "size":
          return direction * (a.size - b.size);
        case "date":
          return direction * (new Date(a.modified) - new Date(b.modified));
        case "security":
          const securityOrder = { "secure": 0, "vulnerable": 1, "critical": 2, "unknown": 3 };
          return direction * (securityOrder[a.securityLevel] - securityOrder[b.securityLevel]);
        default:
          return 0;
      }
    });
  },

  toggleSort(column) {
    if (this.browser.sortBy === column) {
      this.browser.sortDirection =
        this.browser.sortDirection === "asc" ? "desc" : "asc";
    } else {
      this.browser.sortBy = column;
      this.browser.sortDirection = "asc";
    }
  },

  async deleteFile(file) {
    if (!confirm(`Are you sure you want to delete ${file.name}?`)) {
      return;
    }

    try {
      const response = await fetch("/delete_work_dir_file", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          path: file.path,
          currentPath: this.browser.currentPath,
        }),
      });

      if (response.ok) {
        const data = await response.json();
        this.browser.entries = this.browser.entries.filter(
          (entry) => entry.path !== file.path
        );
        this.showToast("File deleted successfully.", "success");
      } else {
        this.showToast(`Error deleting file: ${await response.text()}`, "error");
      }
    } catch (error) {
      window.toastFetchError("Error deleting file", error);
      this.showToast("Error deleting file", "error");
    }
  },

  // Handle drag and drop file upload
  async handleFileDrop(event) {
    event.target.classList.remove('drag-over');
    const files = event.dataTransfer.files;
    if (files.length) {
      await this.processFileUpload(files);
    }
  },

  // Enhanced file upload with progress tracking
  async handleFileUpload(event) {
    const files = event.target.files;
    if (files.length) {
      await this.processFileUpload(files);
    }
  },

  // Common file upload processing
  async processFileUpload(files) {
    try {
      if (!files.length) return;

      // Show upload progress
      this.showUploadProgress(files.length);

      const formData = new FormData();
      formData.append("path", this.browser.currentPath);

      let uploadedCount = 0;
      for (let i = 0; i < files.length; i++) {
        const ext = files[i].name.split(".").pop().toLowerCase();
        if (!["zip", "tar", "gz", "rar", "7z"].includes(ext)) {
          if (files[i].size > 100 * 1024 * 1024) {
            // 100MB
            this.showToast(
              `File ${files[i].name} exceeds the maximum allowed size of 100MB.`,
              "warning"
            );
            continue;
          }
        }
        formData.append("files[]", files[i]);
        
        // Update progress
        uploadedCount++;
        this.updateUploadProgress(uploadedCount, files.length);
      }

      // Proceed with upload after validation
      const response = await fetch("/upload_work_dir_files", {
        method: "POST",
        body: formData,
      });

      if (response.ok) {
        const data = await response.json();
        // Update the file list with new data
        this.browser.entries = data.data.entries.map((entry) => ({
          ...entry,
          uploadStatus: data.failed.includes(entry.name) ? "failed" : "success",
          securityLevel: this.getFileSecurityLevel(entry),
          icon: this.getFileIcon(entry)
        }));
        this.browser.currentPath = data.data.current_path;
        this.browser.parentPath = data.data.parent_path;

        // Hide upload progress
        this.hideUploadProgress();

        // Show success message
        if (data.failed && data.failed.length > 0) {
          const failedFiles = data.failed
            .map((file) => `${file.name}: ${file.error}`)
            .join("\n");
          this.showToast(`Some files failed to upload:\n${failedFiles}`, "warning");
        } else {
          this.showToast("Files uploaded successfully!", "success");
        }
        
        // Start security scan for new files
        this.startSecurityScan();
      } else {
        this.hideUploadProgress();
        this.showToast("Upload failed", "error");
      }
    } catch (error) {
      this.hideUploadProgress();
      window.toastFetchError("Error uploading files", error);
      this.showToast("Error uploading files", "error");
    }
  },

  // Upload progress management
  showUploadProgress(totalFiles) {
    this.uploadProgress = {
      total: totalFiles,
      current: 0,
      visible: true
    };
    this.createUploadProgressElement();
  },

  updateUploadProgress(current, total) {
    if (this.uploadProgress) {
      this.uploadProgress.current = current;
      this.updateUploadProgressElement();
    }
  },

  hideUploadProgress() {
    this.uploadProgress = null;
    this.removeUploadProgressElement();
  },

  createUploadProgressElement() {
    const progressEl = document.createElement('div');
    progressEl.className = 'upload-progress';
    progressEl.id = 'upload-progress';
    progressEl.innerHTML = `
      <div class="upload-progress-header">
        <span>Uploading Files</span>
        <span>${this.uploadProgress.current}/${this.uploadProgress.total}</span>
      </div>
      <div class="upload-progress-bar">
        <div class="upload-progress-fill" style="width: 0%"></div>
      </div>
    `;
    document.body.appendChild(progressEl);
  },

  updateUploadProgressElement() {
    const progressEl = document.getElementById('upload-progress');
    if (progressEl && this.uploadProgress) {
      const percentage = (this.uploadProgress.current / this.uploadProgress.total) * 100;
      const fillEl = progressEl.querySelector('.upload-progress-fill');
      const countEl = progressEl.querySelector('.upload-progress-header span:last-child');
      
      if (fillEl) fillEl.style.width = `${percentage}%`;
      if (countEl) countEl.textContent = `${this.uploadProgress.current}/${this.uploadProgress.total}`;
    }
  },

  removeUploadProgressElement() {
    const progressEl = document.getElementById('upload-progress');
    if (progressEl) {
      progressEl.remove();
    }
  },

  async downloadFile(file) {
    try {
      const downloadUrl = `/download_work_dir_file?path=${encodeURIComponent(
        file.path
      )}`;
      
      // Show download notification
      this.showToast(`Downloading ${file.name}...`, "info");
      
      const response = await fetch(downloadUrl);
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = file.name;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        this.showToast(`${file.name} downloaded successfully!`, "success");
      } else {
        this.showToast(`Error downloading ${file.name}`, "error");
      }
    } catch (error) {
      window.toastFetchError("Error downloading file", error);
      this.showToast(`Error downloading ${file.name}`, "error");
    }
  },

  // Enhanced toast notifications
  showToast(message, type = "info") {
    if (window.toast) {
      window.toast(message, type);
    } else {
      console.log(`[${type.toUpperCase()}] ${message}`);
    }
  },

  formatFileSize(size) {
    if (size === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(size) / Math.log(k));
    return parseFloat((size / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  },

  formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString() + " " + date.toLocaleTimeString();
  },

  handleClose() {
    this.isOpen = false;
    this.hideUploadProgress();
  },

  init() {
    // Initialize any additional features
    console.log("File Browser initialized with cybersecurity features");
  }
};

// Wait for Alpine to be ready
document.addEventListener("alpine:init", () => {
  Alpine.data("fileBrowserModalProxy", () => ({
    init() {
      Object.assign(this, fileBrowserModalProxy);
      // Ensure immediate file fetch when modal opens
      this.$watch("isOpen", async (value) => {
        if (value) {
          await this.fetchFiles(this.browser.currentPath);
        }
      });
    },
  }));
});

// Keep the global assignment for backward compatibility
window.fileBrowserModalProxy = fileBrowserModalProxy;

openFileLink = async function (path) {
  try {
    const resp = await window.sendJsonData("/file_info", { path });
    if (!resp.exists) {
      window.toast("File does not exist.", "error");
      return;
    }

    if (resp.is_dir) {
      fileBrowserModalProxy.openModal(resp.abs_path);
    } else {
      fileBrowserModalProxy.downloadFile({
        path: resp.abs_path,
        name: resp.file_name,
      });
    }
  } catch (e) {
    window.toastFetchError("Error opening file", e);
  }
};
window.openFileLink = openFileLink;
