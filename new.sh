#!/bin/bash

# Let's Encrypt Intermediate Certificate Manager
# Compatible with Debian 11 and Debian 12 (Intel & ARM)
# Requires: bash 4.0+ (for associative arrays)
# Handles: E7, E8, R12, R13 intermediate certificates
# 
# Simple Usage: sudo ./letsencrypt_cert_manager.sh
# 
# What it does:
# - Downloads missing certificates automatically
# - Skips certificates that are already present and valid
# - Validates all certificates for correctness
# - Provides comprehensive logging and reporting

set -euo pipefail

# Check bash version compatibility
check_bash_version() {
    local bash_version
    bash_version=$(bash --version | head -n1 | grep -oE '[0-9]+\.[0-9]+' | head -n1)
    local major_version
    major_version=$(echo "$bash_version" | cut -d. -f1)
    
    if [[ $major_version -lt 4 ]]; then
        echo "Error: This script requires bash 4.0 or higher for associative arrays."
        echo "Current bash version: $bash_version"
        echo "On macOS, install newer bash with: brew install bash"
        echo "On Debian/Ubuntu, bash 4.0+ is typically already installed."
        exit 1
    fi
}

# Early bash version check
check_bash_version

# Script configuration
SCRIPT_VERSION="2.1.0"
LOG_LEVEL="INFO"  # Production logging level

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# System paths
readonly LETSENCRYPT_CERT_DIR="/usr/local/share/ca-certificates"
readonly TEMP_DIR="/tmp/letsencrypt_certs_$$"
readonly LOG_FILE="/var/log/letsencrypt-cert-manager.log"

# Certificate definitions
declare -A CERTIFICATES
CERTIFICATES["E7"]="https://letsencrypt.org/certs/2024/e7.pem"
CERTIFICATES["E8"]="https://letsencrypt.org/certs/2024/e8.pem"  
CERTIFICATES["R12"]="https://letsencrypt.org/certs/2024/r12.pem"
CERTIFICATES["R13"]="https://letsencrypt.org/certs/2024/r13.pem"


# Expected certificate subjects for validation
declare -A CERT_SUBJECTS
CERT_SUBJECTS["E7"]="CN=E7,O=Let's Encrypt,C=US"
CERT_SUBJECTS["E8"]="CN=E8,O=Let's Encrypt,C=US"
CERT_SUBJECTS["R12"]="CN=R12,O=Let's Encrypt,C=US"
CERT_SUBJECTS["R13"]="CN=R13,O=Let's Encrypt,C=US"

# Global counters
CERTS_CHECKED=0
CERTS_ALREADY_PRESENT=0
CERTS_DOWNLOADED=0
CERTS_FAILED=0

# Logging functions
log_debug() { [[ "$LOG_LEVEL" == "DEBUG" ]] && echo -e "${PURPLE}[DEBUG]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"; }
log_info() { echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"; }

# Initialize logging
init_logging() {
    local log_dir
    log_dir=$(dirname "$LOG_FILE")
    
    if [[ ! -d "$log_dir" ]]; then
        mkdir -p "$log_dir" || {
            echo "Warning: Could not create log directory $log_dir"
            LOG_FILE="/tmp/letsencrypt-cert-manager.log"
        }
    fi
    
    # Rotate log if it's too large (>10MB)
    if [[ -f "$LOG_FILE" ]] && [[ $(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0) -gt 10485760 ]]; then
        mv "$LOG_FILE" "${LOG_FILE}.old"
    fi
    
    echo "========================================" >> "$LOG_FILE"
    echo "Let's Encrypt Certificate Manager v$SCRIPT_VERSION" >> "$LOG_FILE"
    echo "Started at: $(date)" >> "$LOG_FILE"
    echo "========================================" >> "$LOG_FILE"
}

# Display banner
display_banner() {
    echo -e "${CYAN}"
    echo "=================================================================="
    echo "   Let's Encrypt Certificate Manager v$SCRIPT_VERSION"
    echo "=================================================================="
    echo -e "${NC}"
    echo "Certificates: E7, E8, R12, R13"
    echo "Storage: $LETSENCRYPT_CERT_DIR/letsencrypt-*.crt"
    echo "Log file: $LOG_FILE"
    echo
    echo "The script will automatically:"
    echo "  • Download missing certificates"
    echo "  • Install certificates in system trust store"
    echo "  • Skip certificates that are already present and valid"
    echo "  • Validate all certificates for correctness"
    echo
}

# Check if script is run as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Error: This script must be run as root"
        echo "Usage: sudo $0"
        echo
        echo "This script will:"
        echo "  • Download missing Let's Encrypt certificates (E7, E8, R12, R13)"
        echo "  • Install certificates in system trust store"
        echo "  • Skip certificates that are already present and valid"
        echo "  • Validate all certificates for correctness"
        echo "  • Save certificates to: $LETSENCRYPT_CERT_DIR/"
        echo "  • Update system trust store with: update-ca-certificates"
        echo "  • Log all activities to: $LOG_FILE"
        exit 1
    fi
}

# Check Debian version compatibility
check_debian_version() {
    if [[ ! -f /etc/debian_version ]]; then
        log_error "This script is designed for Debian systems only"
        exit 1
    fi
    
    local debian_version debian_major
    debian_version=$(cat /etc/debian_version)
    debian_major=$(echo "$debian_version" | cut -d. -f1)
    
    log_info "Detected Debian version: $debian_version"
    
    if [[ ! "$debian_major" =~ ^(11|12)$ ]]; then
        log_warning "This script is tested on Debian 11 & 12. Current version: $debian_major"
        log_warning "Proceeding with caution..."
    fi
    
    # Detect architecture
    local arch
    arch=$(uname -m)
    log_info "Architecture: $arch"
}

# Check network connectivity
check_network_connectivity() {
    log_info "Checking network connectivity..."
    
    # Test connectivity to Let's Encrypt
    if ! curl -s --connect-timeout 10 --max-time 15 https://letsencrypt.org/ >/dev/null 2>&1; then
        log_error "Cannot reach letsencrypt.org - check network connectivity"
        log_error "This script requires internet access to download certificates"
        exit 1
    fi
    
    log_success "Network connectivity verified"
}


# Install required dependencies
install_dependencies() {
    log_info "Checking and installing dependencies..."
    
    # Update package list
    if ! apt-get update -qq; then
        log_warning "Failed to update package list, continuing anyway..."
    fi
    
    local packages=("curl" "ca-certificates" "openssl" "coreutils")
    local missing_packages=()
    
    for package in "${packages[@]}"; do
        if ! dpkg -l "$package" &>/dev/null; then
            missing_packages+=("$package")
        fi
    done
    
    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        log_info "Installing missing packages: ${missing_packages[*]}"
        if apt-get install -y "${missing_packages[@]}"; then
            log_success "Dependencies installed successfully"
        else
            log_error "Failed to install dependencies"
            exit 1
        fi
    else
        log_success "All dependencies are already installed"
    fi
}

# Create necessary directories
setup_directories() {
    local dirs=("$LETSENCRYPT_CERT_DIR" "$TEMP_DIR")
    
    for dir in "${dirs[@]}"; do
        if [[ ! -d "$dir" ]]; then
            if mkdir -p "$dir"; then
                log_debug "Created directory: $dir"
            else
                log_error "Failed to create directory: $dir"
                exit 1
            fi
        fi
    done
    
    # Set appropriate permissions
    chmod 755 "$LETSENCRYPT_CERT_DIR"
    chmod 700 "$TEMP_DIR"
    
    log_info "Certificate directory: $LETSENCRYPT_CERT_DIR (system CA store)"
}

# Get certificate fingerprint for comparison
get_cert_fingerprint() {
    local cert_file="$1"
    
    if [[ -f "$cert_file" ]]; then
        openssl x509 -in "$cert_file" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2
    else
        echo ""
    fi
}

# Validate certificate content and issuer
validate_certificate() {
    local cert_file="$1"
    local cert_name="$2"
    local expected_subject="${CERT_SUBJECTS[$cert_name]}"
    
    if [[ ! -f "$cert_file" ]]; then
        log_debug "Certificate file does not exist: $cert_file"
        return 1
    fi
    
    # Check if file is a valid certificate
    if ! openssl x509 -in "$cert_file" -noout -text >/dev/null 2>&1; then
        log_warning "Invalid certificate format: $cert_file"
        return 1
    fi
    
    # Check certificate subject
    local actual_subject
    actual_subject=$(openssl x509 -in "$cert_file" -noout -subject -nameopt RFC2253 2>/dev/null | sed 's/subject=//')
    
    # Exact subject validation
    if [[ "$actual_subject" != "$expected_subject" ]]; then
        # Fallback to substring validation for compatibility
        if [[ "$actual_subject" != *"$cert_name"* ]] || [[ "$actual_subject" != *"Let's Encrypt"* ]]; then
            log_warning "Certificate subject validation failed for $cert_name"
            log_debug "Expected exact: $expected_subject"
            log_debug "Actual: $actual_subject"
            return 1
        else
            log_debug "Certificate $cert_name: exact subject match failed, but substring validation passed"
        fi
    else
        log_debug "Certificate $cert_name: exact subject validation passed"
    fi
    
    # Check certificate validity period
    local not_after
    not_after=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
    local expiry_epoch
    expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null || echo 0)
    local current_epoch
    current_epoch=$(date +%s)
    
    if [[ $expiry_epoch -le $current_epoch ]]; then
        log_warning "Certificate $cert_name has expired: $not_after"
        return 1
    fi
    
    # Check if certificate expires soon (within 30 days)
    local days_until_expiry
    days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
    
    if [[ $days_until_expiry -le 30 ]]; then
        log_warning "Certificate $cert_name expires soon: $not_after ($days_until_expiry days)"
    fi
    
    log_debug "Certificate $cert_name validation passed"
    return 0
}

# Check if certificate is present and valid
is_certificate_present() {
    local cert_name="$1"
    local cert_file="$LETSENCRYPT_CERT_DIR/letsencrypt-$cert_name.crt"
    
    log_debug "Checking certificate presence: $cert_file"
    
    if [[ -f "$cert_file" ]]; then
        log_info "Certificate $cert_name found, validating..."
        if validate_certificate "$cert_file" "$cert_name"; then
            log_success "Certificate $cert_name is present and valid"
            return 0
        else
            log_warning "Certificate $cert_name exists but is invalid - will re-download"
            return 1
        fi
    fi
    
    log_info "Certificate $cert_name is not present - will download"
    return 1
}

# Download certificate with retry logic and rate limiting
download_certificate() {
    local cert_name="$1"
    local cert_url="$2"
    local temp_file="$TEMP_DIR/$cert_name.pem"
    local final_file="$LETSENCRYPT_CERT_DIR/letsencrypt-$cert_name.crt"
    local max_retries=3
    local retry_delay=5
    
    log_info "Downloading certificate $cert_name from $cert_url"
    
    # Rate limiting: sleep 2 seconds between downloads to be respectful to Let's Encrypt
    if [[ $CERTS_DOWNLOADED -gt 0 ]]; then
        log_debug "Rate limiting: waiting 2 seconds before download"
        sleep 2
    fi
    
    for ((attempt=1; attempt<=max_retries; attempt++)); do
        log_debug "Download attempt $attempt/$max_retries for $cert_name"
        
        # Enhanced curl with better error handling and user agent
        local http_code
        http_code=$(curl -L -s -w "%{http_code}" -o "$temp_file" \
            --connect-timeout 30 --max-time 60 \
            --user-agent "LetsEncrypt-Cert-Manager/2.1.0" \
            --fail-with-body \
            "$cert_url" 2>/dev/null || echo "000")
        
        if [[ "$http_code" == "200" ]]; then
            log_debug "Download successful (HTTP $http_code), validating certificate $cert_name"
            
            if validate_certificate "$temp_file" "$cert_name"; then
                # Move validated certificate to final location with correct extension
                if mv "$temp_file" "$final_file"; then
                    chmod 644 "$final_file"
                    log_success "Certificate $cert_name downloaded and saved to $final_file"
                    return 0
                else
                    log_error "Failed to save certificate $cert_name to final location"
                    return 1
                fi
            else
                log_warning "Downloaded certificate $cert_name failed validation"
            fi
        else
            log_debug "Download failed for $cert_name (HTTP $http_code)"
            if [[ "$http_code" == "404" ]]; then
                log_error "Certificate URL not found (HTTP 404): $cert_url"
                log_error "This may indicate the certificate URL has changed"
                return 1
            fi
        fi
        
        if [[ $attempt -lt $max_retries ]]; then
            log_info "Download failed, retrying in $retry_delay seconds..."
            sleep $retry_delay
            retry_delay=$((retry_delay * 2))  # Exponential backoff
        fi
    done
    
    log_error "Failed to download certificate $cert_name after $max_retries attempts"
    return 1
}

# Update CA certificates database
update_ca_certificates() {
    log_info "Updating CA certificates database..."
    
    if update-ca-certificates >/dev/null 2>&1; then
        log_success "CA certificates database updated successfully"
        return 0
    else
        log_error "Failed to update CA certificates database"
        return 1
    fi
}

# Process a single certificate
# Return codes: 0=downloaded, 1=failed, 2=already present (no change)
process_certificate() {
    local cert_name="$1"
    local cert_url="${CERTIFICATES[$cert_name]}"
    local force_download="$2"
    
    log_info "Checking certificate: $cert_name"
    ((CERTS_CHECKED++))
    
    # Check if certificate is already present and valid
    if [[ "$force_download" != "true" ]] && is_certificate_present "$cert_name"; then
        log_success "✓ Certificate $cert_name is present and valid - skipping download"
        ((CERTS_ALREADY_PRESENT++))
        return 2  # No change made
    fi
    
    if [[ "$force_download" == "true" ]]; then
        log_info "Force downloading certificate $cert_name (overriding existing)"
    fi
    
    # Download certificate
    log_info "→ Downloading certificate $cert_name..."
    if download_certificate "$cert_name" "$cert_url"; then
        log_success "✓ Certificate $cert_name downloaded and validated successfully"
        ((CERTS_DOWNLOADED++))
        return 0  # Certificate was downloaded
    else
        log_error "✗ Failed to download/validate certificate $cert_name"
        ((CERTS_FAILED++))
        return 1
    fi
}

# Generate summary report with expiry warnings
generate_summary() {
    echo
    echo -e "${CYAN}=================================================================="
    echo "                    CERTIFICATE SUMMARY"
    echo -e "==================================================================${NC}"
    echo "Certificates checked: $CERTS_CHECKED"
    echo "Already present: $CERTS_ALREADY_PRESENT"
    echo "Downloaded: $CERTS_DOWNLOADED"
    echo "Failed: $CERTS_FAILED"
    echo
    
    # Track certificates expiring soon
    local expiring_soon=0
    local current_epoch
    current_epoch=$(date +%s)
    
    # List current certificate status in deterministic order
    echo "Current certificate status:"
    local cert_order=("E7" "E8" "R12" "R13")
    for cert_name in "${cert_order[@]}"; do
        local cert_file="$LETSENCRYPT_CERT_DIR/letsencrypt-$cert_name.crt"
        if [[ -f "$cert_file" ]] && validate_certificate "$cert_file" "$cert_name" >/dev/null 2>&1; then
            echo -e "  ${GREEN}✓${NC} Let's Encrypt $cert_name"
            
            # Show certificate details with expiry warning
            local not_after subject fingerprint expiry_epoch days_until_expiry
            not_after=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
            subject=$(openssl x509 -in "$cert_file" -noout -subject 2>/dev/null | sed 's/subject=//')
            fingerprint=$(openssl x509 -in "$cert_file" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
            expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null || echo 0)
            days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
            
            echo "    File: $cert_file"
            echo "    Subject: $subject"
            echo "    Expires: $not_after"
            
            if [[ $days_until_expiry -le 30 ]]; then
                echo -e "    ${YELLOW}⚠ WARNING: Expires in $days_until_expiry days!${NC}"
                ((expiring_soon++))
            else
                echo "    Expires in: $days_until_expiry days"
            fi
            
            echo "    SHA256: ${fingerprint:0:32}..."
        else
            echo -e "  ${RED}✗${NC} Let's Encrypt $cert_name"
            echo "    Status: Missing or invalid"
        fi
        echo
    done
    
    # Summary and warnings
    if [[ $CERTS_FAILED -eq 0 ]]; then
        log_success "All certificates processed successfully!"
        echo "Certificates are installed at: $LETSENCRYPT_CERT_DIR/letsencrypt-*.crt"
        echo "System trust store updated - certificates are available to all applications"
    else
        log_warning "$CERTS_FAILED certificates failed to download"
    fi
    
    if [[ $expiring_soon -gt 0 ]]; then
        echo
        log_warning "$expiring_soon certificate(s) expire within 30 days - consider monitoring"
    fi
    
    # Generate monitoring metrics
    generate_monitoring_output
}

# Generate monitoring-friendly output
generate_monitoring_output() {
    echo
    echo "MONITORING_METRICS_START"
    echo "letsencrypt_certs_checked=$CERTS_CHECKED"
    echo "letsencrypt_certs_already_present=$CERTS_ALREADY_PRESENT"
    echo "letsencrypt_certs_downloaded=$CERTS_DOWNLOADED"
    echo "letsencrypt_certs_failed=$CERTS_FAILED"
    echo "letsencrypt_script_success=$([[ $CERTS_FAILED -eq 0 ]] && echo 1 || echo 0)"
    echo "letsencrypt_script_version=$SCRIPT_VERSION"
    echo "letsencrypt_script_timestamp=$(date +%s)"
    
    # Per-certificate status
    local cert_order=("E7" "E8" "R12" "R13")
    for cert_name in "${cert_order[@]}"; do
        local cert_file="$LETSENCRYPT_CERT_DIR/letsencrypt-$cert_name.crt"
        if [[ -f "$cert_file" ]] && validate_certificate "$cert_file" "$cert_name" >/dev/null 2>&1; then
            local expiry_epoch current_epoch days_until_expiry
            local not_after
            not_after=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2)
            expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null || echo 0)
            current_epoch=$(date +%s)
            days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
            
            echo "letsencrypt_cert_${cert_name,,}_present=1"
            echo "letsencrypt_cert_${cert_name,,}_days_until_expiry=$days_until_expiry"
        else
            echo "letsencrypt_cert_${cert_name,,}_present=0"
            echo "letsencrypt_cert_${cert_name,,}_days_until_expiry=-1"
        fi
    done
    echo "MONITORING_METRICS_END"
}

# Cleanup function
cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
        log_debug "Cleaned up temporary directory: $TEMP_DIR"
    fi
}

# Signal handler for cleanup
cleanup_on_exit() {
    local exit_code=$?
    cleanup
    if [[ $exit_code -ne 0 ]]; then
        log_error "Script exited with error code: $exit_code"
    fi
    exit $exit_code
}


# Main function
main() {
    init_logging
    display_banner
    
    # Pre-flight checks
    check_root
    check_debian_version
    check_network_connectivity
    
    # Setup
    install_dependencies
    setup_directories
    
    # Process certificates in deterministic order
    local cert_order=("E7" "E8" "R12" "R13")
    
    log_info "Starting certificate processing..."
    echo
    
    for cert_name in "${cert_order[@]}"; do
        echo "----------------------------------------"
        
        local result
        process_certificate "$cert_name" "false"  # Never force download - let logic decide
        result=$?
        
        case $result in
            0)
                log_debug "Certificate $cert_name: successfully downloaded"
                ;;
            2)
                log_debug "Certificate $cert_name: already present and valid"
                ;;
            1)
                log_debug "Certificate $cert_name: download failed"
                ;;
        esac
    done
    
    echo "----------------------------------------"
    echo
    
    # Update CA certificates if any were downloaded
    if [[ $CERTS_DOWNLOADED -gt 0 ]]; then
        log_info "Updating system trust store with new certificates..."
        if update_ca_certificates; then
            log_success "System trust store updated - certificates are now available to all applications"
        else
            log_warning "Failed to update system trust store - certificates downloaded but may not be accessible"
        fi
    else
        log_info "No new certificates downloaded - trust store update not needed"
    fi
    
    # Generate summary
    generate_summary
    
    if [[ $CERTS_FAILED -eq 0 ]]; then
        log_success "Certificate management completed successfully"
        exit 0
    else
        log_error "Certificate management completed with $CERTS_FAILED failures"
        exit 1
    fi
}

# Set up signal handlers
trap cleanup_on_exit EXIT INT TERM

# Run main function
main
