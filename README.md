# Elasticsearch Installation Guide

Elasticsearch is a free and open-source distributed, RESTful search and analytics engine. Originally developed by Shay Banon and now maintained by Elastic N.V., Elasticsearch is built on Apache Lucene and designed for horizontal scalability, reliability, and real-time search. It serves as a FOSS alternative to commercial search solutions like Amazon CloudSearch, Azure Cognitive Search, or Splunk Enterprise, offering enterprise-grade features including full-text search, aggregations, and analytics without licensing costs, with features like distributed architecture, RESTful API, and multi-tenancy.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 2 cores minimum (4+ cores recommended for production)
  - RAM: 4GB minimum (16GB+ recommended for production)
  - Storage: 20GB minimum (SSD strongly recommended for performance)
  - Network: Stable connectivity for cluster communication
- **Operating System**: 
  - Linux: Any modern distribution with kernel 3.2+
  - macOS: 10.13+ (High Sierra or newer)
  - Windows: Windows Server 2016+ or Windows 10
  - FreeBSD: 11.0+
- **Network Requirements**:
  - Port 9200 (HTTP/REST API)
  - Port 9300 (Node communication)
  - Additional ports for cluster discovery
- **Dependencies**:
  - Java 11 or Java 17 (OpenJDK recommended)
  - systemd or compatible init system (Linux)
  - Root or administrative access for installation
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Install Java (OpenJDK)
sudo yum install -y java-11-openjdk java-11-openjdk-devel

# Import Elasticsearch GPG key
sudo rpm --import https://artifacts.elastic.co/GPG-KEY-elasticsearch

# Create Elasticsearch repository
sudo tee /etc/yum.repos.d/elasticsearch.repo <<EOF
[elasticsearch]
name=Elasticsearch repository for 8.x packages
baseurl=https://artifacts.elastic.co/packages/8.x/yum
gpgcheck=1
gpgkey=https://artifacts.elastic.co/GPG-KEY-elasticsearch
enabled=0
autorefresh=1
type=rpm-md
EOF

# Install Elasticsearch
sudo yum install -y --enablerepo=elasticsearch elasticsearch

# Enable and start service
sudo systemctl enable --now elasticsearch

# Configure firewall
sudo firewall-cmd --permanent --add-port=9200/tcp
sudo firewall-cmd --permanent --add-port=9300/tcp
sudo firewall-cmd --reload

# Verify installation
curl -X GET "localhost:9200/"
```

### Debian/Ubuntu

```bash
# Update package index
sudo apt update

# Install Java (OpenJDK)
sudo apt install -y openjdk-11-jdk

# Install prerequisite packages
sudo apt install -y wget gnupg apt-transport-https

# Import Elasticsearch GPG key
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/elasticsearch.gpg

# Add Elasticsearch repository
echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list

# Update package index
sudo apt update

# Install Elasticsearch
sudo apt install -y elasticsearch

# Enable and start service
sudo systemctl enable --now elasticsearch

# Configure firewall
sudo ufw allow 9200
sudo ufw allow 9300
```

### Arch Linux

```bash
# Install Java
sudo pacman -S jdk11-openjdk

# Elasticsearch is available in AUR
yay -S elasticsearch

# Alternative: Install from AUR with makepkg
git clone https://aur.archlinux.org/elasticsearch.git
cd elasticsearch
makepkg -si

# Create elasticsearch user and group
sudo useradd -r -s /sbin/nologin elasticsearch

# Create necessary directories
sudo mkdir -p /var/lib/elasticsearch /var/log/elasticsearch
sudo chown elasticsearch:elasticsearch /var/lib/elasticsearch /var/log/elasticsearch

# Enable and start service
sudo systemctl enable --now elasticsearch

# Configuration location: /etc/elasticsearch/
```

### Alpine Linux

```bash
# Install Java
apk add --no-cache openjdk11

# Elasticsearch is not officially packaged for Alpine
# Use Docker for Elasticsearch on Alpine:

# Install Docker
apk add --no-cache docker docker-compose

# Enable and start Docker
rc-update add docker default
rc-service docker start

# Run Elasticsearch container
docker run -d \
  --name elasticsearch \
  --restart unless-stopped \
  -p 9200:9200 -p 9300:9300 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  -v /var/lib/elasticsearch:/usr/share/elasticsearch/data \
  elasticsearch:8.11.3

# Verify installation
curl -X GET "localhost:9200/"
```

### openSUSE/SLES

```bash
# Install Java
sudo zypper install -y java-11-openjdk java-11-openjdk-devel

# Elasticsearch is not officially packaged for openSUSE/SLES
# Use Docker or manual installation:

# Method 1: Docker installation
sudo zypper install -y docker docker-compose
sudo systemctl enable --now docker

docker run -d \
  --name elasticsearch \
  --restart unless-stopped \
  -p 9200:9200 -p 9300:9300 \
  -e "discovery.type=single-node" \
  -e "xpack.security.enabled=false" \
  -v /var/lib/elasticsearch:/usr/share/elasticsearch/data \
  elasticsearch:8.11.3

# Method 2: Manual installation from tarball
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.11.3-linux-x86_64.tar.gz
tar -xzf elasticsearch-8.11.3-linux-x86_64.tar.gz
sudo mv elasticsearch-8.11.3 /usr/local/elasticsearch

# Create elasticsearch user and directories
sudo useradd -r elasticsearch
sudo mkdir -p /var/lib/elasticsearch /var/log/elasticsearch
sudo chown elasticsearch:elasticsearch /var/lib/elasticsearch /var/log/elasticsearch
```

### macOS

```bash
# Using Homebrew
brew tap elastic/tap
brew install elastic/tap/elasticsearch-full

# Start Elasticsearch service
brew services start elastic/tap/elasticsearch-full

# Or run manually
elasticsearch

# Configuration location: /usr/local/etc/elasticsearch/
# Alternative: /opt/homebrew/etc/elasticsearch/ (Apple Silicon)
```

### FreeBSD

```bash
# Install Java
pkg install openjdk11

# Install Elasticsearch from ports
cd /usr/ports/textproc/elasticsearch8
make install clean

# Enable Elasticsearch
echo 'elasticsearch_enable="YES"' >> /etc/rc.conf

# Start service
service elasticsearch start

# Configuration location: /usr/local/etc/elasticsearch/
```

### Windows

```powershell
# Method 1: Using Chocolatey
choco install elasticsearch

# Method 2: Using Scoop
scoop bucket add java
scoop install openjdk11
scoop bucket add extras
scoop install elasticsearch

# Method 3: Manual installation
# Download from https://www.elastic.co/downloads/elasticsearch
# Extract to C:\elasticsearch

# Install as Windows service
"C:\elasticsearch\bin\elasticsearch-service.bat" install

# Start service
net start Elasticsearch

# Configuration location: C:\elasticsearch\config\elasticsearch.yml
```

## Initial Configuration

### First-Run Setup

1. **Create elasticsearch user** (if not created by package):
```bash
# Linux systems
sudo useradd -r -d /var/lib/elasticsearch -s /sbin/nologin -c "Elasticsearch" elasticsearch
```

2. **Default configuration locations**:
- RHEL/CentOS/Rocky/AlmaLinux: `/etc/elasticsearch/elasticsearch.yml`
- Debian/Ubuntu: `/etc/elasticsearch/elasticsearch.yml`
- Arch Linux: `/etc/elasticsearch/elasticsearch.yml`
- Alpine Linux: Docker container configuration
- openSUSE/SLES: `/etc/elasticsearch/elasticsearch.yml` (manual installation)
- macOS: `/usr/local/etc/elasticsearch/elasticsearch.yml`
- FreeBSD: `/usr/local/etc/elasticsearch/elasticsearch.yml`
- Windows: `C:\elasticsearch\config\elasticsearch.yml`

3. **Essential settings to change**:

```yaml
# /etc/elasticsearch/elasticsearch.yml
cluster.name: my-application
node.name: node-1

path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

network.host: 127.0.0.1
http.port: 9200

discovery.type: single-node

# Security (disable for initial setup, enable for production)
xpack.security.enabled: true
xpack.security.enrollment.enabled: true

# Memory settings
bootstrap.memory_lock: true

# Index settings
action.auto_create_index: .monitoring*,.watches,.triggered_watches,.watcher-history*,.ml*
```

### Testing Initial Setup

```bash
# Check if Elasticsearch is running
sudo systemctl status elasticsearch

# Test REST API
curl -X GET "localhost:9200/"

# Check cluster health
curl -X GET "localhost:9200/_cluster/health?pretty"

# Check nodes
curl -X GET "localhost:9200/_cat/nodes?v"

# Test indexing and searching
curl -X PUT "localhost:9200/test_index/_doc/1" -H 'Content-Type: application/json' -d '{"message": "Hello Elasticsearch"}'
curl -X GET "localhost:9200/test_index/_search?pretty"
```

**WARNING:** Enable X-Pack security for production deployments!

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable Elasticsearch to start on boot
sudo systemctl enable elasticsearch

# Start Elasticsearch
sudo systemctl start elasticsearch

# Stop Elasticsearch
sudo systemctl stop elasticsearch

# Restart Elasticsearch
sudo systemctl restart elasticsearch

# Reload configuration (not supported, requires restart)
sudo systemctl restart elasticsearch

# Check status
sudo systemctl status elasticsearch

# View logs
sudo journalctl -u elasticsearch -f
```

### OpenRC (Alpine Linux)

```bash
# Elasticsearch runs in Docker container on Alpine
docker start elasticsearch
docker stop elasticsearch
docker restart elasticsearch

# Check status
docker ps | grep elasticsearch

# View logs
docker logs -f elasticsearch
```

### rc.d (FreeBSD)

```bash
# Enable in /etc/rc.conf
echo 'elasticsearch_enable="YES"' >> /etc/rc.conf

# Start Elasticsearch
service elasticsearch start

# Stop Elasticsearch
service elasticsearch stop

# Restart Elasticsearch
service elasticsearch restart

# Check status
service elasticsearch status
```

### launchd (macOS)

```bash
# Using Homebrew services
brew services start elastic/tap/elasticsearch-full
brew services stop elastic/tap/elasticsearch-full
brew services restart elastic/tap/elasticsearch-full

# Check status
brew services list | grep elasticsearch

# Manual control
elasticsearch
```

### Windows Service Manager

```powershell
# Start Elasticsearch service
net start Elasticsearch

# Stop Elasticsearch service
net stop Elasticsearch

# Using PowerShell
Start-Service Elasticsearch
Stop-Service Elasticsearch
Restart-Service Elasticsearch

# Check status
Get-Service Elasticsearch

# View logs
Get-EventLog -LogName Application -Source Elasticsearch
```

## Advanced Configuration

### Cluster Configuration

```yaml
# Multi-node cluster configuration
cluster.name: production-cluster
node.name: node-1
node.roles: [master, data, ingest]

network.host: 0.0.0.0
http.port: 9200
transport.port: 9300

discovery.seed_hosts: ["node1.example.com", "node2.example.com", "node3.example.com"]
cluster.initial_master_nodes: ["node-1", "node-2", "node-3"]

# Node-specific roles
# Master-eligible node
node.roles: [master]

# Data node
node.roles: [data]

# Ingest node
node.roles: [ingest]

# Coordinating only node
node.roles: []
```

### Memory and Performance Configuration

```yaml
# JVM heap settings (in elasticsearch.yml or jvm.options)
# Set via environment variables:
ES_JAVA_OPTS: "-Xms4g -Xmx4g"

# Thread pool settings
thread_pool:
  write:
    size: 8
    queue_size: 200
  search:
    size: 13
    queue_size: 1000

# Index settings
indices.memory.index_buffer_size: 20%
indices.breaker.total.use_real_memory: true
```

### Advanced Security Settings

```yaml
# X-Pack Security configuration
xpack.security.enabled: true
xpack.security.enrollment.enabled: true

# SSL/TLS configuration
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: certs/http.p12
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: certs/transport.p12
xpack.security.transport.ssl.truststore.path: certs/transport.p12

# Authentication realms
xpack.security.authc.realms:
  native:
    native1:
      order: 0
```

## Reverse Proxy Setup

### nginx Configuration

```nginx
# /etc/nginx/sites-available/elasticsearch
upstream elasticsearch_backend {
    server 127.0.0.1:9200 max_fails=3 fail_timeout=30s;
    server 127.0.0.1:9201 max_fails=3 fail_timeout=30s backup;
}

server {
    listen 80;
    server_name elasticsearch.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name elasticsearch.example.com;

    ssl_certificate /etc/letsencrypt/live/elasticsearch.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/elasticsearch.example.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;

    location / {
        proxy_pass http://elasticsearch_backend;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

### Apache Configuration

```apache
# /etc/apache2/sites-available/elasticsearch.conf
<VirtualHost *:443>
    ServerName elasticsearch.example.com
    
    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/elasticsearch.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/elasticsearch.example.com/privkey.pem
    
    ProxyPreserveHost On
    ProxyPass / http://localhost:9200/
    ProxyPassReverse / http://localhost:9200/
    
    Header always set Strict-Transport-Security "max-age=63072000"
</VirtualHost>
```

### HAProxy Configuration

```haproxy
# /etc/haproxy/haproxy.cfg
frontend elasticsearch_frontend
    bind *:9200 ssl crt /etc/haproxy/certs/elasticsearch.pem
    mode http
    option httplog
    default_backend elasticsearch_backend

backend elasticsearch_backend
    mode http
    balance roundrobin
    option httpchk GET /_cluster/health
    server elasticsearch1 127.0.0.1:9200 check
    server elasticsearch2 127.0.0.1:9201 check backup
```

## Security Configuration

### SSL/TLS Setup

```bash
# Generate certificates using Elasticsearch's certificate tool
cd /usr/share/elasticsearch
sudo bin/elasticsearch-certutil ca --pem --out /tmp/ca.zip
sudo unzip /tmp/ca.zip -d /tmp/ca
sudo bin/elasticsearch-certutil cert --ca-cert /tmp/ca/ca.crt --ca-key /tmp/ca/ca.key --pem --out /tmp/certs.zip
sudo unzip /tmp/certs.zip -d /tmp/certs

# Create certificates directory
sudo mkdir -p /etc/elasticsearch/certs
sudo cp /tmp/ca/ca.crt /etc/elasticsearch/certs/
sudo cp /tmp/certs/instance/instance.crt /etc/elasticsearch/certs/
sudo cp /tmp/certs/instance/instance.key /etc/elasticsearch/certs/

# Create keystore
sudo bin/elasticsearch-keystore create
sudo bin/elasticsearch-keystore add xpack.security.http.ssl.keystore.secure_password
sudo bin/elasticsearch-keystore add xpack.security.transport.ssl.keystore.secure_password

# Set permissions
sudo chown -R elasticsearch:elasticsearch /etc/elasticsearch/certs
sudo chmod 600 /etc/elasticsearch/certs/*
```

### User Management and Authentication

```bash
# Set passwords for built-in users (run after enabling security)
sudo /usr/share/elasticsearch/bin/elasticsearch-setup-passwords auto

# Create custom users
curl -X POST "localhost:9200/_security/user/appuser" -H 'Content-Type: application/json' -u elastic:password -d'
{
  "password" : "SecurePassword123!",
  "roles" : [ "kibana_admin", "monitoring_user" ],
  "full_name" : "Application User",
  "email" : "appuser@example.com"
}'

# Create custom roles
curl -X POST "localhost:9200/_security/role/log_reader" -H 'Content-Type: application/json' -u elastic:password -d'
{
  "cluster": ["monitor"],
  "indices": [
    {
      "names": ["logs-*"],
      "privileges": ["read", "view_index_metadata"]
    }
  ]
}'
```

### Firewall Rules

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow from 192.168.1.0/24 to any port 9200
sudo ufw allow from 192.168.1.0/24 to any port 9300
sudo ufw reload

# firewalld (RHEL/CentOS/openSUSE)
sudo firewall-cmd --permanent --new-zone=elasticsearch
sudo firewall-cmd --permanent --zone=elasticsearch --add-source=192.168.1.0/24
sudo firewall-cmd --permanent --zone=elasticsearch --add-port=9200/tcp
sudo firewall-cmd --permanent --zone=elasticsearch --add-port=9300/tcp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 9200 -j ACCEPT
sudo iptables -A INPUT -s 192.168.1.0/24 -p tcp --dport 9300 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4

# pf (FreeBSD)
# Add to /etc/pf.conf
pass in on $ext_if proto tcp from 192.168.1.0/24 to any port { 9200, 9300 }

# Windows Firewall
New-NetFirewallRule -DisplayName "Elasticsearch HTTP" -Direction Inbound -Protocol TCP -LocalPort 9200 -RemoteAddress 192.168.1.0/24 -Action Allow
New-NetFirewallRule -DisplayName "Elasticsearch Transport" -Direction Inbound -Protocol TCP -LocalPort 9300 -RemoteAddress 192.168.1.0/24 -Action Allow
```

## Database Setup

### Index Templates and Mappings

```bash
# Create index template
curl -X PUT "localhost:9200/_index_template/logs_template" -H 'Content-Type: application/json' -d'
{
  "index_patterns": ["logs-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 1,
      "index.refresh_interval": "30s"
    },
    "mappings": {
      "properties": {
        "timestamp": {
          "type": "date"
        },
        "level": {
          "type": "keyword"
        },
        "message": {
          "type": "text",
          "analyzer": "standard"
        },
        "host": {
          "type": "keyword"
        }
      }
    }
  }
}'

# Create index with custom settings
curl -X PUT "localhost:9200/my_index" -H 'Content-Type: application/json' -d'
{
  "settings": {
    "number_of_shards": 3,
    "number_of_replicas": 2,
    "analysis": {
      "analyzer": {
        "custom_analyzer": {
          "type": "custom",
          "tokenizer": "standard",
          "filter": ["lowercase", "asciifolding"]
        }
      }
    }
  },
  "mappings": {
    "properties": {
      "title": {
        "type": "text",
        "analyzer": "custom_analyzer"
      },
      "content": {
        "type": "text"
      },
      "tags": {
        "type": "keyword"
      },
      "created_at": {
        "type": "date"
      }
    }
  }
}'
```

### Index Lifecycle Management

```bash
# Create ILM policy
curl -X PUT "localhost:9200/_ilm/policy/logs_policy" -H 'Content-Type: application/json' -d'
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "10gb",
            "max_age": "7d"
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "allocate": {
            "number_of_replicas": 0
          }
        }
      },
      "cold": {
        "min_age": "30d",
        "actions": {
          "allocate": {
            "number_of_replicas": 0
          }
        }
      },
      "delete": {
        "min_age": "90d"
      }
    }
  }
}'
```

## Performance Optimization

### System Tuning

```bash
# Elasticsearch-specific system optimizations
sudo tee -a /etc/sysctl.conf <<EOF
# Elasticsearch optimizations
vm.max_map_count = 262144
vm.swappiness = 1
fs.file-max = 65535
net.core.somaxconn = 32768
net.ipv4.tcp_max_syn_backlog = 8192
EOF

sudo sysctl -p

# Disable swap
sudo swapoff -a
echo 'vm.swappiness=1' | sudo tee -a /etc/sysctl.conf

# Set file descriptor limits
sudo tee -a /etc/security/limits.conf <<EOF
elasticsearch soft nofile 65535
elasticsearch hard nofile 65535
elasticsearch soft memlock unlimited
elasticsearch hard memlock unlimited
EOF
```

### JVM and Memory Tuning

```bash
# JVM options (/etc/elasticsearch/jvm.options)
# Set heap size (50% of available RAM, max 32GB)
-Xms8g
-Xmx8g

# GC settings
-XX:+UseG1GC
-XX:G1HeapRegionSize=16m
-XX:+UnlockExperimentalVMOptions
-XX:+UnlockDiagnosticVMOptions
-XX:+G1PrintRegionRememberedSetInfo

# Memory lock
-XX:+AlwaysPreTouch
```

### Index and Query Optimization

```bash
# Index optimization settings
curl -X PUT "localhost:9200/my_index/_settings" -H 'Content-Type: application/json' -d'
{
  "index": {
    "refresh_interval": "30s",
    "number_of_replicas": 1,
    "routing.allocation.total_shards_per_node": 3,
    "translog.flush_threshold_size": "1gb",
    "translog.sync_interval": "30s"
  }
}'

# Force merge indices
curl -X POST "localhost:9200/my_index/_forcemerge?max_num_segments=1"

# Clear cache
curl -X POST "localhost:9200/_cache/clear"
```

## Monitoring

### Built-in Monitoring

```bash
# Cluster health
curl -X GET "localhost:9200/_cluster/health?pretty"

# Node statistics
curl -X GET "localhost:9200/_nodes/stats?pretty"

# Index statistics
curl -X GET "localhost:9200/_stats?pretty"

# Hot threads
curl -X GET "localhost:9200/_nodes/hot_threads"

# Task management
curl -X GET "localhost:9200/_tasks?detailed=true&actions=*search"

# Pending cluster tasks
curl -X GET "localhost:9200/_cluster/pending_tasks"
```

### External Monitoring Setup

```bash
# Install Metricbeat for monitoring
curl -L -O https://artifacts.elastic.co/downloads/beats/metricbeat/metricbeat-8.11.3-linux-x86_64.tar.gz
tar xzvf metricbeat-8.11.3-linux-x86_64.tar.gz
sudo mv metricbeat-8.11.3-linux-x86_64 /usr/local/metricbeat

# Configure Metricbeat for Elasticsearch monitoring
sudo tee /usr/local/metricbeat/metricbeat.yml <<EOF
metricbeat.modules:
- module: elasticsearch
  metricsets:
    - node
    - node_stats
    - cluster_stats
  period: 10s
  hosts: ["localhost:9200"]

output.elasticsearch:
  hosts: ["localhost:9200"]

setup.kibana:
  host: "localhost:5601"
EOF

# Create systemd service for Metricbeat
sudo tee /etc/systemd/system/metricbeat.service <<EOF
[Unit]
Description=Metricbeat
After=network.target

[Service]
Type=simple
User=elasticsearch
WorkingDirectory=/usr/local/metricbeat
ExecStart=/usr/local/metricbeat/metricbeat -c /usr/local/metricbeat/metricbeat.yml
Restart=always

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now metricbeat
```

### Health Check Scripts

```bash
#!/bin/bash
# elasticsearch-health-check.sh

# Check Elasticsearch service
if ! systemctl is-active elasticsearch >/dev/null 2>&1; then
    echo "CRITICAL: Elasticsearch service is not running"
    exit 2
fi

# Check HTTP API
if ! curl -s http://localhost:9200/ >/dev/null; then
    echo "CRITICAL: Cannot connect to Elasticsearch HTTP API"
    exit 2
fi

# Check cluster health
CLUSTER_STATUS=$(curl -s http://localhost:9200/_cluster/health | jq -r '.status')
case $CLUSTER_STATUS in
    "green")
        echo "OK: Cluster health is green"
        exit 0
        ;;
    "yellow")
        echo "WARNING: Cluster health is yellow"
        exit 1
        ;;
    "red")
        echo "CRITICAL: Cluster health is red"
        exit 2
        ;;
    *)
        echo "UNKNOWN: Cannot determine cluster health"
        exit 3
        ;;
esac
```

## 9. Backup and Restore

### Snapshot Repository Setup

```bash
# Create snapshot repository
curl -X PUT "localhost:9200/_snapshot/backup_repo" -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/backup/elasticsearch",
    "compress": true,
    "max_snapshot_bytes_per_sec": "50mb",
    "max_restore_bytes_per_sec": "50mb"
  }
}'

# Create backup directory
sudo mkdir -p /backup/elasticsearch
sudo chown elasticsearch:elasticsearch /backup/elasticsearch

# Add repository path to elasticsearch.yml
echo 'path.repo: ["/backup/elasticsearch"]' | sudo tee -a /etc/elasticsearch/elasticsearch.yml
sudo systemctl restart elasticsearch
```

### Backup Procedures

```bash
#!/bin/bash
# elasticsearch-backup.sh

SNAPSHOT_NAME="snapshot-$(date +%Y%m%d_%H%M%S)"

# Create snapshot
curl -X PUT "localhost:9200/_snapshot/backup_repo/$SNAPSHOT_NAME?wait_for_completion=true" -H 'Content-Type: application/json' -d'
{
  "indices": "*",
  "ignore_unavailable": true,
  "include_global_state": true,
  "metadata": {
    "taken_by": "elasticsearch-backup-script",
    "taken_because": "scheduled backup"
  }
}'

# Verify snapshot
SNAPSHOT_STATUS=$(curl -s "localhost:9200/_snapshot/backup_repo/$SNAPSHOT_NAME" | jq -r '.snapshots[0].state')

if [ "$SNAPSHOT_STATUS" = "SUCCESS" ]; then
    echo "Backup completed successfully: $SNAPSHOT_NAME"
else
    echo "Backup failed: $SNAPSHOT_NAME"
    exit 1
fi

# Clean up old snapshots (keep last 7 days)
curl -s "localhost:9200/_snapshot/backup_repo/_all" | jq -r '.snapshots[] | select(.end_time_in_millis < '$(date -d '7 days ago' +%s000)') | .snapshot' | while read snapshot; do
    curl -X DELETE "localhost:9200/_snapshot/backup_repo/$snapshot"
    echo "Deleted old snapshot: $snapshot"
done

echo "Elasticsearch backup completed: $SNAPSHOT_NAME"
```

### Restore Procedures

```bash
#!/bin/bash
# elasticsearch-restore.sh

SNAPSHOT_NAME="$1"
if [ -z "$SNAPSHOT_NAME" ]; then
    echo "Usage: $0 <snapshot-name>"
    echo "Available snapshots:"
    curl -s "localhost:9200/_snapshot/backup_repo/_all" | jq -r '.snapshots[].snapshot'
    exit 1
fi

# Close indices before restore
curl -X POST "localhost:9200/_all/_close"

# Restore snapshot
curl -X POST "localhost:9200/_snapshot/backup_repo/$SNAPSHOT_NAME/_restore?wait_for_completion=true" -H 'Content-Type: application/json' -d'
{
  "indices": "*",
  "ignore_unavailable": true,
  "include_global_state": true
}'

echo "Restore completed from snapshot: $SNAPSHOT_NAME"
```

### Automated Backup

```bash
# Create cron job for daily backups
echo "0 2 * * * /usr/local/bin/elasticsearch-backup.sh" | sudo crontab -
```

## 6. Troubleshooting

### Common Issues

1. **Elasticsearch won't start**:
```bash
# Check logs
sudo journalctl -u elasticsearch -f
sudo tail -f /var/log/elasticsearch/elasticsearch.log

# Check Java version
java -version

# Check memory settings
grep -E "Xms|Xmx" /etc/elasticsearch/jvm.options

# Check disk space
df -h /var/lib/elasticsearch
```

2. **Out of memory errors**:
```bash
# Check heap usage
curl -X GET "localhost:9200/_nodes/stats/jvm?pretty"

# Check field data cache
curl -X GET "localhost:9200/_nodes/stats/indices/fielddata?pretty"

# Clear field data cache
curl -X POST "localhost:9200/_cache/clear?fielddata=true"
```

3. **Slow queries**:
```bash
# Enable slow log
curl -X PUT "localhost:9200/_all/_settings" -H 'Content-Type: application/json' -d'
{
  "index.search.slowlog.threshold.query.warn": "10s",
  "index.search.slowlog.threshold.query.info": "5s",
  "index.search.slowlog.threshold.query.debug": "2s",
  "index.search.slowlog.threshold.query.trace": "500ms"
}'

# Check slow queries
sudo tail -f /var/log/elasticsearch/*_index_search_slowlog.log
```

### Debug Mode

```bash
# Enable debug logging
curl -X PUT "localhost:9200/_cluster/settings" -H 'Content-Type: application/json' -d'
{
  "transient": {
    "logger.org.elasticsearch": "DEBUG"
  }
}'

# Check cluster state
curl -X GET "localhost:9200/_cluster/state?pretty"

# Explain API for query analysis
curl -X GET "localhost:9200/my_index/_search" -H 'Content-Type: application/json' -d'
{
  "explain": true,
  "query": {
    "match": {
      "title": "search term"
    }
  }
}'
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo yum check-update elasticsearch
sudo yum update elasticsearch

# Debian/Ubuntu
sudo apt update
sudo apt upgrade elasticsearch

# Arch Linux
yay -Syu elasticsearch

# macOS
brew upgrade elastic/tap/elasticsearch-full

# Docker (Alpine/openSUSE)
docker pull elasticsearch:8.11.3
docker stop elasticsearch
docker rm elasticsearch
# Re-run docker run command with new image

# Always backup before updates
./elasticsearch-backup.sh

# Restart after updates
sudo systemctl restart elasticsearch
```

### Maintenance Tasks

```bash
# Weekly maintenance script
#!/bin/bash
# elasticsearch-maintenance.sh

# Force merge old indices
curl -X POST "localhost:9200/logs-$(date -d '1 week ago' +%Y.%m.%d)/_forcemerge?max_num_segments=1"

# Clear caches
curl -X POST "localhost:9200/_cache/clear"

# Optimize indices
curl -X POST "localhost:9200/_optimize"

# Update index settings for better performance
curl -X PUT "localhost:9200/_all/_settings" -H 'Content-Type: application/json' -d'
{
  "index": {
    "refresh_interval": "30s"
  }
}'

echo "Elasticsearch maintenance completed"
```

### Health Monitoring

```bash
# Create monitoring cron job
echo "*/5 * * * * /usr/local/bin/elasticsearch-health-check.sh" | sudo crontab -

# Log rotation
sudo tee /etc/logrotate.d/elasticsearch <<EOF
/var/log/elasticsearch/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 elasticsearch elasticsearch
    postrotate
        systemctl restart elasticsearch > /dev/null 2>&1 || true
    endscript
}
EOF
```

## Integration Examples

### Python Integration

```python
# Using elasticsearch-py
from elasticsearch import Elasticsearch

# Connect to Elasticsearch
es = Elasticsearch(
    hosts=[{'host': 'localhost', 'port': 9200}],
    http_auth=('elastic', 'password'),
    use_ssl=True,
    verify_certs=True,
    ca_certs='/etc/elasticsearch/certs/ca.crt',
)

# Index a document
doc = {
    'title': 'Sample Document',
    'content': 'This is a sample document for testing',
    'timestamp': '2024-01-15T10:30:00'
}
es.index(index='my_index', id=1, body=doc)

# Search documents
response = es.search(
    index='my_index',
    body={
        'query': {
            'match': {
                'content': 'sample'
            }
        }
    }
)
print(response['hits'])
```

### Node.js Integration

```javascript
// Using @elastic/elasticsearch
const { Client } = require('@elastic/elasticsearch');

const client = new Client({
  node: 'https://localhost:9200',
  auth: {
    username: 'elastic',
    password: 'password'
  },
  tls: {
    ca: fs.readFileSync('/etc/elasticsearch/certs/ca.crt'),
    rejectUnauthorized: true
  }
});

// Index a document
async function indexDocument() {
  const response = await client.index({
    index: 'my_index',
    id: 1,
    body: {
      title: 'Sample Document',
      content: 'This is a sample document for testing',
      timestamp: new Date()
    }
  });
  console.log(response);
}

// Search documents
async function searchDocuments() {
  const response = await client.search({
    index: 'my_index',
    body: {
      query: {
        match: {
          content: 'sample'
        }
      }
    }
  });
  console.log(response.body.hits);
}
```

### Java Integration

```java
// Using Elasticsearch Java client
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.search.SearchRequest;
import org.elasticsearch.common.xcontent.XContentType;

RestHighLevelClient client = new RestHighLevelClient(
    RestClient.builder(new HttpHost("localhost", 9200, "https"))
        .setHttpClientConfigCallback(httpClientBuilder -> 
            httpClientBuilder.setDefaultCredentialsProvider(credentialsProvider)
                .setSSLContext(sslContext))
);

// Index a document
IndexRequest indexRequest = new IndexRequest("my_index")
    .id("1")
    .source("{\n" +
        "\"title\":\"Sample Document\",\n" +
        "\"content\":\"This is a sample document for testing\",\n" +
        "\"timestamp\":\"2024-01-15T10:30:00\"\n" +
        "}", XContentType.JSON);

client.index(indexRequest, RequestOptions.DEFAULT);
```

### Logstash Integration

```ruby
# logstash.conf
input {
  beats {
    port => 5044
  }
}

filter {
  if [fields][log_type] == "apache" {
    grok {
      match => { "message" => "%{COMBINEDAPACHELOG}" }
    }
    date {
      match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    user => "logstash_user"
    password => "logstash_password"
    index => "logs-%{+YYYY.MM.dd}"
  }
}
```

## Additional Resources

- [Official Elasticsearch Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html)
- [Elasticsearch Security Guide](https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html)
- [Performance Tuning Guide](https://www.elastic.co/guide/en/elasticsearch/reference/current/tune-for-search-speed.html)
- [Index Lifecycle Management](https://www.elastic.co/guide/en/elasticsearch/reference/current/index-lifecycle-management.html)
- [Elasticsearch Cluster Setup](https://www.elastic.co/guide/en/elasticsearch/reference/current/modules-discovery-bootstrap-cluster.html)
- [Elastic Stack Community](https://discuss.elastic.co/)
- [Elasticsearch Blog](https://www.elastic.co/blog/category/elasticsearch)
- [Best Practices Guide](https://www.elastic.co/guide/en/elasticsearch/guide/current/index.html)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.