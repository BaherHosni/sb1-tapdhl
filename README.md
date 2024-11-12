## Access Control System

A secure access control system with user authentication and IP-based access management using iptables.

### Prerequisites

- Node.js 18+ and npm
- Linux system with sudo access
- iptables installed

### Installation

1. Clone the repository:
```bash
git clone <your-repository-url>
cd access-control-system
```

2. Install dependencies:
```bash
npm install
```

3. Create `.env` file:
```bash
PORT=3000
JWT_SECRET=your-secure-secret-key-here  # Change this!
API_URL=http://your-server-ip:3000      # Update with your VM's IP
```

4. Set up iptables permissions:
```bash
sudo bash -c 'echo "nodejs ALL=(ALL) NOPASSWD: /sbin/iptables" > /etc/sudoers.d/nodejs'
chmod 440 /etc/sudoers.d/nodejs
```

5. Configure firewall:
```bash
# Clear existing rules and set default policies
sudo iptables -F
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow essential traffic
sudo iptables -A INPUT -i lo -j ACCEPT
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT    # SSH
sudo iptables -A INPUT -p tcp --dport 3000 -j ACCEPT  # API
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT    # HTTP
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT   # HTTPS

# Save iptables rules
sudo apt-get install -y iptables-persistent
sudo netfilter-persistent save
```

### Development

Start the development server:
```bash
npm run dev
```

This will start both the frontend and backend servers concurrently.

### Production Deployment

1. Install PM2:
```bash
sudo npm install -g pm2
```

2. Build the frontend:
```bash
npm run build
```

3. Set up Nginx:
```bash
sudo apt-get install -y nginx

# Create Nginx configuration
sudo bash -c 'cat > /etc/nginx/sites-available/access-control << EOL
server {
    listen 80;
    server_name your-domain.com;  # Update this!

    # Frontend
    location / {
        root /path/to/access-control/dist;  # Update path!
        try_files $uri $uri/ /index.html;
    }

    # Backend API
    location /api {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
EOL'

# Enable the site
sudo ln -s /etc/nginx/sites-available/access-control /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

4. Start the application:
```bash
pm2 start backend/server.js --name access-control
pm2 startup
pm2 save
```

### Default Admin Access

```
Email: admin@example.com
Password: admin123
```

⚠️ **IMPORTANT**: Change the admin password immediately after first login!

### Security Recommendations

1. Enable SSL/TLS with Let's Encrypt
2. Configure fail2ban
3. Keep system and dependencies updated
4. Set up regular database backups
5. Monitor firewall logs
6. Use strong passwords
7. Implement rate limiting

### Monitoring

```bash
# View logs
pm2 logs access-control

# Monitor processes
pm2 monit

# Check status
pm2 status
```

### Maintenance

```bash
# Update application
git pull
npm install
npm run build
pm2 restart access-control

# Backup database
sqlite3 database.sqlite .dump > backup.sql
```

### Architecture

The system consists of two main components:

1. **UI Component**
   - React-based frontend
   - User authentication
   - Access rule management interface
   - Admin dashboard

2. **Access Manager Component**
   - Node.js backend
   - iptables integration
   - SQLite database
   - JWT authentication
   - Role-based access control

### Security Features

- JWT-based authentication
- Role-based access control (Admin/User)
- Secure password hashing with bcrypt
- Input validation with Zod
- iptables integration for network access control
- CORS protection
- Environment-based configuration