# Keeper Update Guide

## Quick Update Commands

### Check Current Version
```bash
keeper --version
```

### Update to Latest Release
```bash
# Stop the daemon first
keeper stop

# Update keeper binary
keeper update --self

# Start the daemon again
keeper start
```

### Update to Specific Version
```bash
keeper update --self --tag v0.3.7
```

### Skip Migration Check (Not Recommended)
```bash
keeper update --self --force
```

---

## Understanding the Update Process

### 1. Automatic Migration Check
Before updating, keeper checks if the new version requires data migration:

```bash
# Check if migration is needed
keeper migrate check

# If migration required, create backup first
keeper migrate backup

# Then proceed with update
keeper update --self
```

### 2. What Happens During Update
1. Downloads latest release from GitHub
2. Verifies SHA-256 checksum
3. Replaces current binary
4. Preserves your vault and data

### 3. Post-Update Steps
```bash
# Verify new version
keeper --version

# Check daemon status
keeper status

# If daemon not running, start it
keeper start
```

---

## Troubleshooting Updates

### "Permission Denied" Error
If you get permission errors during update:

```bash
# Option 1: Fix permissions
sudo chown $(whoami) $(which keeper)

# Option 2: Reinstall with curl
curl -fsSL https://github.com/thoughtoinnovate/keeper/raw/main/install.sh | sh
```

### "Migration Required" Warning
```bash
# Create encrypted backup first
keeper migrate backup ~/keeper-backup-$(date +%Y%m%d)

# Then proceed with update
keeper update --self
```

### Update Fails to Download
```bash
# Check internet connection
curl -I https://github.com

# Try manual download
# Download from: https://github.com/thoughtoinnovate/keeper/releases/latest
# Then replace /usr/local/bin/keeper manually
```

---

## Update Notifications (For Developers)

### Checking for Updates Programmatically
```bash
# Compare installed vs latest version
INSTALLED=$(keeper --version | awk '{print $2}')
LATEST=$(curl -s https://api.github.com/repos/thoughtoinnovate/keeper/releases/latest | grep '"tag_name":' | sed 's/.*"v\([^"]*\)".*/\1/')

if [ "$INSTALLED" != "$LATEST" ]; then
    echo "Update available: $INSTALLED → $LATEST"
    echo "Run: keeper update --self"
fi
```

### Automated Update (Cron Job)
```bash
# Add to crontab (check weekly)
0 0 * * 0 keeper update --self 2>/dev/null || true
```

---

## Version History

See all releases: https://github.com/thoughtoinnovate/keeper/releases

### Recent Major Updates
- **v0.3.7** - Clippy fixes, clean builds
- **v0.3.5** - Tier 2 Security Model (sudo → capabilities)
- **v0.3.4** - Recovery code display fix
- **v0.3.0** - Migration system, 31 security fixes

---

## Best Practices

1. **Always backup before major updates**
   ```bash
   keeper migrate backup ~/backups/keeper-$(date +%Y%m%d)
   ```

2. **Stop daemon before updating**
   ```bash
   keeper stop && keeper update --self && keeper start
   ```

3. **Check release notes**
   - Review changes before updating
   - Look for breaking changes
   - Note new features

4. **Test after updating**
   ```bash
   keeper note "Test after update" @default/test
   keeper get @default/test
   ```

---

## Alternative: Reinstall from Script

If self-update fails, reinstall fresh:

```bash
# Backup first
keeper export --encrypted ~/keeper-backup.keeper

# Stop daemon
keeper stop

# Reinstall
curl -fsSL https://github.com/thoughtoinnovate/keeper/raw/main/install.sh | sh

# Restore (if needed)
keeper import --encrypted ~/keeper-backup.keeper
```
