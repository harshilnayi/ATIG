# 🚀 GitHub Push Guide

**Step-by-step guide to push ATIG to GitHub**

---

## 📋 Pre-Push Checklist

### ✅ 1. Complete Testing
Run through **[TESTING_GUIDE.md](TESTING_GUIDE.md)** and confirm:
- [ ] All API tests pass
- [ ] All detection tests pass  
- [ ] Dashboard loads and works
- [ ] WebSocket connections work
- [ ] Analytics endpoints respond
- [ ] Response automation works

**Quick verification script:**
```powershell
# Run this to verify everything is working
Write-Host "=== Pre-Push Verification ===" -ForegroundColor Cyan

# API Health
Invoke-RestMethod -Uri "http://localhost:8001/health" | Out-Null
Write-Host "✓ API OK" -ForegroundColor Green

# Rules
$rules = (Invoke-RestMethod -Uri "http://localhost:8001/rules").total_rules
Write-Host "✓ $rules rules loaded" -ForegroundColor Green

# Dashboard  
Invoke-WebRequest -Uri "http://localhost:3000" -UseBasicParsing | Out-Null
Write-Host "✓ Dashboard OK" -ForegroundColor Green

# Stats
$stats = Invoke-RestMethod -Uri "http://localhost:8001/stats"
Write-Host "✓ $($stats.total_alerts) alerts in database" -ForegroundColor Green

Write-Host "`n=== Ready for Push ===" -ForegroundColor Green
```

---

### ✅ 2. Review Your Changes

```powershell
# Check what will be committed
cd E:\ATIG
git status

# Review changes
git diff
```

**Make sure:**
- No sensitive data (API keys, passwords)
- No `node_modules/` folder
- No `.env` files
- Logs and temporary files excluded

---

### ✅ 3. Stage Files

```powershell
# Add all files
git add .

# Exclude node_modules if not already gitignored
git reset HEAD dashboard/node_modules/
git reset HEAD go/node_modules/ 2>$null

# Verify staged files
git status
```

**Expected staged files:**
- `README.md`
- `TESTING_GUIDE.md`
- `QUICK_START.md`
- `API_DOCUMENTATION.md`
- Source code (`python/`, `dashboard/src/`, `go/`)
- Configuration files
- Documentation

**Should NOT be staged:**
- `dashboard/node_modules/`
- `*.log` files
- `.env` files
- Database files

---

### ✅ 4. Create Commit

```powershell
git commit -m "feat: production-grade ATIG intrusion detection system

- 50+ detection rules (SQLi, XSS, Path Traversal, Command Injection)
- Real-time Vue 3 dashboard with WebSocket updates
- Threat intelligence integration (OTX, Abuse.ch, PhishTank)
- ML-powered anomaly detection
- Auto IP blocking and rate limiting
- Comprehensive API with 20+ endpoints
- Alert correlation and threat scoring
- Full testing suite and documentation"
```

---

### ✅ 5. Push to GitHub

```powershell
# Check current branch
git branch

# Push to main branch
git push origin main
```

**If you don't have a remote yet:**
```powershell
# Initialize remote (replace WITH_YOUR_REPO_URL)
git remote add origin https://github.com/YOUR_USERNAME/ATIG.git

# Push
git push -u origin main
```

---

## 🐛 Common Issues

### Issue: node_modules being pushed
**Solution:**
```powershell
# Add to .gitignore
echo "dashboard/node_modules/" >> .gitignore
echo "go/vendor/" >> .gitignore

# Remove from cache
git rm -r --cached dashboard/node_modules/
git rm -r --cached go/vendor/ 2>$null

# Commit the fix
git commit -m "fix: remove node_modules from tracking"
```

### Issue: Large files rejected
**Solution:**
```powershell
# Check large files
git ls-files --stacky

# Add to .gitignore
echo "*.log" >> .gitignore
echo "*.db" >> .gitignore

# Clean history (careful!)
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch *.log *.db" \
  --prune-empty --tag-name-filter cat -- --all
```

### Issue: Permission denied
**Solution:**
```powershell
# Check SSH key
ssh -T git@github.com

# Or use HTTPS instead of SSH
git remote set-url origin https://github.com/YOUR_USERNAME/ATIG.git
```

---

## 📝 Commit Message Convention

Use these prefixes:

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style (formatting, etc)
- `refactor:` - Code refactoring
- `test:` - Adding tests
- `chore:` - Maintenance

**Example:**
```
feat: add SQL injection detection rule

Added rule 2000001 to detect UNION SELECT patterns
in incoming traffic with medium severity level.
```

---

## 🔄 Post-Push Verification

After pushing, verify:

1. **Check GitHub repository:**
   - Visit your repo on github.com
   - Verify files are present
   - Check README renders correctly

2. **Test the README:**
   - Links should work
   - Code blocks should be formatted
   - Images should display (if any)

3. **Create a release (optional):**
   - Go to "Releases" tab
   - Click "Draft a new release"
   - Tag: `v1.0.0`
   - Title: "Initial Release"
   - Description: Summary of features

---

## 🚦 Release Checklist

Before v1.0.0 release:

- [ ] All tests pass
- [ ] README is complete
- [ ] Documentation is thorough
- [ ] No TODO comments left
- [ ] Version number updated
- [ ] CHANGELOG created
- [ ] License file present
- [ ] .gitignore complete

---

## 📦 .gitignore Template

Make sure your `.gitignore` includes:

```gitignore
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
env/
venv/
ENV/

# Node
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*

# Logs
*.log
logs/

# Environment variables
.env
.env.local
.env.*.local

# Database
*.db
*.sqlite

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Build
dist/
build/
*.egg-info/
```

---

## 🎉 Success!

After successful push:

```
✓ All files committed
✓ Pushed to GitHub
✓ Repository is live
✓ README renders correctly
```

**Your ATIG system is now on GitHub! 🚀**

**Share your repo:**
```
https://github.com/YOUR_USERNAME/ATIG
```

---

**Need help?** Check the issues section or create a new issue on GitHub.
