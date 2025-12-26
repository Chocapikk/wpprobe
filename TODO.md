# WPProbe - Features & Ideas

## 📋 Features & To-Do

### ✅ Completed

- [x] **Stealthy plugin detection** using REST API enumeration (`?rest_route=/`).
- [x] **High-speed scanning** with multithreading and a progress bar.
- [x] **Vulnerability mapping** with known CVEs.
- [x] **Multiple output formats** (CSV, JSON).
- [x] **Update system** via the `update` command to easily fetch the latest release.
- [x] **Use `/wp-json`** to target all permalink configurations, not just `?rest_route=/`.  
  [Ref: WP-Rest-Enum](https://github.com/DreyAnd/WP-Rest-Enum/blob/main/wp-rest-enum.py)
- [x] **Brute-force plugin list** (inspired by wpfinger) as a separate scan mode to keep stealth intact.
- [x] **Add `uninstall` command** to clean up installations/configs.
- [x] **Hybrid scan mode**: Start with stealthy mode, then skip already found plugins during fuzzing to optimize speed and stealth.
- [x] **Rate limiting system**: Add requests per second (RPS) limit to prevent overwhelming targets and respect server limits. Implemented via token bucket limiter in HTTPClientManager. Added `--rate-limit` flag to control request rate. (Issue #11)
- [x] **WPScan API integration**: Enterprise mode support with batch database exports. Downloads complete vulnerability database (10000+ plugins) in a single request. **Note**: Integration not yet fully tested, use with caution.
- [x] **Codebase refactoring**: Major reorganization of scanner package, DRY principles applied to vulnerability management and writers, package structure improvements.
- [x] **Dockerfile improvements**: Multi-stage build with volumes for data and config persistence.
- [x] **CI optimization**: Added caching for Go modules, build cache, and golangci-lint. Removed redundant formatting tools.

### 🔄 In Progress / Partial

- [~] **WPScan integration**: Enterprise mode implemented but requires testing and validation.

### 📝 Planned

- [ ] **Create `config` command** for API keys management with secure storage.
- [ ] **Implement theme detection** (even if unlikely, some themes may expose endpoints).
- [ ] **Test and validate WPScan integration** in production environments.
- [ ] **Add more vulnerability databases** beyond Wordfence and WPScan.

---

💡 *If you're reading this and want to contribute to any of these features, feel free to jump in! Pull requests are welcome.*
