# WPProbe - Features & Ideas

## 📋 Features & To-Do

- [x] **Stealthy plugin detection** using REST API enumeration (`?rest_route=/`).
- [x] **High-speed scanning** with multithreading and a progress bar.
- [x] **Vulnerability mapping** with known CVEs.
- [x] **Multiple output formats** (CSV, JSON).
- [x] **Update system** via the `update` command to easily fetch the latest release.
- [x] **Use `/wp-json`** to target all permalink configurations, not just `?rest_route=/`.  
  [Ref: WP-Rest-Enum](https://github.com/DreyAnd/WP-Rest-Enum/blob/main/wp-rest-enum.py)
- [ ] **Brute-force plugin list** (inspired by wpfinger) as a separate scan mode to keep stealth intact.
- [x] **Add `uninstall` command** to clean up installations/configs.
- [ ] **Integrate more vuln databases** (e.g., WPScan, beyond Wordfence).
- [ ] **Create `config` command** for API keys management with secure storage.
- [ ] **Implement theme detection** (even if unlikely, some themes may expose endpoints).
- [ ] **Hybrid scan mode**: Start with stealthy mode, then skip already found plugins during fuzzing to optimize speed and stealth.

---

💡 *If you're reading this and want to contribute to any of these features, feel free to jump in! Pull requests are welcome.*
