//Spoof useragent
user_pref("general.useragent.override","Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Chrome/90.0.4430.212");
user_pref("general.appname.override","Netscape");
user_pref("general.appversion.override","5.0 (Windows)");
user_pref("general.platform.override","Win32");
user_pref("general.oscpu.override","Windows NT 6.1");
//Spoof Cpu cores
user_pref("dom.maxHardwareConcurrency", 2);

//Clear history when firefox closes
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.clearOnShutdown.cookies", true);
user_pref("privacy.clearOnShutdown.downloads", true);
user_pref("privacy.clearOnShutdown.formdata", true);
user_pref("privacy.clearOnShutdown.history", true);
user_pref("privacy.clearOnShutdown.offlineApps", true);
user_pref("privacy.clearOnShutdown.sessions", true);
user_pref("privacy.clearOnShutdown.openWindows", true);
user_pref("places.history.enabled", false)
user_pref("browser.sessionstore.max_tabs_undo", 0);
user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.disk_cache_ssl", false);
user_pref("browser.download.manager.retention", 0);
user_pref("network.cookie.lifetimePolicy", 2);
user_pref("browser.formfill.expire_days", 0);
user_pref("browser.sessionstore.privacy_level", 2);
user_pref("browser.helperApps.deleteTempFileOnExit", true);
user_pref("browser.bookmarks.max_backups", 0);
user_pref("layout.css.visited_links_enabled", false);
user_pref("security.ssl.disable_session_identifiers", true);

//Set time range to clear everything and clear all but site preferences
user_pref("privacy.sanitize.timeSpan",0)
user_pref("privacy.cpd.offlineApps", true);
user_pref("privacy.cpd.cache", true);
user_pref("privacy.cpd.cookies", true);
user_pref("privacy.cpd.downloads", true);
user_pref("privacy.cpd.formdata", true);
user_pref("privacy.cpd.history", true);
user_pref("privacy.cpd.sessions", true);

//Telemetry
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("experiments.supported", false);
user_pref("experiments.enabled", false);
user_pref("experiments.manifest.uri", "");
user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false);
user_pref("browser.crashReports.unsubmittedCheck.enabled", false);
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.healthreport.service.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("network.manage-offline-status", false);
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");
user_pref("extensions.shield-recipe-client.enabled", false);
user_pref("browser.discovery.enabled", false);
user_pref("loop.logDomains", false);
user_pref("browser.pagethumbnails.capturing_disabled", true);
user_pref("browser.shell.shortcutFavicons", false);
user_pref("browser.chrome.site_icons", false);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("security.ssl.errorReporting.automatic", false);

//Clicpboard event detection javascript
user_pref("dom.event.clipboardevents.enabled", false);

//Clipboard
//user_pref("dom.allow_cut_copy", false);
user_pref("clipboard.autocopy", false);
//Service workers
user_pref("dom.serviceWorkers.enabled", false);

//Web Notifications
user_pref("dom.webnotifications.enabled", false);

//Audio API
user_pref("dom.webaudio.enabled", false);

//Geography
user_pref("geo.enabled", false);
user_pref("geo.wifi.uri", "https://location.services.mozilla.com/v1/geolocate?key=%MOZILLA_API_KEY%");
user_pref("geo.wifi.logging.enabled", false);
user_pref("browser.search.countryCode", "US");
user_pref("browser.search.region", "US");
user_pref("browser.search.geoip.url", "");
user_pref("intl.accept_languages", "en-US, en");
user_pref("intl.locale.matchOS", false);
user_pref("browser.search.geoSpecificDefaults", false);
user_pref("javascript.use_us_english_locale", true);

//mozAddonManager Web APi
user_pref("privacy.resistFingerprinting.block_mozAddonManager", true);
user_pref("extensions.webextensions.restrictedDomains", "");

//Network API
user_pref("dom.network.enabled", false);

//Web Assembly
user_pref("javascript.options.wasm", false);
user_pref("javascript.options.asmjs", false);

//WebRTC
user_pref("media.peerconnection.enabled", false);
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.ice.no_host", true);
user_pref("media.navigator.enabled", false);
user_pref("media.navigator.video.enabled", false);
user_pref("media.getusermedia.screensharing.enabled", false);
user_pref("media.getusermedia.audiocapture.enabled", false);

//WebGL
user_pref("webgl.disabled", true);
user_pref("webgl.min_capability_mode", true);
user_pref("webgl.disable-extensions", true);
user_pref("webgl.disable-fail-if-major-performance-caveat", true);
user_pref("webgl.enable-debug-renderer-info", false);

//Flyweb
user_pref("dom.flyweb.enabled", false);

//Render PDFs
user_pref("pdfjs.enableWebGL", false);
user_pref("pdfjs.disabled", true);

//Battery API
user_pref("dom.battery.enabled", false);

//Sensors API
user_pref("device.sensors.enabled", false);

//Telephony API
user_pref("dom.telephony.enabled", false);

//Gamepad API (prevents USB device enumeration)
user_pref("dom.gamepad.enabled", false);

//webVR
user_pref("dom.vr.enabled", false);

//vibrator API
user_pref("dom.vibrator.enabled", false);

//DOM Timing API
user_pref("dom.enable_performance", false);

//Resource Timing API
user_pref("dom.enable_resource_timing", false);

//User Timing API
user_pref("dom.enable_user_timing", false);

//Archieve API
user_pref("dom.archivereader.enabled", false);

//WebIDE
user_pref("devtools.webide.enabled", false);
user_pref("devtools.webide.autoinstallADBHelper", false);
user_pref("devtools.webide.autoinstallFxdtAdapters", false);

//Prevent Remote debugging
user_pref("devtools.debugger.remote-enabled", false);
user_pref("devtools.chrome.enabled", false);
user_pref("devtools.debugger.force-local", true);

//Disable Flash Player NPAPI plugin
user_pref("plugin.state.flash", 0);
user_pref("dom.ipc.plugins.flash.subprocess.crashreporter.enabled", false);
user_pref("dom.ipc.plugins.reportCrashURL", false);
user_pref("browser.safebrowsing.blockedURIs.enabled", true);
//Disable Java NPAPI plugin
user_pref("plugin.state.java", 0);

//Disable Gnome Shell NPAPI plugin
user_pref("plugin.state.libgnome-shell-browser-plugin", 0);

//raw TCP socket support
user_pref("dom.mozTCPSocket.enabled", false);

//Extension recommendations
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr",false);

//Network/brownser connction information
user_pref("dom.netinfo.enabled", false);

//asynchronouse HTTP transfers
user_pref("beacon.enabled", false);

//Prevents invalid URI submitions
user_pref("keyword.enabled", false);

//Full Url
user_pref("browser.urlbar.trimURLs", false);

//Autocomplete Urls
user_pref("browser.urlbar.speculativeConnect.enabled", false);

//Invalid domain guessing
user_pref("browser.fixup.alternate.enabled", false);

//Hide credentials in url
user_pref("browser.fixup.hide_user_pass", true);

//Send dns through SOCKS when proxy being used
user_pref("network.proxy.socks_remote_dns", true);

//Speech recognition
user_pref("media.webspeech.recognition.enable", false);

//Speech synthesis
user_pref("media.webspeech.synth.enabled", false);

//Pinging urls with html <a> ping attributes
user_pref("browser.send_pings", false);
user_pref("browser.send_pings.require_same_host", true);

//Disable prefeting of <link rel="next" URLs
user_pref("network.prefetch-next", false);

//Disable dns prefetching
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);

//Necko
user_pref("network.predictor.enabled", false);

//Disable password manager
user_pref("signon.rememberSignons", false);
user_pref("browser.formfill.enable", false);
user_pref("signon.autofillForms", false);
user_pref("signon.formlessCapture.enabled", false);
user_pref("signon.autofillForms.http", false);
user_pref("security.insecure_field_warning.contextual.enabled", true);
user_pref("security.insecure_password.ui.enabled", true);
user_pref("security.ask_for_password",2);

//Face Detection
user_pref("camera.control.face_detection.enabled", false);

//Mixed Active Content Blocking
user_pref("security.mixed_content.block_active_content", true);
user_pref("security.mixed_content.block_display_content", true);

//Prevent JAR from opening unsafe filetypes
user_pref("network.jar.open-unsafe-types", false);

//Prevent Scripting of Plugins with Javascript
user_pref("security.xpconnect.plugin.unrestricted", false);

//File URI Orgin Policy
user_pref("security.fileuri.strict_origin_policy", true);

//Prevent javascript in history URLs
user_pref("browser.urlbar.filter.javascript", true);

//Prevent video stats
user_pref("media.video_stats.enabled", false);

//Hide buildID
user_pref("general.buildID.override", "20100101");
user_pref("browser.startup.homepage_override.buildID", "20100101");

//Prevent document specified fonts(font enumeration)
user_pref("browser.display.use_document_fonts", 0);

//Necko A/B testing
user_pref("network.allow-experiments", false);

//Whitelisted URL protocol Headers (true=External false=firefox)
user_pref("network.protocol-handler.warn-external-default", true);
user_pref("network.protocol-handler.external.http", false);
user_pref("network.protocol-handler.external.https", false);
user_pref("network.protocol-handler.external.javascript", false);
user_pref("network.protocol-handler.external.moz-extension", false);
user_pref("network.protocol-handler.external.ftp", false);
user_pref("network.protocol-handler.external.file", false);
user_pref("network.protocol-handler.external.about", false);
user_pref("network.protocol-handler.external.chrome", false);
user_pref("network.protocol-handler.external.blob", false);
user_pref("network.protocol-handler.external.data", false);
user_pref("network.protocol-handler.expose-all", false);
user_pref("network.protocol-handler.expose.http", true);
user_pref("network.protocol-handler.expose.https", true);
user_pref("network.protocol-handler.expose.javascript", true);
user_pref("network.protocol-handler.expose.moz-extension", true);
user_pref("network.protocol-handler.expose.ftp", true);
user_pref("network.protocol-handler.expose.file", true);
user_pref("network.protocol-handler.expose.about", true);
user_pref("network.protocol-handler.expose.chrome", true);
user_pref("network.protocol-handler.expose.blob", true);
user_pref("network.protocol-handler.expose.data", true);

//Enable CSP script-nonce directive support
user_pref("security.csp.experimentalEnabled", true);

//Enable CSP
user_pref("security.csp.enable", true);

//HTTPS only mode
user_pref("dom.security.https_only_mode", true);

//HSTS preload list
user_pref("network.stricttransportsecurity.preloadlist", true);

//Prevent cross domain link redirects
user_pref("network.http.referer.XOriginPolicy", 2);

//Trim HTTP referer headers to only send scheme, host, and port
user_pref("network.http.referer.trimmingPolicy", 2);
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);

//Accept only first party cookies
user_pref("network.cookie.cookieBehavior", 1);
user_pref("network.cookie.cookieBehavior", 1);
user_pref("network.cookie.thirdparty.sessionOnly", true);

//Sub-resource integrity
user_pref("security.sri.enable", true);

//Addon security delay
user_pref("security.dialog_enable_delay", 1000);

//Prevent automatic video playing
user_pref("plugins.click_to_play", true);

//Update addons automatically
user_pref("extensions.update.enabled", true);

//Disable UITour backend
user_pref("browser.uitour.enabled", false);

//Addon and cert blocklists (oneCRL)
user_pref("extensions.blocklist.enabled", true);
user_pref("services.blocklist.update_enabled", true);
user_pref("extensions.blocklist.url", "https://blocklist.addons.mozilla.org/blocklist/3/%APP_ID%/%APP_VERSION%/");

//Search suggestions
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);
user_pref("browser.urlbar.suggest.history", false);
user_pref("browser.urlbar.groupLabels.enabled", false);

//Disable SSDP
user_pref("browser.casting.enabled", false);

//Disable automatic OpenH264 downloads
user_pref("media.gmp-gmpopenh264.enabled", false);
user_pref("media.gmp-manager.url", "");

//Disable speculative pre-connections
user_pref("network.http.speculative-parallel-limit", 0);

//Prevent homepage snippest
user_pref("browser.aboutHomeSnippets.updateUrl", "");
user_pref("browser.newtabpage.activity-stream.feeds.snippets", false);
user_pref("browser.newtabpage.activity-stream.enabled", false);
user_pref("browser.newtabpage.enhanced", false);
user_pref("browser.newtab.preload", false);
user_pref("browser.newtabpage.directory.ping", "");
user_pref("browser.newtabpage.directory.source", "data:text/plain,{}");

//Prevent search enginer update checks
user_pref("browser.search.update", false);

//Disable Automatic captive portal detection
user_pref("network.captive-portal-service.enabled", false);

//Disable blankpage on startup
user_pref("browser.startup.blankWindow", false);

//Disable topsites (part of?)
user_pref("browser.topsites.contile.enabled", false);
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);

//Reject .onion hostnames without passing DNS
user_pref("network.dns.blockDotOnion", true);

//Tracking protection
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.pbmode.enabled", true);
user_pref("privacy.resistFingerprinting", true);

//Enforce checking for firefox updates
user_pref("app.update.enabled", true);

//Block phishing
user_pref("browser.safebrowsing.enabled", true);
user_pref("browser.safebrowsing.phishing.enabled", true);
user_pref("browser.safebrowsing.malware.enabled", true);

//Disable Google Application reputation Database
user_pref("browser.safebrowsing.downloads.remote.enabled", false);

//Prevent downloading of URLS for offline cache
user_pref("browser.cache.offline.enable", false);

//Always ask where to download
user_pref("browser.download.useDownloadDir", false);

//Replace newtab with blank tab
user_pref("browser.newtabpage.enabled", false);
user_pref("browser.newtab.url", "about:blank");

//Disable pocket
user_pref("browser.pocket.enabled", false);
user_pref("extensions.pocket.enabled", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);

//Contextual identity containers
user_pref("privacy.userContext.enabled", true);

//Remove vpn ads
user_pref("browser.vpn_promo.enabled", false);

//Opt-out of themes persona updates
user_pref("lightweightThemes.update.enabled", false);

//Notify outdated plugins
user_pref("plugins.update.notifyUser",true);

//Force punycoe for Internationalized domain names
user_pref("network.IDN_show_punycode", true);

//Disable autocomplete
user_pref("browser.urlbar.autoFill", false);
user_pref("browser.urlbar.autoFill.typed", false);
user_pref("browser.urlbar.autocomplete.enabled", false);

//Notify when website offers data for offline use
user_pref("browser.offline-apps.notify", true);

//Require latest tls
user_pref("security.tls.version.min", 3);
user_pref("security.tls.version.max", 4);
user_pref("security.tls.version.fallback-limit", 4);

//Prepopulate current URL but dont pre-fetch cert
user_pref("browser.ssl_override_behavior", 1);

//Enable SNI when TRR enabled
user_pref("network.security.esni.enabled", true)

//Disable obsolete ciphers
user_pref("security.ssl3.rsa_null_sha", false);
user_pref("security.ssl3.rsa_null_md5", false);
user_pref("security.ssl3.ecdhe_rsa_null_sha", false);
user_pref("security.ssl3.ecdhe_ecdsa_null_sha", false);
user_pref("security.ssl3.ecdh_rsa_null_sha", false);
user_pref("security.ssl3.ecdh_ecdsa_null_sha", false);
user_pref("security.ssl3.rsa_rc4_40_md5", false);
user_pref("security.ssl3.rsa_rc2_40_md5", false);
user_pref("security.ssl3.rsa_1024_rc4_56_sha", false);
user_pref("security.ssl3.rsa_camellia_128_sha", false);
user_pref("security.ssl3.ecdhe_rsa_aes_128_sha", false);
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_sha", false);
user_pref("security.ssl3.ecdh_rsa_aes_128_sha", false);
user_pref("security.ssl3.ecdh_ecdsa_aes_128_sha", false);
user_pref("security.ssl3.dhe_rsa_camellia_128_sha", false);
user_pref("security.ssl3.dhe_rsa_aes_128_sha", false);
user_pref("security.ssl3.ecdh_ecdsa_rc4_128_sha", false);
user_pref("security.ssl3.ecdh_rsa_rc4_128_sha", false);
user_pref("security.ssl3.ecdhe_ecdsa_rc4_128_sha", false);
user_pref("security.ssl3.ecdhe_rsa_rc4_128_sha", false);
user_pref("security.ssl3.rsa_rc4_128_md5", false);
user_pref("security.ssl3.rsa_rc4_128_sha", false);
user_pref("security.tls.unrestricted_rc4_fallback", false);
user_pref("security.ssl3.dhe_dss_des_ede3_sha", false);
user_pref("security.ssl3.dhe_rsa_des_ede3_sha", false);
user_pref("security.ssl3.ecdh_ecdsa_des_ede3_sha", false);
user_pref("security.ssl3.ecdh_rsa_des_ede3_sha", false);
user_pref("security.ssl3.ecdhe_ecdsa_des_ede3_sha", false);
user_pref("security.ssl3.ecdhe_rsa_des_ede3_sha", false);
user_pref("security.ssl3.rsa_des_ede3_sha", false);
user_pref("security.ssl3.rsa_fips_des_ede3_sha", false);
user_pref("security.ssl3.ecdh_rsa_aes_256_sha", false);
user_pref("security.ssl3.ecdh_ecdsa_aes_256_sha", false);
user_pref("security.ssl3.rsa_camellia_256_sha", false);
user_pref("security.ssl3.rsa_seed_sha", false);
user_pref("security.pki.sha1_enforcement_level", 1);
user_pref("security.ssl3.dhe_rsa_camellia_256_sha", false);
user_pref("security.ssl3.dhe_rsa_aes_256_sha", false);
user_pref("security.ssl3.dhe_dss_aes_128_sha", false);
user_pref("security.ssl3.dhe_dss_aes_256_sha", false);
user_pref("security.ssl3.dhe_dss_camellia_128_sha", false);
user_pref("security.ssl3.dhe_dss_camellia_256_sha", false);

//Enable GCM ciphers
user_pref("security.ssl3.ecdhe_ecdsa_aes_128_gcm_sha256", true);
user_pref("security.ssl3.ecdhe_rsa_aes_128_gcm_sha256", true);

//Enable X25519Kyber768Draft00 (post-quantum key exchange)
user_pref("security.tls.enable_kyber", true);

//Enable ChaCha20 and Poly1305
user_pref("security.ssl3.ecdhe_ecdsa_chacha20_poly1305_sha256", true);
user_pref("security.ssl3.ecdhe_rsa_chacha20_poly1305_sha256", true);

//Enforce Public Key Pinning
user_pref("security.cert_pinning.enforcement_level", 2);

//Warn if no support of RFC 5746
user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);

//Prevent SVG OpenType fonts
user_pref("gfx.font_rendering.opentype_svg.enabled", false);
//user_pref("svg.disabled", true);


//IndexedDB (used by uBlock Orgin)
//user_pref("dom.indexedDB.enabled", false);

//DOM storage (disabling can cause TypeError localStorage is null)
//user_pref("dom.storage.enabled", false);
