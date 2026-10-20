const { chromium, webkit } = require("playwright");
const fs = require("node:fs");
const path = require("node:path");

exports.launchBrowser = async () => {
  if (process.env.REVIEW_BROWSER !== "webkit") {
    const executablePath = process.env.CHROMIUM_EXECUTABLE || (fs.existsSync("/usr/bin/google-chrome") ? "/usr/bin/google-chrome" : undefined);
    return chromium.launch({executablePath});
  }
  if (!process.env.WEBKIT_LIBRARY_PATH) return webkit.launch();
  // Optional unpacked Linux libraries keep testing isolated from system packages.
  const base = path.join(path.dirname(webkit.executablePath()), "minibrowser-wpe");
  process.env.PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS = "1";
  return webkit.launch({executablePath:path.join(base,"bin/MiniBrowser"),env:{...process.env,
    WEBKIT_EXEC_PATH:path.join(base,"bin"), WEBKIT_INJECTED_BUNDLE_PATH:path.join(base,"lib"),
    WEBKIT_INSPECTOR_RESOURCES_PATH:path.join(base,"share"),
    LD_LIBRARY_PATH:[process.env.WEBKIT_LIBRARY_PATH,path.join(base,"lib"),path.join(base,"sys/lib")].join(":"),
  }});
};
