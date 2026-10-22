const { chromium, webkit } = require("playwright");
const fs = require("node:fs");
const path = require("node:path");

exports.seedEmptyPolicies = async context => {
  const { makeDemoData } = await import("../src/shared/demo/data.mjs");
  const data = makeDemoData();
  data.access = { books: [], invitations: [], network: { cidr: "10.203.0.0/24", dns_suffix: "ph.io" } };
  await context.addInitScript(seed => {
    if (!sessionStorage.getItem("porthub-demo-v1")) sessionStorage.setItem("porthub-demo-v1", JSON.stringify(seed));
  }, data);
};

exports.navigateWorkspace = async (page, name) => {
  const target = name === "Public Web Proxies" ? "Proxies" : name === "Access Rules" ? "Rules" : name;
  const button = page.getByRole("button", {name:target,exact:true});
  if (!(await button.isVisible().catch(()=>false))) await page.getByRole("button",{name:"More navigation",exact:true}).click();
  await button.click();
};

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
