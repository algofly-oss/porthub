const fs = require('node:fs');
const path = require('node:path');
const root = path.dirname(require.resolve('@excalidraw/excalidraw'));
const out = path.join(__dirname, '../public/excalidraw');
fs.mkdirSync(out, {recursive:true});
fs.cpSync(path.join(root,'fonts'),path.join(out,'fonts'),{recursive:true});
fs.copyFileSync(path.join(__dirname,'../licenses/excalidraw-LICENSE.txt'),path.join(out,'LICENSE.txt'));

fs.copyFileSync(path.join(__dirname,'../licenses/excalidraw-fonts.txt'),path.join(out,'FONT-LICENSES.txt'));
