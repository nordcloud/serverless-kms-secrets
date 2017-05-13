// Proxy
const path = require('path');

if(!process.env.MOCHA_PLUGIN_TEST_DIR) {
  process.env.MOCHA_PLUGIN_TEST_DIR = path.join(__dirname, '../../../');
}

const mochaDir = path.join(process.env.MOCHA_PLUGIN_TEST_DIR, '../', 'index.js');
module.exports = require(mochaDir);
