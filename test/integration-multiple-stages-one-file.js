'use strict';

const Serverless = require('serverless');
const execSync = require('child_process').execSync;
const path = require('path');
const fse = require('fs-extra');
const expect = require('chai').expect;
const testUtils = require('./testUtils');

const serverless = new Serverless();
serverless.init();
const serverlessExec = path.join(serverless.config.serverlessPath, '..', 'bin', 'serverless');

describe('integration with filePerStage option', () => {
  before(() => {
    // create temporary directory and copy test service there
    process.env.MOCHA_PLUGIN_TEST_DIR = path.join(__dirname);
    const tmpDir = testUtils.getTmpDirPath();
    fse.mkdirsSync(tmpDir);
    fse.copySync(path.join(process.env.MOCHA_PLUGIN_TEST_DIR, 'test-service-multiple-stages-one-file'), tmpDir);
    process.chdir(tmpDir);
  });

  it('should contain encrypt and decrypt params in cli info', () => {
    const test = execSync(`${serverlessExec}`);
    const result = new Buffer(test, 'base64').toString();
    expect(result).to.have.string('encrypt ....................... Encrypt variables to file');
    expect(result).to.have.string('decrypt ....................... Decrypt variables from file');
    expect(result).to.have.string('kmsSecretsPlugin');
  });

  // it('should create test for hello function', () => {
  //   const test = execSync(`${serverlessExec} encrypt -n MY_VARIABLE -v my-secret`);
  //   const result = new Buffer(test, 'base64').toString();
  // });
});
