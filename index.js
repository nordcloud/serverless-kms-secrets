'use strict';

/**
 * serverless-kms-secrets
 * - a plugin for for encrypting secrets using KMS with Serverless Framework
 */

const fse = require('fs-extra');
const BbPromise = require('bluebird');
const yaml = require('yamljs');
const AWS = require('aws-sdk');

AWS.config.setPromisesDependency(BbPromise);

// Update new value into the serverless key config file
function updateFile(filePath, varName, encValue, keyArn) {
  return new BbPromise((resolve) => {
    let kmsSecrets = {
      secrets: {},
      keyArn,
    };

    if (fse.existsSync(filePath)) {
      kmsSecrets = yaml.load(filePath);
    }

    kmsSecrets.secrets[varName] = encValue;
    kmsSecrets.keyArn = keyArn;

    fse.writeFileSync(filePath, yaml.stringify(kmsSecrets, 2));
    return resolve();
  });
}

function readFile(filePath) {
  return new BbPromise((resolve, reject) => {
    if (!fse.existsSync(filePath)) {
      reject(`No file ${filePath}`);
    }

    const kmsSecrets = yaml.load(filePath);

    return resolve(kmsSecrets.secrets);
  });
}

class kmsSecretsPlugin {
  constructor(serverless, options) {
    this.serverless = serverless;
    this.options = options;

    this.commands = {
      encrypt: {
        usage: 'Encrypt variables to file',
        lifecycleEvents: [
          'kmsEncrypt',
        ],
        options: {
          name: {
            usage: 'Name of variable',
            shortcut: 'n',
            required: true,
          },
          value: {
            usage: 'Value of variable',
            shortcut: 'v',
            required: true,
          },
        },
      },
      decrypt: {
        usage: 'Decrypt variables from file',
        lifecycleEvents: [
          'kmsDecrypt',
        ],
        options: {
          name: {
            usage: 'Name of variable',
            shortcut: 'n',
            required: false,
          },
        },
      },
    };

    this.hooks = {
      'encrypt:kmsEncrypt': () => {
        BbPromise.bind(this)
          .then(this.encryptVariable);
      },
      'decrypt:kmsDecrypt': () => {
        BbPromise.bind(this)
          .then(this.decryptVariable);
      },
    };
  }

  encryptVariable() {
    const myModule = this;
    const stage = this.options.stage;
    const region = this.options.region;

    this.serverless.service.load({
      stage,
      region,
    })
    .then((inited) => {
      myModule.serverless.environment = inited.environment;
      const vars = new myModule.serverless.classes.Variables(myModule.serverless);
      vars.populateService(this.options);

      const moduleConfig = inited.custom['serverless-kms-secrets'];
      if (!moduleConfig) {
        myModule.serverless.cli.log('No configuration for serverless-kms-secrets in serverless.yml'); // eslint-disable-line max-len
        return;
      }
      if (!moduleConfig.keyId) {
        myModule.serverless.cli.log('No keyId in serverless.yml');
        return;
      }

      const configFile =
        moduleConfig.secretsFile
          || `kms-secrets.${inited.provider.stage}.${inited.provider.region}.yml`;

      AWS.config.update({ region: inited.provider.region });
      const kms = new AWS.KMS();
      kms.encrypt({
        KeyId: moduleConfig.keyId, // The identifier of the CMK to use for encryption.
        // You can use the key ID or Amazon Resource Name (ARN) of the CMK,
        // or the name or ARN of an alias that refers to the CMK.
        Plaintext: Buffer(this.options.value), // eslint-disable-line new-cap
      }).promise()
      .then((data) => {
        updateFile(
          configFile,
          this.options.name,
          data.CiphertextBlob.toString('base64'),
          data.KeyId)
        .then(() => {
          myModule.serverless.cli.log(`Updated ${this.options.name} to ${configFile}`);
        }, error => {
          myModule.serverless.cli.log(`Error updating ${configFile} : ${error}`);
        });
      }, error => {
        myModule.serverless.cli.log(error);
      });
    }, error => myModule.serverless.cli.log(error));
  }

// Decrypt a variable defined in the options
  decryptVariable() {
    const myModule = this;

    const stage = this.options.stage;
    const region = this.options.region;

    this.serverless.service.load({
      stage,
      region,
    })
    .then((inited) => {
      myModule.serverless.environment = inited.environment;
      const vars = new myModule.serverless.classes.Variables(myModule.serverless);
      vars.populateService(this.options);

      const moduleConfig = inited.custom['serverless-kms-secrets'];
      if (!moduleConfig) {
        myModule.serverless.cli.log('No configuration for serverless-kms-secrets in serverless.yml'); // eslint-disable-line max-len
        return;
      }

      const configFile =
        moduleConfig.secretsFile
          || `kms-secrets.${inited.provider.stage}.${inited.provider.region}.yml`;
      myModule.serverless.cli.log(`Decrypting secrets from ${configFile}`);

      readFile(configFile)
      .then(secrets => {
        const names = this.options.name ? [this.options.name] : Object.keys(secrets);
        names.forEach((varName) => {
          if (secrets[varName]) {
            AWS.config.update({ region: inited.provider.region });
            const kms = new AWS.KMS();
            kms.decrypt({
              CiphertextBlob: Buffer(secrets[varName], 'base64'), // eslint-disable-line new-cap
            }).promise()
            .then(data => {
              const secret = String(data.Plaintext);
              myModule.serverless.cli.log(`${varName} = ${secret}`);
            }, error => {
              myModule.serverless.cli.log(`KMS error ${error}`);
            });
          } else {
            myModule.serverless.cli.log(`No secret with name ${varName}`);
          }
        });
      }, error => myModule.serverless.cli.log(error));
    }, error => myModule.serverless.cli.log(error));
  }
}

module.exports = kmsSecretsPlugin;
