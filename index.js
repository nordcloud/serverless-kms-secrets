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
          keyid: {
            usage: 'KMS key Id',
            shortcut: 'k',
            required: false
          }
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
      return vars.populateService(this.options).then(() => inited);
    })
    .then((inited) => {
      const moduleConfig = inited.custom['serverless-kms-secrets'] || {};

      const region = this.options.region || inited.provider.region;
      const stage = this.options.stage || inited.provider.stage;

      const configFile =
        moduleConfig.secretsFile
          || `kms-secrets.${stage}.${region}.yml`;
      let kmsSecrets = {
        secrets: {}
      };
      let keyId = this.options.keyid;

      if (fse.existsSync(configFile)) {
        kmsSecrets = yaml.load(configFile)
        if (! keyId) {
          keyId = kmsSecrets.keyArn.replace(/.*\//, '');
          myModule.serverless.cli.log(`Encrypting using key ${keyId} found in ${configFile}`);
        }  
      } else {
        if (! this.options.keyid) {
          myModule.serverless.cli.log(`No config file ${configFile} and no keyid specified`);
          return ('No keyId in serverless.yml')
        }
      }

      AWS.config.update({ region });
      const kms = new AWS.KMS();
      kms.encrypt({
        KeyId: keyId, // The identifier of the CMK to use for encryption.
        // You can use the key ID or Amazon Resource Name (ARN) of the CMK,
        // or the name or ARN of an alias that refers to the CMK.
        Plaintext: Buffer.from(String(this.options.value)), // eslint-disable-line new-cap
      }).promise()
      .then((data) => {
        kmsSecrets.secrets[this.options.name] = data.CiphertextBlob.toString('base64');
        kmsSecrets.keyArn = data.KeyId;
        fse.writeFileSync(configFile, yaml.stringify(kmsSecrets,2));
        myModule.serverless.cli.log(`Updated ${this.options.name} to ${configFile}`);
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
      return vars.populateService(this.options).then(() => inited);
    })
    .then((inited) => {
      const moduleConfig = inited.custom['serverless-kms-secrets'] || {};
      
      const stage = this.options.stage || inited.provider.stage;
      const region = this.options.region || inited.provider.region;

      const configFile =
        moduleConfig.secretsFile
          || `kms-secrets.${stage}.${region}.yml`;
      myModule.serverless.cli.log(`Decrypting secrets from ${configFile}`);

      readFile(configFile)
      .then(secrets => {
        const names = this.options.name ? [this.options.name] : Object.keys(secrets);
        names.forEach((varName) => {
          if (secrets[varName]) {
            AWS.config.update({ region });
            const kms = new AWS.KMS();
            kms.decrypt({
              CiphertextBlob: Buffer.from(secrets[varName], 'base64'), // eslint-disable-line new-cap
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
