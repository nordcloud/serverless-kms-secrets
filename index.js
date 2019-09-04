'use strict';

/**
 * serverless-kms-secrets
 * - a plugin for for encrypting secrets using KMS with Serverless Framework
 */

const fse = require('fs-extra');
const BbPromise = require('bluebird');
const yaml = require('yamljs');

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
            required: false,
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
      'encrypt:kmsEncrypt': this.encryptVariable.bind(this),
      'decrypt:kmsDecrypt': this.decryptVariable.bind(this),
    };
  }


  decrypt(secret, region, stage) {
    const myModule = this;
    return new Promise((success, failure) => {
      myModule.serverless.getProvider('aws')
        .request('KMS',
          'decrypt',
          {
            CiphertextBlob: Buffer.from(secret, 'base64'), // eslint-disable-line new-cap
          }, region, stage)
        .then((data) => {
          success(String(data.Plaintext));
        }, failure);
    });
  }

  encryptVariable() {
    return new Promise((resolve, reject) => {
      const myModule = this;
      let stage = this.options.stage;
      let region = this.options.region;
      const parts = this.options.name.split(':');
      const varname = parts[0];
      const subvarname = parts[1];
      let value = this.options.value;

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
          region = this.options.region || inited.provider.region;
          stage = this.options.stage || inited.provider.stage;

          const configFile =
            moduleConfig.secretsFile
              || `kms-secrets.${stage}.${region}.yml`;
          const perStage = moduleConfig.perStage || false;
          console.log('perStage', perStage);
          let kmsSecrets = {
            secrets: {},
          };
          let configData;
          let keyId = this.options.keyid;

          if (fse.existsSync(configFile)) {
            configData = yaml.load(configFile);
            console.log('configData', configData);
            kmsSecrets = perStage ? configData[stage]: configData;
            console.log('kmsSecrets', kmsSecrets);
            if (!keyId) {
              keyId = kmsSecrets.keyArn.replace(/.*\//, '');
              myModule.serverless.cli.log(`Encrypting using key ${keyId} found in ${configFile}`);
            }
          } else if (!this.options.keyid) {
            myModule.serverless.cli.log(`No config file ${configFile} and no keyid specified`);
            reject('No keyId in serverless.yml');
          }

          function preEncrypt() {
            return new Promise((succeed) => {
              if (subvarname) {
                if (kmsSecrets &&
                    kmsSecrets.secrets &&
                    kmsSecrets.secrets[varname]) {
                  myModule.decrypt(kmsSecrets.secrets[varname], region, stage)
                    .then((valtext) => {
                      succeed(JSON.parse(valtext));
                    });
                } else {
                  succeed({});
                }
              } else {
                succeed({});
              }
            });
          }

          return preEncrypt()
            .then((valstruct) => {
              if (subvarname) {
                const newStruct = valstruct;
                newStruct[subvarname] = value;
                value = JSON.stringify(newStruct);
              }

              myModule.serverless.getProvider('aws')
                .request('KMS',
                  'encrypt',
                  {
                    KeyId: keyId, // The identifier of the CMK to use for encryption.
                    // You can use the key ID or Amazon Resource Name (ARN) of the CMK,
                    // or the name or ARN of an alias that refers to the CMK.
                    Plaintext: Buffer.from(String(value)), // eslint-disable-line new-cap
                  }, region, stage)
                .then((data) => {
                  kmsSecrets.secrets[varname] = data.CiphertextBlob.toString('base64');
                  kmsSecrets.keyArn = data.KeyId;
                  if (perStage) {
                    configData[stage] = kmsSecrets;
                  } else {
                    configData = kmsSecrets;
                  }
                  fse.writeFileSync(configFile, yaml.stringify(configData, 3, 2));
                  myModule.serverless.cli.log(`Updated ${varname} to ${configFile}`);
                  resolve();
                }, (error) => {
                  myModule.serverless.cli.log(error);
                  reject(error);
                });
            });
        }, (error) => {
          myModule.serverless.cli.log(error);
          reject(error);
        });
    });
  }

  // Decrypt a variable defined in the options
  decryptVariable() {
    return new Promise((resolve, reject) => {
      const myModule = this;

      let stage = this.options.stage;
      let region = this.options.region;

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
          stage = this.options.stage || inited.provider.stage;
          region = this.options.region || inited.provider.region;

          const configFile =
            moduleConfig.secretsFile
              || `kms-secrets.${stage}.${region}.yml`;
          myModule.serverless.cli.log(`Decrypting secrets from ${configFile}`);

          readFile(configFile)
            .then((secrets) => {
              const names = this.options.name ? [this.options.name] : Object.keys(secrets);
              names.forEach((varName) => {
                const parts = varName.split(':');
                const mainVarName = parts[0];
                const subVarName = parts[1];

                if (secrets[mainVarName]) {
                  myModule.decrypt(secrets[mainVarName], region, stage)
                    .then((secret) => {
                      if (subVarName) {
                        let varStruct = {};
                        if (secret) {
                          varStruct = JSON.parse(secret);
                        }
                        myModule.serverless.cli.log(`${varName} = ${varStruct[subVarName] || ''}`);
                      } else {
                        myModule.serverless.cli.log(`${varName} = ${secret}`);
                      }
                    }, (error) => {
                      myModule.serverless.cli.log(`KMS error ${error}`);
                      reject(error);
                    });
                } else {
                  myModule.serverless.cli.log(`No secret with name ${varName}`);
                  resolve();
                }
              });
            }, error => myModule.serverless.cli.log(error));
        }, error => myModule.serverless.cli.log(error));
    });
  }
}

module.exports = kmsSecretsPlugin;
