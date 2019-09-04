# Serverless KMS Secrets

A Serverless Plugin for the [Serverless Framework](http://www.serverless.com) which
helps with encrypting service secrets using the AWS Key Management Service (KMS)

## Introduction

This plugins does the following:

* It provides commands to encrypt and decrypt secrets with KMS

## Installation and configuration

In your service root, run:

```bash
npm install --save-dev serverless-kms-secrets
```

Add the plugin to `serverless.yml`:

```yml
plugins:
  - serverless-kms-secrets
```

Configure the plugin into the custom block in `serverless.yml`. For example:

```yml
custom:
  serverless-kms-secrets:
    secretsFile: kms-secrets.${opt:stage, self:provider.stage}.${opt:region, self:provider.region}.yml (optional)
  kmsSecrets: ${file(kms-secrets.${opt:stage, self:provider.stage}.${opt:region, self:provider.region}.yml)}
```

By default, the plugin creates secrets to the file kms-secrets.[stage].[region].yml. This can be overriden with the secretsFile parameter in the serverless-kms-secrets configuration.

Add Decrypt permissions to your lambda function with e.g. this block in IamRoleStatements:

```yml
    - Effect: Allow
      Action:
      - KMS:Decrypt
      Resource: ${self:custom.kmsSecrets.keyArn} 
```

## Usage

### Creating KMS Key

Create a KMS key in AWS IAM service, under Encryption keys. Collect the key id, which is the remaining part of the key ARN.

### Encrypting Variables

To encrypt a variable using the key defined in the configuration, enter
```
sls encrypt -n VARIABLE_NAME -v myvalue [-k keyId]
```

e.g.

```
sls encrypt -n SLACK_API_TOKEN -v xoxp-1234567890-1234567890-123467890-a12346 -k 999999-9999-99999-999
```
The keyid (-k) parameter is mandatory for the first encrypted variable, but optional for the later ones (will be read from the secrets file).
The encrypted variable is written to your secrets file (kms-secrets.[stage].[region].yml by default)

You may also pack multiple secrets into one KMS encrypted string. This simplifies consuming the secrets in the Lambda function since all secrets can be decrypted with one single KMS.Decrypt call. To encrypt multiple secrets into one single string, use the following notation:

```
sls encrypt -n VARIABLE_NAME:SECRET_NAME -v myvalue [-k keyId]
```

e.g.

```
sls encrypt -n SECRETS:SLACK_API_TOKEN -v xoxp-1234567890-1234567890-123467890-a12346 -k 999999-9999-99999-999
```

Would encrypt and add the SLACK_API_TOKEN into the (JSON) secret SECRETS.

NOTE: you may get warnings about the missing kms-secrets file when encrypting your first variables for a specific stage / region. The warning will go away once the file has been created by the plugin.

### Decrypting Variables

The variables in the secrets file can be decrypted using

```
sls decrypt [-n VARIABLE_NAME]
```

The -n option is optional. Without that, all variables are decrypted and displayed in clear text on the console.

### Using variables

Pass the variables stored in the secrets file e.g. as environment variables using

```yml
  environment:
    MY_VARIABLE: ${self:custom.kmsSecrets.secrets.MY_VARIABLE}
```

The variable must be decrypted in the Lambda function using the KMS decrypt method. E.g.

```js
kms.decrypt({
  CiphertextBlob: Buffer(process.env.MY_VARIABLE, 'base64')
}).promise()
.then(data => {
  const decrypted = String(data.Plaintext)
})
```

If MY_VARIABLE consists of multiple variables, decode it using

```js
  const secrets = JSON.parse(decrypted);
```

### Using one secret file for multiple stages

Rather than having one secret file per stage, you can have one secret file with multiple stages.

Add the `perStage` configuration parameters to your `serverless.yml` configuration file.

```yml
custom:
  serverless-kms-secrets:
    secretsFile: kms-secrets.yml
    filePerStage: false # true = one file per stage, false = one file, defaults to true
  kmsSecrets: ${file(kms-secrets.yml)}
```

Specify the `stage` when encrypting the variable.

```
sls encrypt -n VARIABLE_NAME -v myvalue [-k keyId] --stage dev
```

The encrypt command will also use the `provider.stage` value in the `serverless.yml` configuration file.

```yml
provider:
  stage: ${opt:stage, env:stage, 'dev'}
```

```
sls encrypt -n VARIABLE_NAME -v myvalue [-k keyId]
```

Your `kms-secrets.yml` file has the stage in the first level.

```yml
dev:
  secrets:
    VARIABLE_NAME: encrypted_data
  keyArn: key_arn
prd:
  secrets:
    VARIABLE_NAME: encrypted_data
  keyArn: key_arn
```

Reference the stage when using the variable in the `provider.environment` section of the `serverless.yml` configuration file.

```yml
provider:
  environment:
    MY_VARIABLE: ${self:custom.kmsSecrets.${self:provider.stage}.secrets.VARIABLE_NAME}
```


## TODO

* Add support for sls deploy (deploy as KMS encrypted environment variables)
* Ease configuration (KeyIds / Arns in various places)

## Release History

* 2017/09/09 - v1.0.0 - Add support for multisecret structures
* 2017/05/13 - v0.9.0 - Initial version


## License

Copyright (c) 2017 [Nordcloud](https://nordcloud.com/), licensed for users and contributors under MIT license.
https://github.com/nordcloud/serverless-kms-secrets/blob/master/LICENSE
