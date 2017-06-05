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
  CiphertextBlob: Buffer(process.env[MY_VARIABLE], 'base64')
}).promise()
.then(data => {
  const decrypted = String(data.Plaintext)
})
```


## TODO

* Add support for sls deploy (deploy as KMS encrypted environment variables)
* Ease configuration (KeyIds / Arns in various places)

## Release History

* 2017/05/13 - v0.9.0 - Initial version


## License

Copyright (c) 2017 [SC5](http://sc5.io/), licensed for users and contributors under MIT license.
https://github.com/SC5/serverless-kms-secrets/blob/master/LICENSE
