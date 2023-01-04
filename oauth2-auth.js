const path = require('path');
const fs = require('fs');

module.exports = function (RED) {

  "use strict";

  function OAuth2Auth(config) {
    RED.nodes.createNode(this, config);

    var node = this;

    node.credentials = loadNodeCredentials(node.id, (err) => node.warn(err));

    node.on('input', function (msg) {
      // if (!node.credentials.expireTime || node.credentials.expireTime < (new Date().getTime() / 1000)) {
      //   refreshToken(function (err) {
      //     if (err) {
      //       node.error(err);
      //     }
      //   });
      // }

      node.credentials.accessToken = node.credentials.accessToken ? node.credentials.accessToken + 1 : 1;
      
      RED.nodes.addCredentials(node.id, node.credentials);

      saveNodeCredentials(node.id, node.credentials, (err) => node.error(err));

      msg.headerAuth = 'Bearer: ' + node.credentials.accessToken;
      node.send(msg);
    });
  }

  function loadNodeCredentials(node_id, error_callback) {
    const filepath = path.join(RED.settings.userDir, 'node_' + node_id + '_cred.json')
    const encoding = 'utf8';

    try {
      if (!fs.existsSync(filepath))
      {
        return {};
      }

      const content = fs.readFileSync(filepath, encoding);
      const credentials = JSON.parse(content);

      RED.nodes.addCredentials(node_id, credentials);

      return credentials;
    }
    catch (error) {
      if (error_callback) {
        error_callback("Could not load node credentials: " + error);
      }

      return {};
    }
  }

  function saveNodeCredentials(node_id, credentials, error_callback) {
    const filepath = path.join(RED.settings.userDir, 'node_' + node_id + '_cred.json');
    const content = JSON.stringify(credentials);
    const encoding = 'utf8';
    
    try {
      fs.writeFileSync(filepath, content, encoding);
    } 
    catch (error) {
      if (error_callback) {
        error_callback("Could not save node credentials: " + error);
      }
    }
  }

  // function decryptCredentials(key,credentials) {
  //   var encryptionAlgorithm = "aes-256-ctr";
  //   var creds = credentials["$"];
  //   var initVector = Buffer.from(creds.substring(0, 32),'hex');
  //   creds = creds.substring(32);
  //   var decipher = crypto.createDecipheriv(encryptionAlgorithm, key, initVector);
  //   var decrypted = decipher.update(creds, 'base64', 'utf8') + decipher.final('utf8');
  //   return JSON.parse(decrypted);
  // }

  // refreshToken = function () {
  //   var credentials = this.credentials;
  //   var node = this;

  //   if (!credentials.refreshToken) {
  //     node.error("No refresh token");

  //     return;
  //   }

  //   request.post(
  //     {
  //       url: node.access_token_url,
  //       json: true,
  //       form: {
  //         grant_type: 'refresh_token',
  //         client_id: credentials.clientId,
  //         client_secret: credentials.clientSecret,
  //         refresh_token: credentials.refreshToken,
  //       },
  //     },
  //     function (err, result, data) {
  //       if (err) {
  //         node.error("Refresh token error", { err: err });

  //         return;
  //       }

  //       if (data.error) {
  //         node.error("Refresh token error", { message: data.error.message });

  //         return;
  //       }

  //       credentials.accessToken = data.access_token;

  //       if (data.refresh_token) {
  //         credentials.refreshToken = data.refresh_token;
  //       }

  //       credentials.expiresIn = data.expires_in;
  //       credentials.expireTime = data.expires_in + (new Date().getTime() / 1000);
  //       credentials.tokenType = data.token_type;

  //       RED.nodes.addCredentials(node.id, credentials);
  //     }
  //   );
  // };

  RED.nodes.registerType("oauth2-auth", OAuth2Auth, {
    credentials: {
      clientId: { type: "text" },
      clientSecret: { type: "password" },
      accessToken: { type: "password" },
      refreshToken: { type: "password" },
      expireTime: { type: "password" }
    }
  });
}

