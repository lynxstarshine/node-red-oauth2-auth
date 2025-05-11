module.exports = function (RED) {
  "use strict";

  const crypto = require("crypto");
  const axios = require('axios');

  function generateRandomString(length) {
    var text = "";
    var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    for (var i = 0; i < length; i++) {
      text += possible.charAt(Math.floor(Math.random() * possible.length));
    }

    return text;
  }

  async function generateCodeChallenge(codeVerifier) {
    var digest = await crypto.subtle.digest("SHA-256",
      new TextEncoder().encode(codeVerifier));

    return btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
  }

  function OAuth2AuthConfig(config) {
    RED.nodes.createNode(this, config);
  }

  RED.nodes.registerType("oauth2-auth-config", OAuth2AuthConfig);

  function OAuth2Auth(config) {
    RED.nodes.createNode(this, config);

    var node = this;

    node.on('input', function (msg, send, done) {
      node.status({ fill: "blue", shape: "dot", text: RED._("oauth2auth.status.refreshing") });

      node.refreshNodeCredentials((err) => {
        node.status({});

        if (err) {
          node.status({ fill: "red", shape: "dot", text: RED._("oauth2auth.status.failed") });
          if (done) {
            done(err);
          } else {
            node.error(err, msg);
          }
          return
        }

        msg.bearerToken = 'Bearer ' + node.credentials.access_token;
        send(msg);
        if (done) {
          done();
        }
      });
    });
  }

  RED.nodes.registerType("oauth2-auth", OAuth2Auth, {
    credentials: {
      client_id: { type: "text" },
      client_secret: { type: "password" },
      access_token_url: { type: "password" },
      access_token: { type: "password" },
      refresh_token: { type: "password" },
      expire_time: { type: "password" },
      auth_time: { type: "text" }
    }
  });

  OAuth2Auth.prototype.refreshNodeCredentials = function (callback) {
    const node = this;

    node.credentials = RED.nodes.getCredentials(node.id);

    if (node.credentials && node.credentials.expire_time && node.credentials.expire_time >= (new Date().getTime() / 1000)) {
      return callback(null);
    }

    axios.post(node.credentials.access_token_url, {
      grant_type: 'refresh_token',
      client_id: node.credentials.client_id,
      client_secret: node.credentials.client_secret,
      refresh_token: node.credentials.refresh_token
    }, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },

    }).then((response) => {

      if (response.data.error) {
        node.error(RED._("oauth2auth.error.something_broke", { error: data.error }));
        return callback(data.error);
      }

      node.credentials.access_token = reponse.data.access_token;
      node.credentials.refresh_token = reponse.data.refresh_token;
      node.credentials.expires_in = reponse.data.expires_in;
      node.credentials.expire_time = reponse.data.expires_in + (new Date().getTime() / 1000);

      RED.nodes.addCredentials(node.id, node.credentials);

      return callback(null);
    }, (error) => {
      node.error(RED._("oauth2auth.error.get_access_token", { error: error }));
      return callback(error);
    })
  }

  RED.httpAdmin.get('/oauth2-auth/auth', function (req, res) {
    if (!req.query.id || !req.query.client_id || !req.query.client_secret || !req.query.authentication_url || !req.query.redirect_url || !req.query.access_token_url) {
      res.send(400);
      return;
    }

    var node_id = req.query.id;
    var client_id = req.query.client_id;
    var client_secret = req.query.client_secret;
    var scope = req.query.scope;
    var force_login = req.query.force_login;
    var authentication_url = req.query.authentication_url;
    var redirect_url = req.query.redirect_url;
    var access_token_url = req.query.access_token_url;
    var csrf_token = crypto.randomBytes(18).toString('base64').replace(/\//g, '-').replace(/\+/g, '_');
    var code_verifier = generateRandomString(64)
    var state = node_id + ":" + csrf_token;

    var credentials = {
      client_id: client_id,
      client_secret: client_secret,
      redirect_url: redirect_url,
      access_token_url: access_token_url,
      csrf_token: csrf_token,
      code_verifier: code_verifier
    };

    RED.nodes.addCredentials(node_id, credentials);

    generateCodeChallenge(code_verifier).then((codeChallenge) => {
      var authentication_url_obj = new URL(authentication_url);
      authentication_url_obj.search = new URLSearchParams({
        client_id: credentials.client_id,
        redirect_uri: redirect_url,
        response_type: 'code',
        code_challenge_method: 'S256',
        code_challenge: codeChallenge,
        state: state,
        scope: scope,
        prompt: force_login.toLowerCase() === "true" ? "login" : "consent"
      });

      res.cookie('csrf', csrf_token);
      res.redirect(authentication_url_obj.href);
    })
  });

  RED.httpAdmin.get('/oauth2-auth/callback', function (req, res) {
    if (req.query.error) {
      return res.send(RED._("oauth2auth.error.error", { error: req.query.error, description: req.query.error_description }));
    }

    var auth_code = req.query.code;
    var state = req.query.state.split(':');
    var node_id = state[0];
    var credentials = RED.nodes.getCredentials(node_id);

    if (!credentials || !credentials.client_id || !credentials.client_secret) {
      return res.send(RED._("oauth2auth.error.no_credentials"));
    }

    if (state[1] !== credentials.csrf_token) {
      return res.status(401).send(RED._("oauth2auth.error.csrf_token_mismatch"));
    }

    axios.post(credentials.access_token_url, {
      grant_type: 'authorization_code',
      code: auth_code,
      client_id: credentials.client_id,
      client_secret: credentials.client_secret,
      code_verifier: credentials.code_verifier,
      redirect_uri: credentials.redirect_url,
    }, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },

    }).then((response) => {
      const data = response.data
      if (data.error) {
        return res.send(RED._("oauth2auth.error.something_broke", { error: data.error }));
      }

      credentials.access_token = data.access_token;
      credentials.refresh_token = data.refresh_token;
      credentials.expires_in = data.expires_in;
      credentials.expire_time = data.expires_in + (new Date().getTime() / 1000);
      credentials.auth_time = Date.now();

      delete credentials.csrf_token;
      delete credentials.redirect_url;
      delete credentials.code_verifier;

      RED.nodes.addCredentials(node_id, credentials);

      res.send(RED._("oauth2auth.message.authorisation_successful"));
    }, (error) => {
      return res.send(RED._("oauth2auth.error.get_access_token", { error: error }));
    });
  });
}

