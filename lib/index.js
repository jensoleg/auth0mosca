'use strict';

var request = require('request'),
    jwt = require('jsonwebtoken');

/*
 auth0Namespace is yuor domain in Auth0, e.g. https://yourcompany.auth0.com
 clientId, identifies your app (mosca) with Auth0
 clientSecret, is used to sign the JWT (and validate it when using JWT mode)
 connection identifies the user store you want to use in Auth0. It must be one that supports the
 'Resource Owner' flow: Active Directory, database, etc.
 */

// Initialize with reference to auth0 config
function Auth0Mosca(domains) {
    this.domains = domains;
}

/*
 Used when the device is sending JWT instead of credentials.
 mqtt.username must be JWT
 mqtt.password is the JWT itself
 */
Auth0Mosca.prototype.authenticateWithJWT = function () {

    var self = this;

    return function (client, username, password, callback) {

        if (!username || !password) {
            return callback("Invalid Credentials", false);
        }

        var domain = username.toString().split("@", 1)[0],
            user = username.toString().substr(domain.length + 1);

        if (!user || !domain || user !== 'JWT') {
            return callback("Invalid Credentials", false);
        }

        var config = self.domains[domain];

        jwt.verify(password, new Buffer(config.clientSecret, 'base64'), function (err, profile) {
            if (err) {
                return callback("Error getting UserInfo", false);
            }
            client.domain = domain;
            client.deviceProfile = profile;
            return callback(null, true);
        });
    };
};

/*
 Used when the device is sending credentials.
 mqtt.username must correspond to the device username in the Auth0 connection
 mqtt.password must correspond to the device password
 */
Auth0Mosca.prototype.authenticateWithCredentials = function () {

    var self = this;

    return function (client, username, password, callback) {

        if (!username || !password) {
            return callback("Invalid Credentials", false);
        }

        var domain = username.toString().split("@", 1)[0],
            user = username.toString().substr(domain.length + 1);

        if (!user || !domain) {
            return callback("Invalid Credentials", false);
        }

        var config = self.domains[domain],
            data = {
                client_id: config.clientId, // {client-name}
                username: user,
                password: password.toString(),
                connection: 'Username-Password-Authentication',
                grant_type: "password",
                scope: 'openid profile'
            };

        request.post({
            headers: {
                "Content-type": "application/json"
            },
            url: config.endpoint + '/oauth/ro',
            body: JSON.stringify(data)
        }, function (e, r, b) {

            if (e) {
                return callback(e, false);
            }
            r = JSON.parse(b);

            if (r.error) {
                return callback(r, false);
            }

            jwt.verify(r.id_token, new Buffer(config.clientSecret, 'base64'), function (err, profile) {

                if (err) {
                    return callback("Error getting UserInfo", false);
                }
                client.domain = domain;
                client.deviceProfile = profile; //profile attached to the client object
                return callback(null, true);
            });
        });
    };
};

/*
 Used when the device may send username/password or JWT credentials.
 mqtt.username must correspond to the device username in the Auth0 connection
 mqtt.password must correspond to the device password
 First JWT token is checked and if it fails username/password credentials is verified
 */
Auth0Mosca.prototype.authenticate = function () {

    var authenticateWithJWT = this.authenticateWithJWT(),
        authenticateWithCredentials = this.authenticateWithCredentials();

    return function (client, username, password, callback) {

        if (!username) {
            return callback("Missing username", false);
        }

        var domain = username.toString().split("@", 1)[0],
            user = username.toString().substr(domain.length + 1);

        authenticateWithJWT(client, username, password, function (err, verdict) {
            if (err) {
                if (user !== 'JWT') {
                    authenticateWithCredentials(client, username, password, function (err, verdict) {
                        if (err) {
                            return callback(err, false);
                        }
                        return callback(null, true);
                    });
                } else {
                    return callback(null, false);
                }
            }
            return callback(null, true);
        });
    };
};

Auth0Mosca.prototype.authorizePublish = function () {
    return function (client, topic, payload, callback) {
        // callback(null, client.deviceProfile && client.deviceProfile.topics && client.deviceProfile.topics.indexOf(topic) > -1);
        callback(null, true);
    };
};

Auth0Mosca.prototype.authorizeSubscribe = function () {
    return function (client, topic, callback) {
        // callback(null, client.deviceProfile && client.deviceProfile.topics && client.deviceProfile.topics.indexOf(topic) > -1);
        callback(null, true);
    };
};

module.exports = Auth0Mosca;