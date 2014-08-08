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

// Initialize with reference to auth0 domains
function Auth0Mosca(domains) {

    this.domains = domains;

    this.selectDomainAndUser = function (username) {

        var JWT,
            user,
            userStr = username.toString(),
            domain = userStr.split("/")[1];

        if (!domain) {
            JWT = userStr.split("@")[0];
            domain = userStr.split("@")[1];
            if (JWT === 'JWT' || JWT === 'jwt') {
                user = JWT;
            } else {
                user = userStr;
            }
        } else {
            user = userStr.substr(0, userStr.length - domain.length - 1);
        }

        return {'user': user, 'domain': domain};
    };

    this.authenticateJWT = function (client, username, password, callback) {

        var domainUser, config;
        if (!username || !password) {
            return callback("Invalid Credentials", false);
        }

        domainUser = this.selectDomainAndUser(username);

        if (!domainUser.user || !domainUser.domain || domainUser.user !== 'JWT') {
            return callback("Invalid Credentials", false);
        }

        config = this.domains[domainUser.domain];

        if (!config) {
            return callback("Invalid Credentials", false);
        }

        jwt.verify(password, new Buffer(config.clientSecret, 'base64'), function (err, profile) {
            if (err) {
                return callback("Error getting UserInfo", false);
            }
            client.token = password;
            client.domain = domainUser.domain;
            client.deviceProfile = profile;
            return callback(null, true);
        });
    };

    this.authenticateCredentials = function (client, username, password, callback) {
        var domainUser, config, data;

        if (!username || !password) {
            return callback("Invalid Credentials", false);
        }

        domainUser = this.selectDomainAndUser(username);

        if (!domainUser.user || !domainUser.domain) {
            return callback("Invalid Credentials", false);
        }

        config = this.domains[domainUser.domain];

        if (!config) {
            return callback("Invalid Credentials", false);
        }

        data = {
            client_id: config.clientId, // {client-name}
            username: domainUser.user,
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
                client.token = r.id_token;
                client.domain = domainUser.domain;
                client.deviceProfile = profile; //profile attached to the client object
                return callback(null, true);
            });
        });
    };
}

/*
 Used when the device is sending JWT instead of credentials.
 mqtt.username must be JWT
 mqtt.password is the JWT itself
 */
Auth0Mosca.prototype.authenticateWithJWT = function () {

    var self = this;

    return function (client, username, password, callback) {

        self.authenticateJWT(client, username, password, callback);
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

        self.authenticateCredentials(client, username, password, callback);
    };
};

/*
 Used when the device may send username/password or JWT credentials.
 mqtt.username must correspond to the device username in the Auth0 connection
 mqtt.password must correspond to the device password
 First JWT token is checked and if it fails username/password credentials is verified
 */
Auth0Mosca.prototype.authenticate = function () {

    var self = this;

    return function (client, username, password, callback) {

        if (!username) {
            return callback("Missing username", false);
        }

        var domainUser = self.selectDomainAndUser(username);

        self.authenticateJWT(client, username, password, function (err, verdict) {
            if (err) {
                if (domainUser.user !== 'JWT') {
                    self.authenticateCredentials(client, username, password, function (err, verdict) {
                        if (err) {
                            return callback(err, false);
                        }
                        return callback(null, true);
                    });
                } else {
                    return callback(null, false);
                }
            } else {
                return callback(null, true);
            }
        });
    };
};

Auth0Mosca.prototype.authorizePublish = function () {
    return function (client, topic, payload, callback) {
        callback(null, topic.substr(0, client.domain.length) === client.domain || topic.substr(1, client.domain.length) === client.domain);
//        callback(null, {topic: '/' + client.domain + topic});
    };
};

Auth0Mosca.prototype.authorizeSubscribe = function () {
    return function (client, topic, callback) {
        callback(null, topic.substr(0, client.domain.length) === client.domain || topic.substr(1, client.domain.length) === client.domain);
//        callback(null, {topic: '/' + client.domain + topic});
    };
};

module.exports = Auth0Mosca;