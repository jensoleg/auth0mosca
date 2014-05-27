var request = require('request');
var jwt = require('jsonwebtoken');

/*
 auth0Namespace is yuor domain in Auth0, e.g. https://yourcompany.auth0.com
 clientId, identifies your app (mosca) with Auth0
 clientSecret, is used to sign the JWT (and validate it when using JWT mode)
 connection identifies the user store you want to use in Auth0. It must be one that supports the
 'Resource Owner' flow: Active Directory, database, etc.
 */
function Auth0Mosca(auth0Namespace, clientId, clientSecret, connection) {
    this.auth0Namespace = auth0Namespace;
    this.connection = connection;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
}

/*
 Used when the device is sending JWT instead of credentials.
 mqtt.username must be JWT
 mqtt.password is the JWT itself
 */
Auth0Mosca.prototype.authenticateWithJWT = function () {

    var self = this;

    return function (client, username, password, callback) {

        if (username !== 'JWT') {
            return callback("Invalid Credentials", false);
        }

        jwt.verify(password, new Buffer(self.clientSecret, 'base64'), function (err, profile) {
            if (err) {
                return callback("Error getting UserInfo", false);
            }
            client.deviceProfile = profile;
            return callback(null, true);
        });
    }
};

/*
 Used when the device is sending credentials.
 mqtt.username must correspond to the device username in the Auth0 connection
 mqtt.password must correspond to the device password
 */
Auth0Mosca.prototype.authenticateWithCredentials = function () {

    var self = this;

    return function (client, username, password, callback) {

        var data = {
            client_id: self.clientId, // {client-name}
            username: username,
            password: password,
            connection: self.connection,
            grant_type: "password",
            scope: 'openid profile'
        };

        request.post({
            headers: {
                "Content-type": "application/json"
            },
            url: self.auth0Namespace + '/oauth/ro',
            body: JSON.stringify(data)
        }, function (e, r, b) {
            if (e) {
                return callback(e, false);
            }
            var r = JSON.parse(b);

            if (r.error) {
                return callback(r, false);
            }

            jwt.verify(r.id_token, new Buffer(self.clientSecret, 'base64'), function (err, profile) {
                if (err) {
                    return callback("Error getting UserInfo", false);
                }
                client.deviceProfile = profile; //profile attached to the client object
                return callback(null, true);
            });
        });
    }
};

/*
 Used when the device may send username/password or JWT credentials.
 mqtt.username must correspond to the device username in the Auth0 connection
 mqtt.password must correspond to the device password
 First JWT token is checked and if it fails username/password credentials is verified
 */
Auth0Mosca.prototype.authenticate = function () {

    var self = this;
    var authenticateWithJWT = self.authenticateWithJWT();
    var authenticateWithCredentials = self.authenticateWithCredentials();

    return function (client, username, password, callback) {

        authenticateWithJWT(client, username, password, function (err, verdict) {
            if (err) {
                authenticateWithCredentials(client, username, password, function (err, verdict) {
                    if (err) {
                        return callback(err, false);
                    }
                    else {
                        return callback(null, true);
                    }
                })
            }
            else {
                return callback(null, true);
            }
        })
    }
};

Auth0Mosca.prototype.authorizePublish = function () {
    return function (client, topic, payload, callback) {
//        callback(null, client.deviceProfile && client.deviceProfile.topics && client.deviceProfile.topics.indexOf(topic) > -1);
        callback(null, true);

    }
};

Auth0Mosca.prototype.authorizeSubscribe = function () {
    return function (client, topic, callback) {
//        callback(null, client.deviceProfile && client.deviceProfile.topics && client.deviceProfile.topics.indexOf(topic) > -1);
        callback(null, true);

    }
};

module.exports = Auth0Mosca;
