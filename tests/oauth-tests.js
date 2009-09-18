/*
 * Portions Copyright 2009 Neville Burnell
 */

/*
 * Copyright 2008 Netflix, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var assert = require("test/assert"),
    OAuth = require("OAuth").OAuth;

var ENCODING // From http://wiki.oauth.net/TestCases
  = [ ["abcABC123", "abcABC123"]
    , ["-._~"     , "-._~"]
    , ["%"        , "%25"]
    , ["+"        , "%2B"]
    , ["&=*"      , "%26%3D%2A"]
    , ["!'()"     , "%21%27%28%29"]
    , ["\n"       , "%0A"]
    , [" "        , "%20"]
    ];

exports.testEncode = function() {
    for (var i = 0; i < ENCODING.length; ++i) {
        var input    = ENCODING[i][0];
        var expected = ENCODING[i][1];
        var actual = OAuth.percentEncode(input);

        assert.eq(expected, actual);
    };
};

exports.testGetParameterList = function() {
    var list;

    list = OAuth.getParameterList(null);
    assert.eq([], list);

    list = OAuth.getParameterList('');
    assert.eq([], list);
};

exports.testGetParameterMap = function() {
    var map = OAuth.getParameterMap(null);
    assert.isFalse(null === map);
    assert.isFalse(map instanceof Array);
    assert.isTrue(map instanceof Object);
};

exports.testGetParameter = function() {
    var actual;

    actual = OAuth.getParameter({x: 'a', y: 'b'}, 'x');
    assert.eq('a', actual);

    actual = OAuth.getParameter([['x', 'a'], ['y', 'b'], ['x', 'c']], 'x');
    assert.eq('a', actual);
};

exports.testGetAuthorizationHeader = function() {
    var actual;
    var expected = 'OAuth realm="R",oauth_token="T",oauth_w%40%21rd="%23%40%2A%21"';

    actual = OAuth.getAuthorizationHeader('R', [['a', 'b'], ['oauth_token', 'T'], ['oauth_w@!rd', '#@*!']]);
    assert.isFalse(null === actual);
    assert.eq(expected, actual);

    actual = OAuth.getAuthorizationHeader('R', {a: 'b', oauth_token: 'T', 'oauth_w@!rd': '#@*!'});
    assert.isFalse(null === actual);
    assert.eq(expected, actual);
};

exports.testCompleteRequest = function() {
    var message = {action: 'http://localhost', parameters: {}};
    OAuth.completeRequest(message, {consumerKey: 'CK', token: 'T'});

    assert.eq('GET', message['method']);

    var map = message.parameters;

    assert.eq('CK', map['oauth_consumer_key']);
    assert.eq('T', map['oauth_token']);
    assert.eq('1.0', map['oauth_version']);
    assert.isFalse(null === map['oauth_timestamp']);
    assert.isFalse(null === map['oauth_nonce']);
};


var OAUTH_A_BASE_STRING = "GET&http%3A%2F%2Fphotos.example.net%2Fphotos&"
    + "file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal";

var BASES = //
    // label, HTTP method, action, parameters, expected
    { "simple"         : ["GET", "http://example.com/", {n: "v"}, "GET&http%3A%2F%2Fexample.com%2F&n%3Dv" ]
    , "no path"        : ["GET", "http://example.com" , {n: "v"}, "GET&http%3A%2F%2Fexample.com%2F&n%3Dv" ]
    , "sorting"        : ["GET", "http://example.com/", [["n", "AB"], ["n", "{}"]], "GET&http%3A%2F%2Fexample.com%2F&n%3D%257B%257D%26n%3DAB" ]
    , "OAuth A request": ["POST", "https://photos.example.net/request_token",
            { oauth_version: "1.0", oauth_consumer_key: "dpf43f3p2l4k3l03"
            , oauth_timestamp: "1191242090", oauth_nonce: "hsu94j3884jdopsl"
            , oauth_signature_method: "PLAINTEXT", oauth_signature: "ignored"
            }
            , "POST&https%3A%2F%2Fphotos.example.net%2Frequest_token&"
                 + "oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dhsu94j3884jdopsl%26oauth_signature_method%3DPLAINTEXT%26oauth_timestamp%3D1191242090%26oauth_version%3D1.0" ]
    , "OAuth A access" : ["GET", "http://photos.example.net/photos",
            { file: "vacation.jpg", size: "original"
            , oauth_version: "1.0", oauth_consumer_key: "dpf43f3p2l4k3l03", oauth_token: "nnch734d00sl2jdk"
            , oauth_timestamp: "1191242096", oauth_nonce: "kllo9940pd9333jh"
            , oauth_signature: "ignored", oauth_signature_method: "HMAC-SHA1"
            }
            , OAUTH_A_BASE_STRING ]
};

exports.testGetBaseString = function() {
    for (var label in BASES) {
        var base = BASES[label];
        var b = 0;
        var method = base[b++];
        var action = base[b++];
        var parameters = base[b++];
        var expected = base[b++];
        var actual = OAuth.SignatureMethod.getBaseString({method: method, action: action, parameters: parameters});

        assert.eq(expected, actual, label);
    };
};

var SIGNATURES =
// label, method, consumer secret, token secret, base string, expected
{ "HMAC-SHA1.a"    : [ "HMAC-SHA1", "cs", null, "bs", "egQqG5AJep5sJ7anhXju1unge2I=" ]
, "HMAC-SHA1.b"    : [ "HMAC-SHA1", "cs", "ts", "bs", "VZVjXceV7JgPq/dOTnNmEfO0Fv8=" ]
, "OAuth A access" : [ "HMAC-SHA1", "kd94hf93k423kf44",
                       "pfkkdhi9sl3r4s00", OAUTH_A_BASE_STRING,
                       "tR3+Ty81lMeYAr/Fid0kMTYa/WM=" ]
, "PLAINTEXT"      : [ "PLAINTEXT", "cs", "ts", "bs", "cs&ts" ]
, "OAuth A request": [ "PLAINTEXT", "kd94hf93k423kf44", null, null, "kd94hf93k423kf44&" ]
};

exports.testGetSignature = function() {
    for (var label in SIGNATURES) {
        var signature = SIGNATURES[label];
        var s = 0;
        var methodName = signature[s++];
        var consumerSecret = signature[s++];
        var tokenSecret = signature[s++];
        var baseString = signature[s++];
        var expected = signature[s++];
        var signer = OAuth.SignatureMethod.newMethod(methodName,
                     {consumerSecret: consumerSecret, tokenSecret: tokenSecret});
        var actual = signer.getSignature(baseString);

        assert.eq(expected, actual, label);
    };
};
