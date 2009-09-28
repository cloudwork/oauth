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

/* Here's some JavaScript software for implementing OAuth.

   This isn't as useful as you might hope.  OAuth is based around
   allowing tools and websites to talk to each other.  However,
   JavaScript running in web browsers is hampered by security
   restrictions that prevent code running on one website from
   accessing data stored or served on another.

   Before you start hacking, make sure you understand the limitations
   posed by cross-domain XMLHttpRequest.

   On the bright side, some platforms use JavaScript as their
   language, but enable the programmer to access other web sites.
   Examples include Google Gadgets, and Microsoft Vista Sidebar.
   For those platforms, this library should come in handy.
*/

// The HMAC-SHA1 signature method calls b64_hmac_sha1, defined by
// http://pajhome.org.uk/crypt/md5/sha1.js

/* An OAuth message is represented as an object like this:
   {method: "GET", action: "http://server.com/path", parameters: ...}

   The parameters may be either a map {name: value, name2: value2}
   or an Array of name-value pairs [[name, value], [name2, value2]].
   The latter representation is more powerful: it supports parameters
   in a specific sequence, or several parameters with the same name;
   for example [["a", 1], ["b", 2], ["a", 3]].

   Parameter names and values are NOT percent-encoded in an object.
   They must be encoded before transmission and decoded after reception.
   For example, this message object:
   {method: "GET", action: "http://server/path", parameters: {p: "x y"}}
   ... can be transmitted as an HTTP request that begins:
   GET /path?p=x%20y HTTP/1.0
   (This isn't a valid OAuth request, since it lacks a signature etc.)
   Note that the object "x y" is transmitted as x%20y.  To encode
   parameters, you can call OAuth.addToURL, OAuth.formEncode or
   OAuth.getAuthorization.

   This message object model harmonizes with the browser object model for
   input elements of an form, whose value property isn't percent encoded.
   The browser encodes each value before transmitting it. For example,
   see consumer.setInputs in example/consumer.js.
 */

/* This script needs to know what time it is. By default, it uses the local
   clock (new Date), which is apt to be inaccurate in browsers. To do
   better, you can load this script from a URL whose query string contains
   an oauth_timestamp parameter, whose value is a current Unix timestamp.
   For example, when generating the enclosing document using PHP:

   <script src="oauth.js?oauth_timestamp=<?=time()?>" ...

   Another option is to call OAuth.correctTimestamp with a Unix timestamp.
 */

var SHA = require("sha"),
    update = require("hash").Hash.update;

// utility functions
var percentEncode = exports.percentEncode = function (s) {
    if (!s) return "";

    if (s instanceof Array) {
        var e = "";
        for (var i = 0; i < s.length; ++s) {
            if (e != "") e += '&';
            e += percentEncode(s[i]);
        }
        return e;
    }
    s = encodeURIComponent(s);
    // Now replace the values which encodeURIComponent doesn't do
    // encodeURIComponent ignores: - _ . ! ~ * ' ( )
    // OAuth dictates the only ones you can ignore are: - _ . ~
    // Source: http://developer.mozilla.org/en/docs/Core_JavaScript_1.5_Reference:Global_Functions:encodeURIComponent
    s = s.replace(/\!/g, "%21");
    s = s.replace(/\*/g, "%2A");
    s = s.replace(/\'/g, "%27");
    s = s.replace(/\(/g, "%28");
    s = s.replace(/\)/g, "%29");
    return s;
}

var decodePercent = function (s) {
    if (s != null) {
        // Handle application/x-www-form-urlencoded, which is defined by
        // http://www.w3.org/TR/html4/interact/forms.html#h-17.13.4.1
        s = s.replace(/\+/g, " ");
    }
    return decodeURIComponent(s);
}

/** Convert the given parameters to an Array of name-value pairs. */
var getParameterList = exports.getParameterList = function (parameters) {
    if (!parameters) return [];
    if (typeof parameters != "object") return decodeForm(parameters + "");
    if (parameters instanceof Array) return parameters;

    var list = [];
    for (var p in parameters) {
        list.push([p, parameters[p]]);
    }
    return list;
}

/** Convert the given parameters to a map from name to value. */
var getParameterMap = exports.getParameterMap = function (parameters) {
    if (!parameters) return {};
    if (typeof parameters != "object") return getParameterMap(decodeForm(parameters + ""));

    if (parameters instanceof Array) {
        var map = {};
        for (var p = 0; p < parameters.length; ++p) {
            var key = parameters[p][0];
            if (map[key] === undefined) { // first value wins
                map[key] = parameters[p][1];
            }
        }
        return map;
    }
    return parameters;
}

var getParameter = exports.getParameter = function (parameters, name) {
    if (parameters instanceof Array) {
        for (var p = 0; p < parameters.length; ++p) {
            if (parameters[p][0] == name) {
                return parameters[p][1]; // first value wins
            }
        }
    } else {
        return getParameterMap(parameters)[name];
    }
    return null;
}

var formEncode = function (parameters) {
    var form = "";
    var list = getParameterList(parameters);
    for (var p = 0; p < list.length; ++p) {
        var value = list[p][1];
        if (value == null) value = "";
        if (form != "") form += '&';
        form += percentEncode(list[p][0])
          +'='+ percentEncode(value);
    }
    return form;
}

var decodeForm = function (form) {
    var list = [];
    var nvps = form.split('&');
    for (var n = 0; n < nvps.length; ++n) {
        var nvp = nvps[n];
        if (nvp == "") {
            continue;
        }
        var equals = nvp.indexOf('=');
        var name, value;
        if (equals < 0) {
            name = decodePercent(nvp);
            value = null;
        } else {
            name = decodePercent(nvp.substring(0, equals));
            value = decodePercent(nvp.substring(equals + 1));
        }
        list.push([name, value]);
    }
    return list;
}

var setParameter = function (message, name, value) {
    var parameters = message.parameters;
    if (parameters instanceof Array) {
        for (var p = 0; p < parameters.length; ++p) {
            if (parameters[p][0] == name) {
                if (value === undefined) {
                    parameters.splice(p, 1);
                } else {
                    parameters[p][1] = value;
                    value = undefined;
                }
            }
        }
        if (value !== undefined) {
            parameters.push([name, value]);
        }
    } else {
        parameters = getParameterMap(parameters);
        parameters[name] = value;
        message.parameters = parameters;
    }
}

var setParameters = function (message, parameters) {
    var list = getParameterList(parameters);
    for (var i = 0; i < list.length; ++i) {
        setParameter(message, list[i][0], list[i][1]);
    }
}

/** Fill in parameters to help construct a request message.
    This function doesn't fill in every parameter.
    The accessor object should be like:
    {consumerKey:'foo', consumerSecret:'bar', accessorSecret:'nurn', token:'krelm', tokenSecret:'blah'}
    The accessorSecret property is optional.
 */

var completeRequest = exports.completeRequest = function (message, accessor) {
    if (!message.method) message.method = "GET";

    var map = getParameterMap(message.parameters);
    if (!map.oauth_consumer_key)            setParameter(message, "oauth_consumer_key", accessor.consumerKey || "");
    if (!map.oauth_token && accessor.token) setParameter(message, "oauth_token", accessor.token);
    if (!map.oauth_version)                 setParameter(message, "oauth_version", "1.0");
    if (!map.oauth_timestamp)               setParameter(message, "oauth_timestamp", timestamp());
    if (!map.oauth_nonce)                   setParameter(message, "oauth_nonce", nonce(6));

    sign(message, accessor);
}

var setTimestampAndNonce = function (message) {
    setParameter(message, "oauth_timestamp", timestamp());
    setParameter(message, "oauth_nonce", nonce(6));
}

var addToURL = function (url, parameters) {
    newURL = url;
    if (parameters) {
        var toAdd = formEncode(parameters);
        if (toAdd.length > 0) {
            var q = url.indexOf('?');
            if (q < 0) newURL += '?';
            else       newURL += '&';
            newURL += toAdd;
        }
    }
    return newURL;
}

/** Construct the value of the Authorization header for an HTTP request. */
var getAuthorizationHeader = exports.getAuthorizationHeader = function (realm, parameters) {
    var header = 'OAuth realm="' + percentEncode(realm) + '"';
    var list = getParameterList(parameters);
    for (var p = 0; p < list.length; ++p) {
        var parameter = list[p];
        var name = parameter[0];
        if (name.indexOf("oauth_") == 0) {
            header += ',' + percentEncode(name) + '="' + percentEncode(parameter[1]) + '"';
        }
    }
    return header;
}

/** Correct the time using a parameter from the URL from which the last script was loaded. */
var correctTimestampFromSrc = function (parameterName) {
    parameterName = parameterName || "oauth_timestamp";
    var scripts = []; //document.getElementsByTagName('script');  TODO fix reference to document
    if (scripts == null || !scripts.length) return;
    var src = scripts[scripts.length-1].src;
    if (!src) return;
    var q = src.indexOf("?");
    if (q < 0) return;
    parameters = getParameterMap(decodeForm(src.substring(q+1)));
    var t = parameters[parameterName];
    if (t == null) return;
    correctTimestamp(t);
}

/** Generate timestamps starting with the given value. */
var correctTimestamp = function (timestamp) {
    timeCorrectionMsec = (timestamp * 1000) - (new Date()).getTime();
}

/** The difference between the correct time and my clock. */
var timeCorrectionMsec = 0;

var timestamp = function timestamp() {
    var t = (new Date()).getTime() + timeCorrectionMsec;
    return Math.floor(t / 1000);
}

var nonceChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz";

var nonce = function nonce(length) {
    var result = "";
    for (var i = 0; i < length; ++i) {
        var rnum = Math.floor(Math.random() * nonceChars.length);
        result += nonceChars.substring(rnum, rnum+1);
    }
    return result;
}

var getBaseString = exports.getBaseString = function (message) {
    var URL = message.action;
    var q = URL.indexOf('?');
    var parameters;
    if (q < 0) {
        parameters = message.parameters;
    } else {
        // Combine the URL query string with the other parameters:
        parameters = decodeForm(URL.substring(q + 1));
        var toAdd = getParameterList(message.parameters);
        for (var a = 0; a < toAdd.length; ++a) {
            parameters.push(toAdd[a]);
        }
    }
    return percentEncode(message.method.toUpperCase())
     +'&'+ percentEncode(normalizeUrl(URL))
     +'&'+ percentEncode(normalizeParameters(parameters));
}

var normalizeUrl = function (url) {
    var uri = parseUri(url);
    var scheme = uri.protocol.toLowerCase();
    var authority = uri.authority.toLowerCase();
    var dropPort = (scheme == "http" && uri.port == 80) || (scheme == "https" && uri.port == 443);
    if (dropPort) {
        // find the last : in the authority
        var index = authority.lastIndexOf(":");
        if (index >= 0) {
            authority = authority.substring(0, index);
        }
    }
    var path = uri.path;
    if (!path) {
        path = "/"; // conforms to RFC 2616 section 3.2.2
    }
    // we know that there is no query and no fragment here.
    return scheme + "://" + authority + path;
}

var parseUri = function (str) {
    /* This function was adapted from parseUri 1.2.1
       http://stevenlevithan.com/demo/parseuri/js/assets/parseuri.js
     */
    var o = {key: ["source","protocol","authority","userInfo","user","password","host","port","relative","path","directory","file","query","anchor"],
             parser: {strict: /^(?:([^:\/?#]+):)?(?:\/\/((?:(([^:@]*):?([^:@]*))?@)?([^:\/?#]*)(?::(\d*))?))?((((?:[^?#\/]*\/)*)([^?#]*))(?:\?([^#]*))?(?:#(.*))?)/ }};
    var m = o.parser.strict.exec(str);
    var uri = {};
    var i = 14;
    while (i--) uri[o.key[i]] = m[i] || "";
    return uri;
}

var normalizeParameters = function (parameters) {
    if (!parameters) return "";

    var list = getParameterList(parameters);
    var sortable = [];
    for (var p = 0; p < list.length; ++p) {
        var nvp = list[p];
        if (nvp[0] != "oauth_signature") {
            sortable.push([ percentEncode(nvp[0])
                          + " " // because it comes before any character that can appear in a percentEncoded string.
                          + percentEncode(nvp[1])
                          , nvp]);
        }
    }
    sortable.sort(function(a,b) {
                      if (a[0] < b[0]) return -1;
                      if (a[0] > b[0]) return 1;
                      return 0;
                  });
    var sorted = [];
    for (var s = 0; s < sortable.length; ++s) {
        sorted.push(sortable[s][1]);
    }
    return formEncode(sorted);
}

/** A map from signature method name to constructor. */
var REGISTERED = {};

var registerMethod = function (names, method) {
    names.forEach(function(name) {
        REGISTERED[name] = method;
    });
}

var sign = function (message, accessor) {
    var name = getParameterMap(message.parameters).oauth_signature_method;
    if (!name || name == "") {
        name = "HMAC-SHA1";
        setParameter(message, "oauth_signature_method", name);
    }
    newMethod(name, accessor).sign(message);
}

/** Instantiate a SignatureMethod for the given method name. */
var newMethod = exports.newMethod = function (name, accessor) {
    if (REGISTERED[name]) return new (REGISTERED[name])(name, accessor);

    var err = new Error("signature_method_rejected");
    var acceptable = "";
    for (var r in REGISTERED) {
        if (acceptable != "") acceptable += '&';
        acceptable += percentEncode(r);
    }
    err.oauth_acceptable_signature_methods = acceptable;
    throw err;
}

/** Subsequently, the given constructor will be used for the named methods.
    The constructor will be called with no parameters.
    The resulting object should usually implement getSignature(baseString).
    You can easily define such a constructor by calling makeSubclass, below.
 */

/** Create a subclass of OAuth.SignatureMethod, with the given getSignature function. */
var makeSignatureClass = function (options) {

    var c = function(name, accessor) {
        this.initialize(name, accessor);
    };

    c.prototype = Object.create(SignatureMethod.prototype);
    update(c.prototype, options);

    return c;
}


/** An abstract algorithm for signing messages. */
/* SignatureMethod expects an accessor object to be like this:
   {tokenSecret: "lakjsdflkj...", consumerSecret: "QOUEWRI..", accessorSecret: "xcmvzc..."}
   The accessorSecret property is optional.
 */

SignatureMethod = function(){};

SignatureMethod.prototype = {

    /** Add a signature to the message. */
    sign: function (message) {
        var baseString = getBaseString(message);
        var signature = this.getSignature(baseString);
        setParameter(message, "oauth_signature", signature);
        return signature; // just in case someone's interested
    },

    /** Set the key string for signing. */
    initialize: function (name, accessor) {
        var consumerSecret;
        if (accessor.accessorSecret
            && name.length > 9
            && name.substring(name.length-9) == "-Accessor")
        {
            consumerSecret = accessor.accessorSecret;
        } else {
            consumerSecret = accessor.consumerSecret;
        }
        this.key = percentEncode(consumerSecret) + "&" + percentEncode(accessor.tokenSecret);
    }
};

registerMethod(["PLAINTEXT", "PLAINTEXT-Accessor"],
    makeSignatureClass({
        getSignature: function (baseString) {
            return this.key;
        }
    })
);

registerMethod(["HMAC-SHA1", "HMAC-SHA1-Accessor"],
    makeSignatureClass({
        getSignature: function (baseString) {
            return SHA.hmac_sha(this.key, baseString).toString(64);
        }
    })  
);

correctTimestampFromSrc();