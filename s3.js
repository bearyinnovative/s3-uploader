'use strict';

//-----------------------------------------------------------------------------
/*****************************************************************************
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-1, as defined
 * in FIPS PUB 180-1
 * Version 2.1a Copyright Paul Johnston 2000 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for details.
 */


var b64pad  = "="; /* base-64 pad character. "=" for strict RFC compliance   */
var chrsz   = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode      */

function b64_hmac_sha1(key, data) { return binb2b64(core_hmac_sha1(key, data));}

function core_sha1(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << (24 - len % 32);
  x[((len + 64 >> 9) << 4) + 15] = len;

  var w = Array(80);
  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;
  var e = -1009589776;

  for(var i = 0; i < x.length; i += 16)
  {
  var olda = a;
  var oldb = b;
  var oldc = c;
  var oldd = d;
  var olde = e;

  for(var j = 0; j < 80; j++)
  {
    if(j < 16) w[j] = x[i + j];
    else w[j] = rol(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1);
    var t = safe_add(safe_add(rol(a, 5), sha1_ft(j, b, c, d)),
             safe_add(safe_add(e, w[j]), sha1_kt(j)));
    e = d;
    d = c;
    c = rol(b, 30);
    b = a;
    a = t;
  }

  a = safe_add(a, olda);
  b = safe_add(b, oldb);
  c = safe_add(c, oldc);
  d = safe_add(d, oldd);
  e = safe_add(e, olde);
  }
  return Array(a, b, c, d, e);

}

function sha1_ft(t, b, c, d)
{
  if(t < 20) return (b & c) | ((~b) & d);
  if(t < 40) return b ^ c ^ d;
  if(t < 60) return (b & c) | (b & d) | (c & d);
  return b ^ c ^ d;
}

function sha1_kt(t)
{
  return (t < 20) ?  1518500249 : (t < 40) ?  1859775393 :
  (t < 60) ? -1894007588 : -899497514;
}

function core_hmac_sha1(key, data)
{
  var bkey = str2binb(key);
  if(bkey.length > 16) bkey = core_sha1(bkey, key.length * chrsz);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
  ipad[i] = bkey[i] ^ 0x36363636;
  opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = core_sha1(ipad.concat(str2binb(data)), 512 + data.length * chrsz);
  return core_sha1(opad.concat(hash), 512 + 160);
}

function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

function rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

function str2binb(str)
{
  var bin = Array();
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < str.length * chrsz; i += chrsz)
  bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (32 - chrsz - i%32);
  return bin;
}

function binb2b64(binarray)
{
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i += 3)
  {
  var triplet = (((binarray[i   >> 2] >> 8 * (3 -  i   %4)) & 0xFF) << 16)
    | (((binarray[i+1 >> 2] >> 8 * (3 - (i+1)%4)) & 0xFF) << 8 )
    |  ((binarray[i+2 >> 2] >> 8 * (3 - (i+2)%4)) & 0xFF);
  for(var j = 0; j < 4; j++)
  {
    if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
    else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
  }
  }
  return str;
}
//---------------------------End Of Sha1--------------------------------------------------  //
var ACL_HEADER = "x-amz-acl:public-read";

var awsKeyId = ''
var awsKeySecrect = ''

function getRandomKeyName() {
  //FIXME: maybe conflict
  var date = new Date();
  var prefix = [date.getFullYear(), date.getMonth(), date.getDate()].join('');
  var rand = Math.random().toString(36).substr(4);
  return prefix + rand
}

function getPreSignedPath(method, key, contentType, headers, bucket, s3Path) {
  // reference from https://github.com/basho/riak_cs/blob/develop/src/riak_cs_s3_auth.erl#L158
  var resource = "/" + bucket + "/" + key;
  // the uploader url will be expired after 10 minutes
  var expiresAtInSeconds = Math.ceil(Date.now()/1000) + 10 * 60;

  var parts = [];
  parts.push(method);
  parts.push("");
  parts.push(contentType);
  parts.push(expiresAtInSeconds);
  parts.push(headers);
  parts.push(resource);

  var stringToSign = parts.join('\n');
  var sign = b64_hmac_sha1(awsKeySecrect, stringToSign);
  return s3Path + resource + "?AWSAccessKeyId=" + awsKeyId + "&Expires=" + expiresAtInSeconds.toString() + "&Signature=" + encodeURIComponent(sign);
}

function uploader(config) {
  var uploader = new plupload.Uploader(config);
  var bucket = config.bucket
  var S3_PATH = config.s3_path

  uploader.setOption({url: S3_PATH + "/" + bucket});

  if (config.auto_start) {
    uploader.bind('FilesAdded', function(up, files) {
      up.start();
    })
  }

  uploader.bind('BeforeUpload', function(up, file){
    if (!isKeysReady()) {
      confirm('Miss Upload Keys. Try Again Later'); // shoud never fired in real world.
      return
    }
    var key = getRandomKeyName();
    var url = getPreSignedPath("PUT", key, file.type, ACL_HEADER, bucket, S3_PATH);
    file.key = key;
    up.settings.multipart = false;
    up.settings.method = 'put';
    up.settings.content_type = file.type;

    // NOTE:
    //
    // Chrome reuqires proper quoting for content disposition header.
    //
    // Reference:
    //
    //  - https://bugs.chromium.org/p/chromium/issues/detail?id=103618
    //  - http://stackoverflow.com/a/14836763
    var fileName = '"' + encodeURI(file.name) + '"';
    // FIXME: set object acl as public-read for now
    up.setOption({'headers': {"x-amz-acl": "public-read",
                              "content-disposition": "attachment; filename="+fileName}});
    up.setOption({url: url});
  });

  uploader.bind('FileUploaded', function(up, file, info){
    info.key = file.key;
  });
  uploader.init()
  return uploader;
}

function isKeysReady() {
  return !!(awsKeySecrect && awsKeyId)
}

function fetchKeys(api_path) {
  var xmlhttp = new XMLHttpRequest();
  xmlhttp.open('GET', api_path, true);
  xmlhttp.onreadystatechange = function() {
    if (xmlhttp.readyState == 4 && xmlhttp.status == 200) {
      var data = JSON.parse(xmlhttp.responseText);
      if (data.code === 0) {
        awsKeyId = data.result.access_key;
        awsKeySecrect = data.result.secret_key;
      }
    }
  };
  xmlhttp.send(null);
};

module.exports = {
  uploader: uploader,
  fetchKeys: fetchKeys
};
