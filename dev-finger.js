/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.1 Copyright (C) Paul Johnston 1999 - 2002.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 0;  /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = ""; /* base-64 pad character. "=" for strict RFC compliance   */
var chrsz   = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode      */

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
function hex_md5(s){ return binl2hex(core_md5(str2binl(s), s.length * chrsz));}
function b64_md5(s){ return binl2b64(core_md5(str2binl(s), s.length * chrsz));}
function str_md5(s){ return binl2str(core_md5(str2binl(s), s.length * chrsz));}
function hex_hmac_md5(key, data) { return binl2hex(core_hmac_md5(key, data)); }
function b64_hmac_md5(key, data) { return binl2b64(core_hmac_md5(key, data)); }
function str_hmac_md5(key, data) { return binl2str(core_hmac_md5(key, data)); }

/*
 * Perform a simple self-test to see if the VM is working
 */
function md5_vm_test()
{
  return hex_md5("abc") == "900150983cd24fb0d6963f7d28e17f72";
}

/*
 * Calculate the MD5 of an array of little-endian words, and a bit length
 */
function core_md5(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << ((len) % 32);
  x[(((len + 64) >>> 9) << 4) + 14] = len;

  var a =  1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d =  271733878;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;

    a = md5_ff(a, b, c, d, x[i+ 0], 7 , -680876936);
    d = md5_ff(d, a, b, c, x[i+ 1], 12, -389564586);
    c = md5_ff(c, d, a, b, x[i+ 2], 17,  606105819);
    b = md5_ff(b, c, d, a, x[i+ 3], 22, -1044525330);
    a = md5_ff(a, b, c, d, x[i+ 4], 7 , -176418897);
    d = md5_ff(d, a, b, c, x[i+ 5], 12,  1200080426);
    c = md5_ff(c, d, a, b, x[i+ 6], 17, -1473231341);
    b = md5_ff(b, c, d, a, x[i+ 7], 22, -45705983);
    a = md5_ff(a, b, c, d, x[i+ 8], 7 ,  1770035416);
    d = md5_ff(d, a, b, c, x[i+ 9], 12, -1958414417);
    c = md5_ff(c, d, a, b, x[i+10], 17, -42063);
    b = md5_ff(b, c, d, a, x[i+11], 22, -1990404162);
    a = md5_ff(a, b, c, d, x[i+12], 7 ,  1804603682);
    d = md5_ff(d, a, b, c, x[i+13], 12, -40341101);
    c = md5_ff(c, d, a, b, x[i+14], 17, -1502002290);
    b = md5_ff(b, c, d, a, x[i+15], 22,  1236535329);

    a = md5_gg(a, b, c, d, x[i+ 1], 5 , -165796510);
    d = md5_gg(d, a, b, c, x[i+ 6], 9 , -1069501632);
    c = md5_gg(c, d, a, b, x[i+11], 14,  643717713);
    b = md5_gg(b, c, d, a, x[i+ 0], 20, -373897302);
    a = md5_gg(a, b, c, d, x[i+ 5], 5 , -701558691);
    d = md5_gg(d, a, b, c, x[i+10], 9 ,  38016083);
    c = md5_gg(c, d, a, b, x[i+15], 14, -660478335);
    b = md5_gg(b, c, d, a, x[i+ 4], 20, -405537848);
    a = md5_gg(a, b, c, d, x[i+ 9], 5 ,  568446438);
    d = md5_gg(d, a, b, c, x[i+14], 9 , -1019803690);
    c = md5_gg(c, d, a, b, x[i+ 3], 14, -187363961);
    b = md5_gg(b, c, d, a, x[i+ 8], 20,  1163531501);
    a = md5_gg(a, b, c, d, x[i+13], 5 , -1444681467);
    d = md5_gg(d, a, b, c, x[i+ 2], 9 , -51403784);
    c = md5_gg(c, d, a, b, x[i+ 7], 14,  1735328473);
    b = md5_gg(b, c, d, a, x[i+12], 20, -1926607734);

    a = md5_hh(a, b, c, d, x[i+ 5], 4 , -378558);
    d = md5_hh(d, a, b, c, x[i+ 8], 11, -2022574463);
    c = md5_hh(c, d, a, b, x[i+11], 16,  1839030562);
    b = md5_hh(b, c, d, a, x[i+14], 23, -35309556);
    a = md5_hh(a, b, c, d, x[i+ 1], 4 , -1530992060);
    d = md5_hh(d, a, b, c, x[i+ 4], 11,  1272893353);
    c = md5_hh(c, d, a, b, x[i+ 7], 16, -155497632);
    b = md5_hh(b, c, d, a, x[i+10], 23, -1094730640);
    a = md5_hh(a, b, c, d, x[i+13], 4 ,  681279174);
    d = md5_hh(d, a, b, c, x[i+ 0], 11, -358537222);
    c = md5_hh(c, d, a, b, x[i+ 3], 16, -722521979);
    b = md5_hh(b, c, d, a, x[i+ 6], 23,  76029189);
    a = md5_hh(a, b, c, d, x[i+ 9], 4 , -640364487);
    d = md5_hh(d, a, b, c, x[i+12], 11, -421815835);
    c = md5_hh(c, d, a, b, x[i+15], 16,  530742520);
    b = md5_hh(b, c, d, a, x[i+ 2], 23, -995338651);

    a = md5_ii(a, b, c, d, x[i+ 0], 6 , -198630844);
    d = md5_ii(d, a, b, c, x[i+ 7], 10,  1126891415);
    c = md5_ii(c, d, a, b, x[i+14], 15, -1416354905);
    b = md5_ii(b, c, d, a, x[i+ 5], 21, -57434055);
    a = md5_ii(a, b, c, d, x[i+12], 6 ,  1700485571);
    d = md5_ii(d, a, b, c, x[i+ 3], 10, -1894986606);
    c = md5_ii(c, d, a, b, x[i+10], 15, -1051523);
    b = md5_ii(b, c, d, a, x[i+ 1], 21, -2054922799);
    a = md5_ii(a, b, c, d, x[i+ 8], 6 ,  1873313359);
    d = md5_ii(d, a, b, c, x[i+15], 10, -30611744);
    c = md5_ii(c, d, a, b, x[i+ 6], 15, -1560198380);
    b = md5_ii(b, c, d, a, x[i+13], 21,  1309151649);
    a = md5_ii(a, b, c, d, x[i+ 4], 6 , -145523070);
    d = md5_ii(d, a, b, c, x[i+11], 10, -1120210379);
    c = md5_ii(c, d, a, b, x[i+ 2], 15,  718787259);
    b = md5_ii(b, c, d, a, x[i+ 9], 21, -343485551);

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);
  }
  return Array(a, b, c, d);

}

/*
 * These functions implement the four basic operations the algorithm uses.
 */
function md5_cmn(q, a, b, x, s, t)
{
  return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s),b);
}
function md5_ff(a, b, c, d, x, s, t)
{
  return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
}
function md5_gg(a, b, c, d, x, s, t)
{
  return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
}
function md5_hh(a, b, c, d, x, s, t)
{
  return md5_cmn(b ^ c ^ d, a, b, x, s, t);
}
function md5_ii(a, b, c, d, x, s, t)
{
  return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
}

/*
 * Calculate the HMAC-MD5, of a key and some data
 */
function core_hmac_md5(key, data)
{
  var bkey = str2binl(key);
  if(bkey.length > 16) bkey = core_md5(bkey, key.length * chrsz);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = core_md5(ipad.concat(str2binl(data)), 512 + data.length * chrsz);
  return core_md5(opad.concat(hash), 512 + 128);
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function bit_rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

/*
 * Convert a string to an array of little-endian words
 * If chrsz is ASCII, characters >255 have their hi-byte silently ignored.
 */
function str2binl(str)
{
  var bin = Array();
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < str.length * chrsz; i += chrsz)
    bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (i%32);
  return bin;
}

/*
 * Convert an array of little-endian words to a string
 */
function binl2str(bin)
{
  var str = "";
  var mask = (1 << chrsz) - 1;
  for(var i = 0; i < bin.length * 32; i += chrsz)
    str += String.fromCharCode((bin[i>>5] >>> (i % 32)) & mask);
  return str;
}

/*
 * Convert an array of little-endian words to a hex string.
 */
function binl2hex(binarray)
{
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i++)
  {
    str += hex_tab.charAt((binarray[i>>2] >> ((i%4)*8+4)) & 0xF) +
           hex_tab.charAt((binarray[i>>2] >> ((i%4)*8  )) & 0xF);
  }
  return str;
}

/*
 * Convert an array of little-endian words to a base-64 string
 */
function binl2b64(binarray)
{
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var str = "";
  for(var i = 0; i < binarray.length * 4; i += 3)
  {
    var triplet = (((binarray[i   >> 2] >> 8 * ( i   %4)) & 0xFF) << 16)
                | (((binarray[i+1 >> 2] >> 8 * ((i+1)%4)) & 0xFF) << 8 )
                |  ((binarray[i+2 >> 2] >> 8 * ((i+2)%4)) & 0xFF);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > binarray.length * 32) str += b64pad;
      else str += tab.charAt((triplet >> 6*(3-j)) & 0x3F);
    }
  }
  return str;
}

/**
 * UAFormat.js v0.0.2
 * https://github.com/jeeinn/ua-format-js
 *
 * Copyright ? 2016 Jeeinn
 * Licensed under GPLv2 & MIT
 * Created by xyw on 2017/3/8.
 */

;(function (window) {
    'use strict';
    // 定义常量
    var EMPTY = '', UNKNOWN = 'unknown', TYPE_UNDEF = 'undefined', NAME = 'name', VERSION = 'version',
        TYPE = 'type', MODEL = 'model', VENDOR = 'vendor',
        MOBILE = 'mobile', TABLET = 'tablet', SMARTTV = 'smarttv',
        WEARABLE = 'wearable', CONSOLE = 'console', DESKTOP = 'desktop', EMBEDDED = 'embedded';

    // 所有匹配规则, 注意：规则不能为空对象
    var uaRules = {
        osRules:[
            {// Windows based
                patterns:[/microsoft\s(windows)\s(vista|xp)/i],                         // Windows (iTunes)
                defaults:[[NAME],[VERSION]]
            }, {
                patterns:[
                    /(windows)\snt\s6\.2;\s(arm)/i,                                     // Windows RT
                    /(windows\sphone(?:\sos)*)[\s\/]?([\d\.\s]+\w)*/i,                  // Windows Phone
                    /(windows\smobile|windows)[\s\/]?([ntce\d\.\s]+\w)/i
                ],
                defaults:[[NAME],[VERSION]]
            }, {// Mobile/Embedded OS
                patterns:[/\((bb)(10);/i],                                              // BlackBerry 10
                defaults:[[NAME,'BlackBerry'],[VERSION]]
            }, {
                patterns:[
                    /(blackberry)\w*\/?([\w\.]+)*/i,                                    // Blackberry
                    /(tizen)[\/\s]([\w\.]+)/i,                                          // Tizen
                    /Linux;\s*(Android)\s*([\d.]+);\s*/,                                // Android Mobile
                    // Android/WebOS/Palm/QNX/Bada/RIM/MeeGo/Contiki
                    /(android|webos|palm\sos|qnx|bada|rim\stablet\sos|meego|contiki)[\/\s-]?([\w\.]+)*/i,
                    /linux;.+(sailfish);/i                                              // Sailfish OS
                ],
                defaults:[[NAME],[VERSION]]
            }, {
                patterns:[/(symbian\s?os|symbos|s60(?=;))[\/\s-]?([\w\.]+)*/i],         // Symbian
                defaults:[[NAME,'Symbian'],[VERSION]]
            }, {
                patterns:[/\((series40);/i],                                            // Series 40
                defaults:[[NAME]]
            }, {
                patterns:[/mozilla.+\(mobile;.+gecko.+firefox/i],                       // Firefox OS
                defaults:[[NAME,'Firefox OS'],[VERSION]]
            }, {
                patterns:[
                    // Console
                    /(nintendo|playstation)\s([wids34portablevu]+)/i,                   // Nintendo/Playstation
                    // GNU/Linux based
                    /(mint)[\/\s\(]?(\w+)*/i,                                           // Mint
                    /(mageia|vectorlinux)[;\s]/i,                                       // Mageia/VectorLinux
                    /(joli|[kxln]?ubuntu|debian|[open]*suse|gentoo|(?=\s)arch|slackware|fedora|mandriva|centos|pclinuxos|redhat|zenwalk|linpus)[\/\s-]?(?!chrom)([\w\.-]+)*/i,
                    // Joli/Ubuntu/Debian/SUSE/Gentoo/Arch/Slackware
                    // Fedora/Mandriva/CentOS/PCLinuxOS/RedHat/Zenwalk/Linpus
                    /(hurd|linux)\s?([\w\.]+)*/i,                                       // Hurd/Linux
                    /(gnu)\s?([\w\.]+)*/i                                               // GNU

                ],
                defaults:[[NAME],[VERSION]]
            }, {
                patterns:[/(cros)\s[\w]+\s([\w\.]+\w)/i],                               // Chromium OS
                defaults:[[NAME,'Chromium OS'],[VERSION]]
            }, {// Solaris
                patterns:[/(sunos)\s?([\w\.]+\d)*/i],                                   // Solaris
                defaults:[[NAME,'Solaris'],[VERSION]]
            }, {// BSD based
                patterns:[/\s([frentopc-]{0,4}bsd|dragonfly)\s?([\w\.]+)*/i],           // FreeBSD/NetBSD/OpenBSD/PC-BSD/DragonFly
                defaults:[[NAME],[VERSION]]
            }, {
                patterns:[/(haiku)\s(\w+)/i],                                           // Haiku
                defaults:[[NAME],[VERSION]]
            }, {
                patterns:[/(ip[honead]+)(?:.*os\s([\w]+)*\slike\smac|;\sopera)/i],      // iOS
                defaults:[[NAME,'iOS'],[VERSION]]
            }, {
                patterns:[
                    /(mac\sos\sx)\s?([\w\s\.]+\w)*/i,
                    /(macintosh|mac(?=_powerpc)\s)/i                                    // Mac OS
                ],
                defaults:[[NAME,'Mac OS'],[VERSION]]
            }, {// Other
                patterns:[
                    /((?:open)?solaris)[\/\s-]?([\w\.]+)*/i,                            // Solaris
                    /(aix)\s((\d)(?=\.|\)|\s)[\w\.]*)*/i,                               // AIX
                    /(plan\s9|minix|beos|os\/2|amigaos|morphos|risc\sos|openvms)/i,
                    // Plan9/Minix/BeOS/OS2/AmigaOS/MorphOS/RISCOS/OpenVMS
                    /(unix)\s?([\w\.]+)*/i                                              // UNIX
                ],
                defaults:[[NAME],[VERSION]]
            }
        ],
        browserRules:[
            {
                patterns:[
                    // Presto based
                    /(opera\smini)\/([\w\.-]+)/i,                                       // Opera Mini
                    /(opera\s[mobiletab]+).+version\/([\w\.-]+)/i,                      // Opera Mobi/Tablet
                    /(opera).+version\/([\w\.]+)/i,                                     // Opera > 9.80
                    /(opera)[\/\s]+([\w\.]+)/i                                          // Opera < 9.80
                ],
                defaults:[[NAME],[VERSION]]
            }, {
                patterns:[/(opios)[\/\s]+([\w\.]+)/i],                                  // Opera mini on iphone >= 8.0
                defaults:[[NAME,'Opera Mini'], [VERSION]]
            }, {
                patterns:[/\s(opr)\/([\w\.]+)/i],                                       // Opera Webkit
                defaults:[[NAME, 'Opera'], [VERSION]]
            }, {                                                                        // baiduboxapp 苹果可能不准确
                patterns:[
                    /baiduboxapp\/(.+)\s\(baidu;/i,
                    /baiduboxapp\/(.+)_enohpi/i
                ],
                defaults:[[VERSION],[NAME,'Baidu']]
            }, {                                                                        // Mixed
                patterns:[
                    /(kindle)\/([\w\.]+)/i,                                             // Kindle
                    /(lunascape|maxthon|netfront|jasmine|blazer)[\/\s]?([\w\.]+)*/i,    // Lunascape/Maxthon/Netfront/Jasmine/Blazer
                    // Trident based
                    /(avant\s|iemobile|slim|baidu)(?:browser)?[\/\s]?([\w\.]*)/i,       // Avant/IEMobile/SlimBrowser/Baidu
                    /(?:ms|\()(ie)\s([\w\.]+)/i,                                        // Internet Explorer
                    // Webkit/KHTML based
                    /(rekonq)\/([\w\.]+)*/i,                                            // Rekonq
                    /(chromium|flock|rockmelt|midori|epiphany|silk|skyfire|ovibrowser|bolt|iron|vivaldi|iridium|phantomjs)\/([\w\.-]+)/i
                    // Chromium/Flock/RockMelt/Midori/Epiphany/Silk/Skyfire/Bolt/Iron/Iridium/PhantomJS
                ],
                defaults:[[NAME], [VERSION]]
            }, {
                patterns:[/(trident).+rv[:\s]([\w\.]+).+like\sgecko/i],                 // IE11
                defaults:[[NAME, 'IE'], [VERSION]]
            }, {
                patterns:[/(edge)\/((\d+)?[\w\.]+)/i],                                  // Microsoft Edge
                defaults:[[NAME], [VERSION]]
            }, {
                patterns:[/(yabrowser)\/([\w\.]+)/i],                                   // Yandex
                defaults:[[NAME, 'Yandex'], [VERSION]]
            }, {
                patterns:[/(comodo_dragon)\/([\w\.]+)/i],                               // Comodo Dragon 或许有误差
                defaults:[[NAME, 'Comodo Dragon'], [VERSION]]
            }, {
                patterns:[/xiaomi\/miuibrowser\/([\w\.]+)/i],                           // MIUI Browser
                defaults:[[VERSION],[NAME, 'MIUI Browser']]
            }, {
                patterns:[/(micromessenger)\/([\w\.]+)/i],                              // WeChat
                defaults:[[NAME, 'WeChat'], [VERSION]]
            }, {
                patterns:[
                    /(qqbrowser)[\/\s]?([\w\.]+)/i ,                                    // QQBrowser
                    /(chrome|omniweb|arora|[tizenoka]{5}\s?browser)\/v?([\w\.]+)/i      // Chrome/OmniWeb/Arora/Tizen/Nokia
                ],
                defaults:[[NAME], [VERSION]]
            }, {                                                                         // UCBrowser
                patterns:[
                    /(uc\s?browser)[\/\s]?([\w\.]+)/i,
                    /ucweb.+(ucbrowser)[\/\s]?([\w\.]+)/i,
                    /juc.+(ucweb)[\/\s]?([\w\.]+)/i
                ],
                defaults:[[NAME, 'UCBrowser'], [VERSION]]
            }, {                                                                         // Dolphin
                patterns:[/(dolfin)\/([\w\.]+)/i],
                defaults:[[NAME, 'Dolphin'], [VERSION]]
            }, {
                patterns:[/((?:android.+)crmo|crios)\/([\w\.]+)/i],                     // Chrome for Android/iOS
                defaults:[[NAME, 'Chrome'], [VERSION]]
            }, {
                patterns:[/;fbav\/([\w\.]+);/i],                                        // Facebook App for iOS 虽然国内没什么人上
                defaults:[[VERSION], [NAME, 'Facebook']]
            }, {
                patterns:[/fxios\/([\w\.-]+)/i],                                        // Firefox for iOS
                defaults:[[VERSION], [NAME, 'Firefox iOS']]
            }, {
                patterns:[/version\/([\w\.]+).+?mobile\/\w+\s(safari)/i],               // Mobile Safari
                defaults:[[VERSION],[NAME, 'Mobile Safari']]
            }, {
                patterns:[/version\/([\w\.]+).+?(mobile\s?safari|safari)/i],            // Safari & Safari Mobile
                defaults:[[VERSION],[NAME]]
            }, {
                patterns:[/webkit.+?(mobile\s?safari|safari)(\/[\w\.]+)/i],             // Safari < 3.0 几乎没用
                defaults:[[NAME], [VERSION]]
            }, {
                patterns:[
                    /(konqueror)\/([\w\.]+)/i,                                          // Konqueror
                    /(webkit|khtml)\/([\w\.]+)/i
                ],
                defaults:[[NAME], [VERSION]]
            }, {
                // Gecko based
                patterns:[/(navigator|netscape)\/([\w\.-]+)/i],                         // Netscape
                defaults:[[NAME, 'Netscape'], [VERSION]]
            }, {
                patterns:[
                    /(swiftfox)/i,                                                      // Swiftfox
                    /(icedragon|iceweasel|camino|chimera|fennec|maemo\sbrowser|minimo|conkeror)[\/\s]?([\w\.\+]+)/i,
                    // IceDragon/Iceweasel/Camino/Chimera/Fennec/Maemo/Minimo/Conkeror
                    /(firefox|seamonkey|k-meleon|icecat|iceape|firebird|phoenix)\/([\w\.-]+)/i,
                    // Firefox/SeaMonkey/K-Meleon/IceCat/IceApe/Firebird/Phoenix
                    /(mozilla)\/([\w\.]+).+rv\:.+gecko\/\d+/i,                          // Mozilla

                    // Other
                    /(polaris|lynx|dillo|icab|doris|amaya|w3m|netsurf|sleipnir)[\/\s]?([\w\.]+)/i,
                    // Polaris/Lynx/Dillo/iCab/Doris/Amaya/w3m/NetSurf/Sleipnir
                    /(links)\s\(([\w\.]+)/i,                                            // Links
                    /(gobrowser)\/?([\w\.]+)*/i,                                        // GoBrowser
                    /(ice\s?browser)\/v?([\w\._]+)/i,                                   // ICE Browser
                    /(mosaic)[\/\s]([\w\.]+)/i
                ],
                defaults:[[NAME], [VERSION]]
            }, {                                                                         // Android Browser
                patterns:[
                    /android.+samsungbrowser\/([\w\.]+)/i,
                    /android.+version\/([\w\.]+)\s+(?:mobile\s?safari|safari)*/i
                ],
                defaults:[[VERSION], [NAME, 'Android Browser']]
            }, {
                patterns:[/\swv\).+(chrome)\/([\w\.]+)/i],                              // Chrome WebView
                defaults:[[NAME, 'Chrome WebView'], [VERSION]]
            }
        ],
        deviceRules:[
            {                                                                           // ZUK mobile
                patterns:[/android.+;\s(zuk.+)\sbuild\/\w.+mobile/i],
                defaults:[[MODEL], [VENDOR,'Lenovo'], [TYPE, MOBILE]]
            }, {                                                                        // Smartisan mobile
                patterns:[
                    /android.+;\s(sm\d+)\sbuild\/\w.+mobile/i,
                    /android.+;\s(yq\d+)\sbuild\/\w.+mobile/i
                ],
                defaults:[[MODEL], [VENDOR,'Smartisan'], [TYPE, MOBILE]]
            }, {                                                                        // MeiZu mobile
                patterns:[/android.+;\s(m1+|m2+|m3+|m5+|m040+|mx4+|mx5+|mx6+)\sbuild\/\w.+mobile/i],
                defaults:[[MODEL], [VENDOR,'Meizu'], [TYPE, MOBILE]]
            }, {                                                                        // le mobile
                patterns:[/android.+;\s(le.+)\sbuild\/\w.+mobile/i],
                defaults:[[MODEL], [VENDOR,'LeMobile'], [TYPE, MOBILE]]
            }, {                                                                        // vivo mobile
                patterns:[/android.+;\s((vivo).+)\sbuild\/\w.+mobile/i],
                defaults:[[MODEL], [VENDOR], [TYPE, MOBILE]]
            }, {                                                                        // OPPO mobile
                patterns:[/android.+;\s((oppo).+)\sbuild\/\w.+mobile/i],
                defaults:[[MODEL], [VENDOR], [TYPE, MOBILE]]
            }, {                                                                        // GiONEE mobile
                patterns:[/android.+;\s(gn.+)\sbuild\/\w.+mobile/i],
                defaults:[[MODEL], [VENDOR,'GiONEE'], [TYPE, MOBILE]]
            }, {                                                                        // nubia mobile
                patterns:[/android.+;\s(nx.+)\sbuild\/\w.+mobile/i],
                defaults:[[MODEL], [VENDOR,'nubia'], [TYPE, MOBILE]]
            }, {                                                                        // Xiaomi mobile
                patterns:[
                    /android.+;\s(mi\s.+)\sbuild\/\w.+mobile/i,
                    /android.+;\s(redmi\s.+)\sbuild\/\w.+mobile/i
                ],
                defaults:[[MODEL], [VENDOR,'Xiaomi'], [TYPE, MOBILE]]
            }, {                                                                        // iPad/PlayBook
                patterns:[/\((ipad|playbook);[\w\s\);-]+(rim|apple)/i],
                defaults:[[MODEL], [VENDOR], [TYPE, TABLET]]
            }, {                                                                        // iPad
                patterns:[/applecoremedia\/[\w\.]+ \((ipad)/],
                defaults:[[MODEL], [VENDOR, 'Apple'], [TYPE, TABLET]]
            }, {                                                                        // Apple TV
                patterns:[/(apple\s{0,1}tv)/i],
                defaults:[[MODEL, 'Apple TV'], [VENDOR, 'Apple'], [TYPE, SMARTTV]]
            }, {
                patterns:[
                    /(archos)\s(gamepad2?)/i,                                           // Archos
                    /(hp).+(touchpad)/i,                                                // HP TouchPad
                    /(hp).+(tablet)/i,                                                  // HP Tablet
                    /(kindle)\/([\w\.]+)/i,                                             // Kindle
                    /\s(nook)[\w\s]+build\/(\w+)/i,                                     // Nook
                    /(dell)\s(strea[kpr\s\d]*[\dko])/i                                  // Dell Streak
                ],
                defaults:[[VENDOR], [MODEL], [TYPE, TABLET]]
            }, {                                                                        // Kindle Fire HD
                patterns:[/(kf[A-z]+)\sbuild\/[\w\.]+.*silk\//i],
                defaults:[[MODEL], [VENDOR, 'Amazon'], [TYPE, TABLET]]
            }, {                                                                        // Fire Phone
                patterns:[/(sd|kf)[0349hijorstuw]+\sbuild\/[\w\.]+.*silk\//i],
                defaults:[[MODEL], [VENDOR, 'Amazon'], [TYPE, MOBILE]]
            }, {                                                                        // iPod/iPhone
                patterns:[/\((ip[honed|\s\w*]+);.+(apple)/i],
                defaults:[[MODEL], [VENDOR], [TYPE, MOBILE]]
            }, {                                                                        // iPad/PlayBook
                patterns:[/\((ipad|playbook);[\w\s\);-]+(rim|apple)/i],
                defaults:[[MODEL], [VENDOR], [TYPE, TABLET]]
            }, {                                                                        // iPod/iPhone
                patterns:[/\((ip[honed|\s\w*]+);/i],
                defaults:[[MODEL], [VENDOR, 'Apple'], [TYPE, MOBILE]]
            }, {                                                                        // BlackBerry 10
                patterns:[/\(bb10;\s(\w+)/i],
                defaults:[[MODEL], [VENDOR, 'BlackBerry'], [TYPE, MOBILE]]
            }, {                                                                        // Asus Tablets
                patterns:[/android.+(transfo[prime\s]{4,10}\s\w+|eeepc|slider\s\w+|nexus 7|padfone)/i],
                defaults:[[MODEL], [VENDOR, 'Asus'], [TYPE, TABLET]]
            }, {                                                                        // Sony
                patterns:[
                    /(sony)\s(tablet\s[ps])\sbuild\//i,
                    /(sony)?(?:sgp.+)\sbuild\//i
                ],
                defaults:[[VENDOR, 'Sony'], [MODEL, 'Xperia Tablet'], [TYPE, TABLET]]
            }, {
                patterns:[/(?:sony)?(?:(?:(?:c|d)\d{4})|(?:so[-l].+))\sbuild\//i],
                defaults:[[VENDOR, 'Sony'], [MODEL, 'Xperia Phone'], [TYPE, MOBILE]]
            }, {
                patterns:[
                    /\s(ouya)\s/i,                                                      // Ouya
                    /(nintendo)\s([wids3u]+)/i                                          // Nintendo
                ],
                defaults:[[VENDOR], [MODEL], [TYPE, CONSOLE]]
            }, {                                                                        // Nvidia
                patterns:[/android.+;\s(shield)\sbuild/i],
                defaults:[[MODEL], [VENDOR, 'Nvidia'], [TYPE, CONSOLE]]
            }, {                                                                        // Playstation
                patterns:[/(playstation\s[34portablevi]+)/i],
                defaults:[[MODEL], [VENDOR, 'Sony'], [TYPE, CONSOLE]]
            }, {                                                                        // Lenovo tablets
                patterns:[/(lenovo)\s?(S(?:5000|6000)+(?:[-][\w+]))/i],
                defaults:[[VENDOR], [MODEL], [TYPE, TABLET]]
            }, {
                patterns:[
                    /(sprint\s(\w+))/i,                                                 // Sprint Phones
                    /(htc)[;_\s-]+([\w\s]+(?=\))|\w+)*/i,                               // HTC
                    /(zte)-(\w+)*/i,                                                    // ZTE
                    /android.+;\s((zte).+)build\/\w+/i,
                    /(microsoft);\s(lumia[\s\w]+)/i,                                    // Microsoft Lumia
                    // Alcatel/GeeksPhone/Huawei/Lenovo/Nexian/Panasonic/Sony
                    /(alcatel|geeksphone|huawei|lenovo|nexian|panasonic|(?=;\s)sony)[_\s-]?([\w-]+)*/i,
                    /(blackberry)[\s-]?(\w+)/i,                                         // BlackBerry
                    // BenQ/Palm/Sony-Ericsson/Acer/Asus/Dell/Huawei/Meizu/Motorola/Polytron
                    /(blackberry|benq|palm(?=\-)|sonyericsson|acer|asus|dell|huawei|meizu|motorola|polytron)[\s_-]?([\w-]+)*/i,
                    /(hp)\s([\w\s]+\w)/i,                                               // HP iPAQ
                    /(asus)-?(\w+)/i,                                                   // Asus
                    /linux;.+((jolla));/i                                               // Jolla
                ],
                defaults:[[VENDOR], [MODEL], [TYPE, MOBILE]]
            }, {                                                                        // HTC Nexus 9
                patterns:[/(nexus\s9)/i],
                defaults:[[MODEL], [VENDOR, 'HTC'], [TYPE, TABLET]]
            }, {                                                                        // Huawei Nexus 6P
                patterns:[/(nexus\s6p)/i],
                defaults:[[MODEL], [VENDOR, 'Huawei'], [TYPE, MOBILE]]
            }, {                                                                        // Microsoft Xbox
                patterns:[/[\s\(;](xbox(?:\sone)?)[\s\);]/i],
                defaults:[[MODEL], [VENDOR, 'Microsoft'], [TYPE, CONSOLE]]
            }, {
                patterns:[/(kin\.[onetw]{3})/i],                                        // Microsoft Kin
                defaults:[[MODEL], [VENDOR, 'Microsoft'], [TYPE, MOBILE]]
            }, {                                                                        // Motorola
                patterns:[
                    /\s(milestone|droid(?:[2-4x]|\s(?:bionic|x2|pro|razr))?(:?\s4g)?)[\w\s]+build\//i,
                    /mot[\s-]?(\w+)*/i,
                    /(XT\d{3,4}) build\//i,
                    /(nexus\s6)/i
                ],
                defaults:[[MODEL], [VENDOR, 'Motorola'], [TYPE, MOBILE]]
            }, {
                patterns:[/android.+\s(mz60\d|xoom[\s2]{0,2})\sbuild\//i],
                defaults:[[MODEL], [VENDOR, 'Motorola'], [TYPE, TABLET]]
            }, {                                                                        // HbbTV devices
                patterns:[/hbbtv\/\d+\.\d+\.\d+\s+\([\w\s]*;\s*(\w[^;]*);([^;]*)/i],
                defaults:[[VENDOR], [MODEL], [TYPE, SMARTTV]]
            }, {                                                                        // 有误差
                patterns:[/hbbtv.+maple;(\d+)/i],
                defaults:[[MODEL, 'SmartTV'], [VENDOR, 'Samsung'], [TYPE, SMARTTV]]
            }, {                                                                        // Sharp
                patterns:[/\(dtv[\);].+(aquos)/i],
                defaults:[[MODEL], [VENDOR, 'Sharp'], [TYPE, SMARTTV]]
            }, {                                                                        // Samsung
                patterns:[
                    /android.+((sch-i[89]0\d|shw-m380s|gt-p\d{4}|gt-n\d+|sgh-t8[56]9|nexus 10))/i,
                    /((SM-T\w+))/i
                ],
                defaults:[[VENDOR, 'Samsung'], [MODEL], [TYPE, TABLET]]
            }, {
                patterns:[
                    /((s[cgp]h-\w+|gt-\w+|galaxy\snexus|sm-\w[\w\d]+))/i,
                    /(sam[sung]*)[\s-]*(\w+-?[\w-]*)*/i,
                    /sec-((sgh\w+))/i
                ],
                defaults:[[VENDOR, 'Samsung'], [MODEL], [TYPE, MOBILE]]
            }, {                                                                        // Siemens
                patterns:[/sie-(\w+)*/i],
                defaults:[[MODEL], [VENDOR, 'Siemens'], [TYPE, MOBILE]]
            }, {                                                                        // Nokia
                patterns:[
                    /(maemo|nokia).*(n900|lumia\s\d+)/i,
                    /(nokia)[\s_-]?([\w-]+)*/i
                ],
                defaults:[[VENDOR, 'Nokia'], [MODEL], [TYPE, MOBILE]]
            }, {                                                                        // Acer
                patterns:[/android\s3\.[\s\w;-]{10}(a\d{3})/i],
                defaults:[[MODEL], [VENDOR, 'Acer'], [TYPE, TABLET]]
            }, {                                                                        // LG Tablet
                patterns:[/android\s3\.[\s\w;-]{10}(lg?)-([06cv9]{3,4})/i],
                defaults:[[VENDOR, 'LG'], [MODEL], [TYPE, TABLET]]
            }, {                                                                        // LG SmartTV
                patterns:[/(lg) netcast\.tv/i],
                defaults:[[VENDOR], [MODEL], [TYPE, SMARTTV]]
            }, {                                                                        // LG
                patterns:[
                    /(nexus\s[45])/i,
                    /lg[e;\s\/-]+(\w+)*/i
                ],
                defaults:[[MODEL], [VENDOR, 'LG'], [TYPE, MOBILE]]
            }, {                                                                        // Lenovo
                patterns:[/android.+(ideatab[a-z0-9\-\s]+)/i],
                defaults:[[MODEL], [VENDOR, 'Lenovo'], [TYPE, TABLET]]
            }, {                                                                        // Pebble
                patterns:[/((pebble))app\/[\d\.]+\s/i],
                defaults:[[VENDOR], [MODEL], [TYPE, WEARABLE]]
            }, {                                                                        // Google Glass
                patterns:[/android.+;\s(glass)\s\d/i],
                defaults:[[MODEL], [VENDOR, 'Google'], [TYPE, WEARABLE]]
            }, {                                                                        // Google Pixel C
                patterns:[/android.+;\s(pixel c)\s/i],
                defaults:[[MODEL], [VENDOR, 'Google'], [TYPE, TABLET]]
            }, {                                                                        // Google Pixel
                patterns:[/android.+;\s(pixel xl|pixel)\s/i],
                defaults:[[MODEL], [VENDOR, 'Google'], [TYPE, MOBILE]]
            }, {
                patterns:[
                    /android.+(\w+)\s+build\/hm\1/i,                                    // Xiaomi Hongmi 'numeric' models
                    /android.+(hm[\s\-_]*note?[\s_]*(?:\d\w)?)\s+build/i,               // Xiaomi Hongmi
                    // Xiaomi Mi
                    /android.+(mi[\s\-_]*(?:one|one[\s_]plus|note lte)?[\s_]*(?:\d\w)?)\s+build/i
                ],
                defaults:[[MODEL], [VENDOR, 'Xiaomi'], [TYPE, MOBILE]]
            }, {                                                                        // OnePlus
                patterns:[
                    /android.+a000(1)\s+build/i,
                    /android.+;\s(one.+)\sbuild\/\w.+mobile/i
                ],
                defaults:[[MODEL], [VENDOR, 'OnePlus'], [TYPE, MOBILE]]
            }, {
                patterns:[
                    /\s(tablet)[;\/]/i,                                                 // Unidentifiable Tablet
                    /\s(mobile)(?:[;\/]|\ssafari)/i                                     // Unidentifiable Mobile
                ],
                defaults:[[TYPE], [VENDOR, UNKNOWN], [MODEL, UNKNOWN]]
            }

        ],
        engineRules:[
            {                                                                           // EdgeHTML
                patterns:[/windows.+\sedge\/([\w\.]+)/i],
                defaults:[[VERSION], [NAME, 'EdgeHTML']]
            }, {
                patterns:[
                    /(presto)\/([\w\.]+)/i,                                             // Presto
                    /(webkit|trident|netfront|netsurf|amaya|lynx|w3m)\/([\w\.]+)/i,     // WebKit/Trident/NetFront/NetSurf/Amaya/Lynx/w3m
                    /(khtml|tasman|links)[\/\s]\(?([\w\.]+)/i,                          // KHTML/Tasman/Links
                    /(icab)[\/\s]([23]\.[\d\.]+)/i                                      // iCab
                ],
                defaults:[[NAME], [VERSION]]
            }, {                                                                        // Gecko
                patterns:[/rv\:([\w\.]+).*(gecko)/i],
                defaults:[[VERSION], [NAME]]
            }
        ]
    };
    // 核心工具
    var tools = {
        versionFix:function (obj) {
            obj.version =  obj.version.replace(/_/g,'.');
            return obj;
        },
        modelFix:function (obj) {
            obj.model = obj.model.replace(/[_.]/g,' ');
            return obj;
        },
        chResult:function (defaults, tmp) {
            var res = {};
            for (var i=0;i<defaults.length;i++){
                if(defaults[i].length==1){
                    res[defaults[i][0]] = tmp[i+1];
                }else{
                    res[defaults[i][0]] = defaults[i][1];
                }
            }
            return res;
        },
        filter:function (type,ua) {
            var i,j,rules, matched=false, result={};
            switch (type){
                case 'os':
                    rules = uaRules.osRules;
                    break;
                case 'browser':
                    rules = uaRules.browserRules;
                    break;
                case 'device':
                    rules = uaRules.deviceRules;
                    break;
                case 'engine':
                    rules = uaRules.engineRules;
            }
            //遍历rules
            for(i = 0; i < rules.length; i++){
                var patterns = rules[i].patterns;
                var defaults = rules[i].defaults;
                //遍历patterns
                for(j = 0; j < patterns.length; j++){
                    var tmp = patterns[j].exec(ua);
                    //处理结果与自定义
                    if(tmp !== null) {
                        matched = true;
                        result = this.chResult(defaults, tmp);
                        break;
                    }
                }
                if(matched) break;
            }
            //处理无结果情况
            if(!matched) {
                rules[0].defaults.forEach(function (value) {
                    result[value[0]] = UNKNOWN;
                });
            }
            // console.log(result);
            if(result.version !== undefined) this.versionFix(result);
            if(result.model !== undefined) this.modelFix(result);
            return result;
        },
        getOS:function (ua) {
            return this.filter('os',ua);
        },
        getBrowser:function (ua) {
            return this.filter('browser',ua);
        },
        getDevice:function (ua) {
            return this.filter('device',ua);
        },
        getEngine:function (ua) {
            return this.filter('engine',ua);
        }
    };

    var UAFormat = function (uaString) {
        var ua = uaString || ((window && window.navigator && window.navigator.userAgent) ? window.navigator.userAgent : EMPTY);
        this.setUA = function (uaString) {
            var uaSet = uaString || EMPTY;
            if(uaSet){
                ua = uaSet;
            }else{
                console.warn('setUA(): param is empty, use default ua');
            }
            return this;
        };
        this.getUA = function () {return ua;};
        this.getOS = function(){
            return tools.getOS(ua);
        };
        this.getBrowser = function(){
            return tools.getBrowser(ua);
        };
        this.getDevice = function(){
            return tools.getDevice(ua);
        };
        this.getEngine = function(){
            return tools.getEngine(ua);
        };
        this.getResult = function () {
            return {
                ua : this.getUA(),
                os : this.getOS(),
                browser : this.getBrowser(),
                device : this.getDevice(),
                engine : this.getEngine()
            };
        };
        return this;
    };

    // 判断js环境导出
    if (typeof(exports) !== TYPE_UNDEF) {
        // nodejs 环境
        if ((typeof module !== TYPE_UNDEF) && module.exports) {
            exports = module.exports = UAFormat;
        }
        exports.UAFormat = UAFormat;
    }else {
        // 浏览器环境
        window.UAFormat = UAFormat;
    }

})(typeof window === 'object' ? window : this);

function colorDepthKey(){
	return screen.colorDepth || -1
};
function pixelRatioKey(){
	return getPixelRatio()
};
function getPixelRatio(){
	return window.devicePixelRatio || ""
};
function screenResolutionKey(){
	return getScreenResolution()
};
function getScreenResolution(){
	var t="";
	return screen.height > screen.width ? [screen.height, screen.width] : [screen.width, screen.height]
};
function availableScreenResolutionKey(){
	return getAvailableScreenResolution()
};
function getAvailableScreenResolution(){
	var t="";
	return screen.availWidth && screen.availHeight && (t = 1 ? screen.availHeight > screen.availWidth ? [screen.availHeight, screen.availWidth] : [screen.availWidth, screen.availHeight] : [screen.availHeight, screen.availWidth]),t
};
function getfingerresult(){
	var ua1 = new UAFormat();
	//ua1.setUA("Mozilla/5.0 (Linux; Android 5.0.1; Nexus 6 Build/LRX22C) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/37.0.0.0 Mobile Safari/537.36");
	var result = ua1.getResult();
	var finger = result.device.model +';'+ result.device.type + ';' + result.device.vendor + ';' + result.os.name + ';' + result.os.version +';'+ colorDepthKey() +';'+ pixelRatioKey() +';'+ screenResolutionKey() +';'+ availableScreenResolutionKey();
	return finger;
};
function getfingermd5(){
	var ua1 = new UAFormat();
	//ua1.setUA("Mozilla/5.0 (Linux; Android 5.0.1; Nexus 6 Build/LRX22C) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/37.0.0.0 Mobile Safari/537.36");
	var result = ua1.getResult();
	var finger = result.device.model +';'+ result.device.type + ';' + result.device.vendor + ';' + result.os.name + ';' + result.os.version +';'+ colorDepthKey() +';'+ pixelRatioKey() +';'+ screenResolutionKey() +';'+ availableScreenResolutionKey();
	return hex_md5(finger);
};
