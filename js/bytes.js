// Byte-level helpers.

function byteArrayToHexString(byteArray) {
    return Array.prototype.map.call(byteArray, function (byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('');
}

function textToHexString(text) {
    let hexString = '';
    for (let i = 0; i < text.length; i++) {
        hexString += text.charCodeAt(i).toString(16);
    }
    return hexString;
}
