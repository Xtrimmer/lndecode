const bech32CharValues = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function byteArrayToInt(byteArray) {
    let value = 0;
    for (let i = 0; i < byteArray.length; ++i) {
        value = (value << 8) + byteArray[i];
    }
    return value;
}

function bech32ToInt(str) {
    let sum = 0;
    for (let i = 0; i < str.length; i++) {
        sum = sum * 32;
        sum = sum + bech32CharValues.indexOf(str.charAt(i));
    }
    return sum;
}

function bech32ToFiveBitArray(str) {
    let array = [];
    for (let i = 0; i < str.length; i++) {
        array.push(bech32CharValues.indexOf(str.charAt(i)));
    }
    return array;
}

function fiveBitArrayTo8BitArray(int5Array, includeOverflow) {
    let count = 0;
    let buffer = 0;
    let byteArray = [];
    int5Array.forEach((value) => {
        buffer = (buffer << 5) + value;
        count += 5;
        if (count >= 8) {
            byteArray.push(buffer >> (count - 8) & 255);
            count -= 8;
        }
    });
    if (includeOverflow && count > 0) {
        byteArray.push(buffer << (8 - count) & 255);
    }
    return byteArray;
}

function bech32ToUTF8String(str) {
    let int5Array = bech32ToFiveBitArray(str);
    let byteArray = fiveBitArrayTo8BitArray(int5Array);

    let utf8String = '';
    for (let i = 0; i < byteArray.length; i++) {
        utf8String += '%' + ('0' + byteArray[i].toString(16)).slice(-2);
    }
    return decodeURIComponent(utf8String);
}

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

function epochToDate(int) {
    let date = new Date(int * 1000);
    return date.toUTCString();
}

function escapeHtmlText(text){
    if (typeof text === "string") {
        text = text.split('&').join('&amp;');
        text = text.split('<').join('&lt;');
        text = text.split('>').join('&gt;');
        text = text.split('"').join('&quot;');
        text = text.split("'").join('&#x27;');
        text = text.split('/').join('&#x2F;');
    }
    return text;
}