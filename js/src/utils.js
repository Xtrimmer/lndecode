function byteArrayToInt(byteArray) {
    var value = 0;
    for (var i = 0; i < byteArray.length; ++i) {
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

function FiveBitArrayTo8BitArray(int5Array) {
    let buffer = 0;
    let byteArray = [];
    let count = 0;
    int5Array.forEach((value) => {
        buffer = (buffer << 5) | (value & 31);
        count = count + 5;
        while (count >= 8) {
            byteArray.push((buffer >> (count - 8)) & 255);
            count = count - 8;
        }
    });
    return byteArray;
}

function bech32ToUTF8String(str) {
    let int5Array = bech32ToFiveBitArray(str);
    let byteArray = FiveBitArrayTo8BitArray(int5Array);

    let utf8String = '';
    for (let i = 0; i < byteArray.length; i++) {
        utf8String += '%' + ('0' + byteArray[i].toString(16)).slice(-2);
    }
    return decodeURIComponent(utf8String);
}

function ByteArrayToHexString(byteArray) {
    return Array.prototype.map.call(byteArray, function (byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('');
}

function epochToDate(int) {
    let date = new Date(int * 1000);
    return date.toUTCString();
}

function minimizeAmount(amount, multiplier) {
    amount = convertToMilliSatoshi(amount, multiplier);
    return encode(amount);
}

function convertToMilliSatoshi(amount, multiplier) {
    let symbols = ['p', 'n', 'u', 'm'];
    let multipliers = [0.1, 100, 100000, 100000000];
    amount *= multipliers[symbols.indexOf(multiplier)];
    return amount;
}

function encode(amount) {
    let unit = getUnit(amount);
    switch (unit){
        case 'p': return amount * 10 + unit;
        case 'n': return (amount / 100) + unit;
        case 'u': return (amount / 100000) + unit;
        case 'm': return (amount / 100000000) + unit;
    }
}

function getUnit(amount) {
    switch (true) {
        case amount % 100 > 0: return 'p';
        case amount % 100000 > 0: return 'n';
        case amount % 100000000 > 0: return 'u';
        default: return 'm';
    }
}