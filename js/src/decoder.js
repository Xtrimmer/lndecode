const bech32CharValues = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function decode(str) {
    let input = str.toLowerCase();
    let splitPosition = input.lastIndexOf('1');
    let humanReadablePart = input.substring(0, splitPosition);
    let data = input.substring(splitPosition + 1, input.length);
    let checksum = data.substring(data.length - 6, data.length);
    data = data.substring(0, data.length - 6);
    //TODO - if (!verify_checksum(humanReadablePart, data)) throw 'Malformed request: checksum invalid';
    return {
        "humanReadablePart": decodeHumanReadablePart(humanReadablePart),
        "data": decodeData(data),
        "checksum": checksum
    }
}

function decodeHumanReadablePart(str) {
    let prefixes = ["lnbc", "lntb", "lnbcrt"];
    let prefix;
    prefixes.forEach(value => {
        if (str.substring(0, value.length) === value) {
            prefix = value;
        }
    });
    if (prefix == null) throw 'Malformed request: undefined prefix';
    let amount = decodeAmount(str.substring(prefix.length, str.length));
    return {
        "prefix": prefix,
        "amount": amount
    }
}

function decodeData(str) {
    let date32 = str.substring(0, 7);
    let dateEpoch = bech32ToInt(date32);
    let date = epochToDate(dateEpoch);
    let signature = str.substring(str.length - 104, str.length);
    let tagData = str.substring(7, str.length - 104);
    let decodedTags = decodeTags(tagData);
    return {
        "timeStamp": date,
        "tags": decodedTags,
        "signature": signature
    }
}

function decodeAmount(str) {
    let multiplier = str.charAt(str.length - 1);
    let amount = str.substring(0, str.length - 1);
    if (amount.substring(0, 1) === '0') throw 'Malformed request: amount cannot contain leading zeros';
    amount = Number(amount);
    if (amount < 0 || !Number.isInteger(amount)) throw 'Malformed request: amount must be a positive decimal integer';

    switch (multiplier) {
        case '':
            return 'Any amount accepted';
        case 'p':
            return amount / 10;
        case 'n':
            return amount * 100;
        case 'u':
            return amount * 100000;
        case 'm':
            return amount * 100000000;
        default:
            throw 'Malformed request: undefined amount multiplier';
    }
}

function decodeTags(tagData) {
    let tags = extractTags(tagData);
    let decodedTags = [];
    tags.forEach((value) => {
        decodedTags.push(decodeTag(value.type, value.data));
    });
    return decodedTags;
}

function extractTags(str) {
    let tags = [];
    while (str.length > 0) {
        let type = str.charAt(0);
        let dataLength = bech32ToInt(str.substring(1, 3));
        let data = str.substring(3, dataLength + 3);
        tags.push({"type": type, "length": dataLength, "data": data});
        str = str.substring(3 + dataLength, str.length);
    }
    return tags;
}

function decodeTag(type, data) {
    switch (type) {
        case 'p':
            return {"paymentHash": ByteArrayToHexString(FiveBitArrayTo8BitArray(bech32ToFiveBitArray(data)))};
        case 'd':
            return {"description": bech32ToUTF8String(data)};
        case 'n':
            return {"payeePublicKey": ByteArrayToHexString(FiveBitArrayTo8BitArray(bech32ToFiveBitArray(data)))};
        case 'h':
            return {"descriptionHash": data};
        case 'x':
            return {"expiry": bech32ToInt(data)};
        case 'c':
            return {"minFinalCltvExpiry": bech32ToInt(data)};
        case 'f':
            let version = bech32ToFiveBitArray(data.charAt(0))[0];
            data = data.substring(1, data.length);
            return {
                "version": version,
                "fallbackAddress": data //TODO this needs to be decoded into an address
            };
        case 'r':
            data = FiveBitArrayTo8BitArray(bech32ToFiveBitArray(data));
            let pubkey = data.slice(0, 33);
            let shortChannelId = data.slice(33, 41);
            let feeBaseMsat = data.slice(41, 45);
            let feeProportionalMillionths = data.slice(45, 49);
            let cltvExpiryDelta = data.slice(49, 51);
            return {
                "pubkey": ByteArrayToHexString(pubkey),
                "shortChannelId": ByteArrayToHexString(shortChannelId),
                "feeBaseMsat": byteArrayToInt(feeBaseMsat),
                "feeProportionalMillionths": byteArrayToInt(feeProportionalMillionths),
                "cltvExpiryDelta": byteArrayToInt(cltvExpiryDelta)
            }
    }
}