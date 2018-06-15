document.getElementById('decode').onclick = updatePage;

const NETWORK = new Map([
    ['lnbc', 'bitcoin mainnet'],
    ['lntb', 'bitcoin testnet'],
    ['lnbcrt', 'bitcoin regtest']
]);
const TAG_TYPES = new Map([
    ['p', 'Payment Hash'],
    ['d', 'Description'],
    ['n', 'Destination'],
    ['h', 'Description Hash'],
    ['x', 'Expiration Time'],
    ['c', 'Min Final CLTV Expiry'],
    ['f', 'Fallback On-Chain Address'],
    ['r', 'Routing Info']
]);
const KEY_DESCRIPTIONS = new Map([
    ['version', 'Version'],
    ['fallback_address', 'Fall Back Address'],
    ['public_key', 'Public Key'],
    ['short_channel_id', 'Short Channel Id'],
    ['fee_base_msat', 'Fee Base Msat'],
    ['fee_proportional_millionths', 'Fee Proportional Millimonths'],
    ['cltv_expiry_delta', 'CLTV Expiry Delta'],
    ['r', 'R value'],
    ['s', 'S value'],
    ['recovery_flag', 'Recovery Flag']
]);

function updatePage() {
    try {
        let paymentRequest = document.getElementById('request-string').value;
        let decodedRequest = decode(paymentRequest);
        let div = document.getElementById('response');
        div.innerHTML = '';
        div.appendChild(jsonToHtml(decodedRequest));
        div.classList.remove('hidden');
        div.classList.remove('alert-danger');
        div.classList.add('alert');
        div.classList.add('alert-success');
    } catch (e) {
        let div = document.getElementById('response');
        div.innerHTML = '<strong>Uh-Oh!</strong> Something is not quite right with this request.<br>' + e.toString();
        div.classList.remove('hidden');
        div.classList.remove('alert-success');
        div.classList.add('alert');
        div.classList.add('alert-danger');
    }
}

function createStandardRow() {
    let row = document.createElement('div');
    row.classList.add('row');
    row.classList.add('border-bottom');
    for (let i = 0; i < arguments.length; i++) {
        let col = document.createElement('div');
        if (i === 0) {
            col.classList.add('font-weight-bold');
            col.classList.add('col-sm-4');
        } else {
            col.classList.add('col-sm-8');
            col.classList.add('pl-4');
            col.classList.add('pl-sm-3');
        }
        col.innerHTML = escapeHtmlText(arguments[i]);
        row.appendChild(col);
    }
    return row;
}

function createMultiRow(data, title) {
    let section = document.createElement('div');

    let row = document.createElement('div');
    row.classList.add('row');
    row.classList.add('border-bottom');

    let col = document.createElement('div');
    col.classList.add('font-weight-bold');
    col.classList.add('col-sm-4');
    col.innerHTML = escapeHtmlText(title);
    row.appendChild(col);

    let col2 = document.createElement('div');
    col.classList.add('col-sm-8');
    row.appendChild(col2);
    section.appendChild(row);

    let keys = Object.keys(data);
    let values = Object.values(data);

    for (let i = 0; i < keys.length; i++) {
        let subRow = document.createElement('div');
        subRow.classList.add('row');
        subRow.classList.add('border-bottom');

        col = document.createElement('div');
        col.classList.add('font-italic');
        col.classList.add('col-sm-4');
        col.classList.add('pl-4');
        col.innerHTML = KEY_DESCRIPTIONS.get(keys[i]);
        subRow.appendChild(col);

        col = document.createElement('div');
        col.classList.add('col-sm-8');
        col.classList.add('pl-5');
        col.classList.add('pl-sm-3');
        col.innerHTML = escapeHtmlText(values[i]);
        subRow.appendChild(col);

        section.appendChild(subRow);
    }
    return section;
}

function hasTag(tags, type) {
    for (let i = 0; i < tags.length; i++) {
        let tagType = tags[i].type;
        if (tagType === type) {
            return true;
        }
    }
    return false;
}

function jsonToHtml(json) {
    let container = document.createElement('div');
    let pmtInfo = document.createElement('h4');
    pmtInfo.innerHTML = 'Payment Info:';
    container.appendChild(pmtInfo);

    let hrpDiv = document.createElement('div');
    hrpDiv.classList.add('mb-4');
    let row = createStandardRow('Network', NETWORK.get(json.human_readable_part.prefix));
    hrpDiv.appendChild(row);

    let amount = json.human_readable_part.amount / 100000000000;
    amount = Number.isNaN(amount) ? 'any payment amount' : amount;
    row = createStandardRow('Amount', amount + ' BTC');
    hrpDiv.appendChild(row);

    row = createStandardRow('Date', epochToDate(json.data.time_stamp));
    hrpDiv.appendChild(row);

    for (let i = 0; i < json.data.tags.length; i++) {
        let tag = json.data.tags[i];
        switch (tag.type) {
            case 'f':
            case 'r':
                row = createMultiRow(tag.value, TAG_TYPES.get('r'));
                hrpDiv.appendChild(row);
                break;
            case 'x':
                row = createStandardRow(TAG_TYPES.get(tag.type), tag.value + ' seconds');
                hrpDiv.appendChild(row);
                break;
            case 'p':
            case 'd':
            case 'n':
            case 'h':
            case 'c':
                row = createStandardRow(TAG_TYPES.get(tag.type), tag.value);
                hrpDiv.appendChild(row);
                break;
        }
    }

    if (!(hasTag(json.data.tags, 'x'))) {
        row = createStandardRow(TAG_TYPES.get('x'), 3600 + ' seconds');
        hrpDiv.appendChild(row);
    }

    if (!(hasTag(json.data.tags, 'c'))) {
        row = createStandardRow(TAG_TYPES.get('c'), 9);
        hrpDiv.appendChild(row);
    }

    row = createMultiRow(json.data.signature, 'Signature');
    hrpDiv.appendChild(row);

    row = createStandardRow('Signing Data', json.data.signing_data);
    hrpDiv.appendChild(row);

    row = createStandardRow('Checksum', json.checksum);
    hrpDiv.appendChild(row);

    container.appendChild(hrpDiv);

    let rawData = document.createElement('h4');
    rawData.innerHTML = 'Raw Data:';
    container.appendChild(rawData);

    let textarea = document.createElement('textarea');
    textarea.rows = JSON.stringify(json, null, 4).split(/\r\n|\r|\n/).length;
    textarea.disabled = true;
    textarea.classList.add('form-control');
    textarea.style.whiteSpace = 'pre';
    textarea.innerHTML = escapeHtmlText(JSON.stringify(json, null, 4));
    container.appendChild(textarea);
    return container;
}