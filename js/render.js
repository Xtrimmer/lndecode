// Walks a display model and builds the response DOM.

const textarea = document.getElementById('request-string');
textarea.addEventListener('input', updatePage);

function updatePage() {
    let div = document.getElementById('response');
    try {
        let request = document.getElementById('request-string').value.trim();
        let model = decodeRequest(request);
        div.textContent = '';
        div.appendChild(renderModel(model));
        div.classList.remove('hidden');
        div.classList.remove('alert-danger');
        div.classList.add('alert');
        div.classList.add('alert-success');
    } catch (e) {
        div.innerHTML = '<strong>Uh-Oh!</strong> Something is not quite right with this request.<br>' + e.toString();
        div.classList.remove('hidden');
        div.classList.remove('alert-success');
        div.classList.add('alert');
        div.classList.add('alert-danger');
    }
}

function createStandardRow(label, value) {
    let row = document.createElement('div');
    row.classList.add('row');
    row.classList.add('border-bottom');

    let labelCol = document.createElement('div');
    labelCol.classList.add('font-weight-bold');
    labelCol.classList.add('col-sm-4');
    labelCol.textContent = label;
    row.appendChild(labelCol);

    let valueCol = document.createElement('div');
    valueCol.classList.add('break-all');
    valueCol.classList.add('col-sm-8');
    valueCol.classList.add('pl-4');
    valueCol.classList.add('pl-sm-3');
    valueCol.textContent = value;
    row.appendChild(valueCol);

    return row;
}

function createMultiRow(label, subRows) {
    let section = document.createElement('div');

    let row = document.createElement('div');
    row.classList.add('row');
    row.classList.add('border-bottom');

    let labelCol = document.createElement('div');
    labelCol.classList.add('font-weight-bold');
    labelCol.classList.add('col-sm-4');
    labelCol.textContent = label;
    row.appendChild(labelCol);

    let spacer = document.createElement('div');
    spacer.classList.add('col-sm-8');
    row.appendChild(spacer);
    section.appendChild(row);

    for (const sub of subRows) {
        let subRow = document.createElement('div');
        subRow.classList.add('row');
        subRow.classList.add('border-bottom');

        let subLabel = document.createElement('div');
        subLabel.classList.add('font-italic');
        subLabel.classList.add('col-sm-4');
        subLabel.classList.add('pl-4');
        subLabel.textContent = sub.label;
        subRow.appendChild(subLabel);

        let subValue = document.createElement('div');
        subValue.classList.add('break-all');
        subValue.classList.add('col-sm-8');
        subValue.classList.add('pl-5');
        subValue.classList.add('pl-sm-3');
        subValue.textContent = sub.value;
        subRow.appendChild(subValue);

        section.appendChild(subRow);
    }
    return section;
}

// Renders BigInt as a string.
function jsonReplacer(key, value) {
    return typeof value === 'bigint' ? value.toString() : value;
}

function renderModel(model) {
    let container = document.createElement('div');

    for (const section of model.sections) {
        let heading = document.createElement('h4');
        heading.textContent = section.title;
        container.appendChild(heading);

        let body = document.createElement('div');
        body.classList.add('mb-4');
        for (const row of section.rows) {
            body.appendChild(row.sub === undefined
                ? createStandardRow(row.label, row.value)
                : createMultiRow(row.label, row.sub));
        }
        container.appendChild(body);
    }

    let rawHeading = document.createElement('h4');
    rawHeading.textContent = 'Raw Data:';
    container.appendChild(rawHeading);

    let raw = JSON.stringify(model.raw, jsonReplacer, 4);
    let rawBox = document.createElement('textarea');
    rawBox.rows = raw.split(/\r\n|\r|\n/).length;
    rawBox.disabled = true;
    rawBox.classList.add('form-control');
    rawBox.style.whiteSpace = 'pre';
    rawBox.textContent = raw;
    container.appendChild(rawBox);

    return container;
}

function getUrlVars() {
    var vars = {};
    var parts = window.location.href.replace(/[?&]+([^=&]+)=([^&]*)/gi, function (m, key, value) {
        vars[key] = value;
    });
    return vars;
}

function getUrlParam(parameter, defaultvalue) {
    var urlparameter = defaultvalue;
    if (window.location.href.indexOf(parameter) > -1) {
        urlparameter = getUrlVars()[parameter];
    }
    return urlparameter;
}

window.onload = function () {
    var invoice = getUrlParam('invoice', '');
    var textbox = document.getElementById('request-string');
    textbox.value = invoice;
    if (!isEmptyOrSpaces(invoice)) {
        updatePage();
    }
}
