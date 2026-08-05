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
        div.classList.remove('alert');
        div.classList.remove('alert-danger');
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

// A card with a shaded header, so each section reads as its own block.
function createCard(title) {
    let card = document.createElement('div');
    card.classList.add('card');
    card.classList.add('mb-3');

    let header = document.createElement('div');
    header.classList.add('card-header');
    header.classList.add('font-weight-bold');
    header.textContent = title;
    card.appendChild(header);

    let body = document.createElement('div');
    body.classList.add('card-body');
    card.appendChild(body);

    return { section: card, body: body };
}

// A green panel with the heading inside it.
function createHighlight(title) {
    let panel = document.createElement('div');
    panel.classList.add('alert');
    panel.classList.add('alert-success');
    panel.classList.add('mb-3');

    let heading = document.createElement('h4');
    heading.textContent = title;
    panel.appendChild(heading);

    return { section: panel, body: panel };
}

function renderModel(model) {
    let container = document.createElement('div');

    for (const section of model.sections) {
        let rendered = section.emphasis ? createHighlight(section.title) : createCard(section.title);
        for (const row of section.rows) {
            rendered.body.appendChild(row.sub === undefined
                ? createStandardRow(row.label, row.value)
                : createMultiRow(row.label, row.sub));
        }
        container.appendChild(rendered.section);
    }

    let jsonCard = createCard(model.jsonTitle);
    let raw = JSON.stringify(model.raw, jsonReplacer, 4);
    let rawBox = document.createElement('textarea');
    rawBox.rows = raw.split(/\r\n|\r|\n/).length;
    rawBox.disabled = true;
    rawBox.classList.add('form-control');
    rawBox.style.whiteSpace = 'pre';
    rawBox.textContent = raw;
    jsonCard.body.appendChild(rawBox);
    container.appendChild(jsonCard.section);

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
