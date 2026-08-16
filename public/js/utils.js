// Presentation helpers.

function epochToDate(int) {
    const date = new Date(int * 1000);
    return date.toUTCString();
}

function isEmptyOrSpaces(str) {
    return str === null || str.match(/^ *$/) !== null;
}

// Expands a number out of exponential notation.
function toFixed(x) {
    if (Math.abs(x) < 1.0) {
        const e = parseInt(x.toString().split('e-')[1]);
        if (e) {
            x *= 10 ** (e - 1);
            x = `0.${'0'.repeat(e - 1)}${x.toString().substring(2)}`;
        }
    } else {
        let e = parseInt(x.toString().split('+')[1]);
        if (e > 20) {
            e -= 20;
            x /= 10 ** e;
            x += '0'.repeat(e);
        }
    }
    return x;
}
