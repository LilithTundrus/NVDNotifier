'use strict';
const fs = require('fs');                                       // for reading the JSON file
const path = require('path');
var extract = require('extract-zip');
const util = require('util');                                   // for using child-process
const PDFDocument = require('pdfkit');
const exec = require('child-process-promise').exec;
const config = require('./config.js');                          // config file for script
const NVDClass = require('./NVDJSONClass.js');                  // helper for getting at NVD Data for specific years
const debug = config.debug;                                     // used to allow/disallow verbose logging
var appRootDir = require('app-root-dir').get();

const tempFileDir = `${appRootDir}/node_modules/nvd-cli/lib/temp/`;
var globalNVDJSON;


// TODO: Allow for vulerability severity arg (IE Ignore 'LOW' scoring entries that match)
// TODO: for recents, ensure that the CVE review is FINAL?
// TODO: fix the global JSON data issue that really shouldn't be there
// TODO: add more of the NVD data to the objects in parseNVDData

module.exports.defaultOutputLocation = `${process.cwd()}/output.pdf`;

module.exports.executeNVDCheck = function (optsObj) {
    let searchYear = optsObj.searchYear;
    if (optsObj.executeType == 'full') {
        //we know all of the search props will be provided
        return productAndVendorSearchHanlder(searchYear, optsObj.searchTerm, './', `output`)

    } else if (optsObj.executeType == 'recent') {
        return productAndVendorSearchHanlder('recent', optsObj.searchTerm, './', `output`);
    }
}

module.exports.wait = function () {
    return new Promise((resolve) => {
        setTimeout(function () {
            console.log('Waiting for file to be ready..')
            resolve('Promise resolved!!');
        }, 2 * 1000);
    });
}

module.exports.cleanTempDir = function () {
    // Clean the temporary folder on every PDF generation execute here
    fs.readdir(tempFileDir, (err, files) => {
        if (err) throw err;
        for (const file of files) {
            fs.unlink(path.join(tempFileDir, file), err => {
                if (err) throw err;
            });
        }
    });
}

// NON-PUBLIC functions
function capitalizeFirstLetter(string) {                            // used to clean up some of the NVD names for products
    return string.charAt(0).toUpperCase() + string.slice(1);
}

function getNVDZipFile(url, fileLocation) {
    return new Promise((resolve, reject) => {
        return exec(`curl "${url}" > ${fileLocation}`)
            .then(function (result) {
                var stdout = result.stdout;
                var stderr = result.stderr;
                if (debug) { console.log('stderr: ', stderr); }
                console.log(stderr)
                return resolve(stdout);
            });
    });
}

function extractZipFile(fileNameToExtract) {
    console.log(`Extracting file ${fileNameToExtract}`)
    console.log(fs.existsSync(fileNameToExtract))
    return new Promise((resolve, reject) => {
        return extract(fileNameToExtract, { dir: tempFileDir }, function (err) {
            return resolve(err);
        });
    });
}

function productAndVendorSearchHanlder(yearToSearch, searchQuery, outputLocation, outputName) {
    if (typeof (searchQuery) !== 'string') {
        return console.log('Error: Product search term must be a string');
    } else if (searchQuery.length < 3) {
        console.log(`Error: please give a product name with at least 3 characters`);
        process.exit(0);
    } else {
        console.log(`Searching NVD year ${yearToSearch} for ${searchQuery}`);
        let NVDFileData = new NVDClass(yearToSearch);                   // generate the new NVDData references to work with
        return Promise.resolve()                                               // start the promise chain as resolved to avoid issues
            .then(() => getNVDZipFile(NVDFileData.NVDURL, NVDFileData.zipFileLocation))
            .then(() => extractZipFile(NVDFileData.zipFileLocation))
            .then(() => {
                let NVDJSON = fs.readFileSync(NVDFileData.NVDJSONFileName, 'utf-8');
                let parsedNVDData = JSON.parse(NVDJSON);
                globalNVDJSON = parsedNVDData;                          // used to allow the PDF file acess to certain data
                return parsedNVDData;
            })
            .then((NVDData) => searchNVDItems(NVDData, searchQuery))
            .then((affectedItemsArray) => {
                writePDFReport(affectedItemsArray, `SEARCH '${searchQuery}' ${yearToSearch}`, outputName);
            })
            .then(() => {
                if (debug) { console.log(`\nSuccessfully ended on ${new Date().toISOString()}`); }
            })
            .catch((err) => {
                console.log(`Ended with error at ${new Date().toISOString()}: ${err} ${err.stack}`);
            })
    }
}

function parseNVDData(NVDObjArray, checklist) {
    console.log(`CVE data version: ${NVDObjArray.CVE_data_version}`);
    console.log(`CVE count: ${NVDObjArray.CVE_data_numberOfCVEs}`);
    console.log(`Last Updated: ${NVDObjArray.CVE_data_timestamp}`);
    var affectedItems = [];
    let swChecklist = JSON.parse(fs.readFileSync(checklist, 'utf-8'));
    NVDObjArray.CVE_Items.forEach((entry, index) => {
        var affectedItem = {};
        entry.cve.affects.vendor.vendor_data.forEach((entryV, indexV) => {
            // check against the list of vendors to check for vulnerabilities
            swChecklist.forEach((item, itemIndex) => {
                if (entryV.vendor_name.toLowerCase() == item.manufacturerName.toLowerCase()) {
                    entryV.product.product_data.forEach((product, productIndex) => {
                        if (product.product_name == item.softwareName.toLowerCase()) {
                            if (debug) { console.log(entry); }
                            var versionsAffected = [];
                            var referenceURLs = [];
                            entryV.product.product_data[0].version.version_data.forEach((version) => {
                                versionsAffected.push(version.version_value);
                            });
                            if (entry.cve.hasOwnProperty('references')) {
                                entry.cve.references.reference_data.forEach((ref, refIndex) => {
                                    referenceURLs.push(ref.url);
                                });
                            }
                            // push all of the data to an the affectedItem Obj
                            affectedItem.ID = entry.cve.CVE_data_meta.ID;
                            affectedItem.vendorName = entryV.vendor_name;
                            affectedItem.productName = entryV.product.product_data[0].product_name;
                            affectedItem.publishedDate = entry.publishedDate;
                            affectedItem.lastModifiedDate = entry.lastModifiedDate;
                            affectedItem.vulnerabilityDescription = entry.cve.description.description_data[0].value;
                            affectedItem.versionsAffected = versionsAffected;
                            affectedItem.referenceURLs = referenceURLs
                            // validate that v3 exists
                            if (entry.impact.hasOwnProperty('baseMetricV3')) {
                                affectedItem.v3SeverityScore = {
                                    severity: entry.impact.baseMetricV3.cvssV3.baseSeverity,
                                    scoreString: entry.impact.baseMetricV3.cvssV3.baseScore
                                }
                                affectedItem.attackVector = entry.impact.baseMetricV3.cvssV3.attackVector;
                            } else {
                                affectedItem.v3SeverityScore = {
                                    severity: 'NONE',
                                    scoreString: 'NONE'
                                }
                            }
                            // Do the same for v2
                            if (entry.impact.hasOwnProperty('baseMetricV2')) {
                                affectedItem.v2SeverityScore = {
                                    severity: entry.impact.baseMetricV2.severity,
                                    scoreString: entry.impact.baseMetricV2.cvssV2.baseScore
                                }
                            } else {
                                affectedItem.v2SeverityScore = {
                                    severity: 'NONE',
                                    scoreString: 'NONE'
                                }
                            }
                            affectedItems.push(affectedItem);       // push the affected item to the array to return
                        }
                    });
                }
            });
        });
    });
    console.log(`Number of matches found: ${affectedItems.length}`);
    return affectedItems;
}

function searchNVDItems(NVDObjArray, searchQuery) {
    console.log(`CVE data version: ${NVDObjArray.CVE_data_version}`);
    console.log(`CVE count: ${NVDObjArray.CVE_data_numberOfCVEs}`);
    console.log(`Last Updated: ${NVDObjArray.CVE_data_timestamp}`);
    var matches = [];
    NVDObjArray.CVE_Items.forEach((entry, index) => {
        var affectedItem = {};
        entry.cve.affects.vendor.vendor_data.forEach((entryV, indexV) => {
            // check against the list of products to match
            entryV.product.product_data.forEach((product, productIndex) => {
                if (product.product_name == searchQuery.toLowerCase() || product.product_name.includes(searchQuery.toLowerCase()) || entryV.vendor_name.toLowerCase() == searchQuery.toLowerCase() || entryV.vendor_name.toLowerCase().includes(searchQuery)) {
                    if (debug) { console.log(entry); }
                    var versionsAffected = [];
                    var referenceURLs = [];
                    entryV.product.product_data[0].version.version_data.forEach((version) => {
                        versionsAffected.push(version.version_value);
                    });
                    if (entry.cve.hasOwnProperty('references')) {
                        entry.cve.references.reference_data.forEach((ref, refIndex) => {
                            referenceURLs.push(ref.url);
                        });
                    }
                    // push all of the data to an the affectedItem Obj
                    affectedItem.ID = entry.cve.CVE_data_meta.ID;
                    affectedItem.vendorName = entryV.vendor_name;
                    affectedItem.productName = entryV.product.product_data[0].product_name;
                    affectedItem.publishedDate = entry.publishedDate;
                    affectedItem.lastModifiedDate = entry.lastModifiedDate;
                    affectedItem.vulnerabilityDescription = entry.cve.description.description_data[0].value;
                    affectedItem.versionsAffected = versionsAffected;
                    affectedItem.referenceURLs = referenceURLs
                    // validate that v3 exists
                    if (entry.impact.hasOwnProperty('baseMetricV3')) {
                        affectedItem.v3SeverityScore = {
                            severity: entry.impact.baseMetricV3.cvssV3.baseSeverity,
                            scoreString: entry.impact.baseMetricV3.cvssV3.baseScore
                        }
                        affectedItem.attackVector = entry.impact.baseMetricV3.cvssV3.attackVector;
                    } else {
                        affectedItem.v3SeverityScore = {
                            severity: 'NONE',
                            scoreString: 'NONE'
                        }
                    }
                    // Do the same for v2
                    if (entry.impact.hasOwnProperty('baseMetricV2')) {
                        affectedItem.v2SeverityScore = {
                            severity: entry.impact.baseMetricV2.severity,
                            scoreString: entry.impact.baseMetricV2.cvssV2.baseScore
                        }
                    } else {
                        affectedItem.v2SeverityScore = {
                            severity: 'NONE',
                            scoreString: 'NONE'
                        }
                    }
                    matches.push(affectedItem);                     // push the affected item to the array to return
                }
            });
        });
    });
    console.log(`Number of matches found for '${searchQuery}': ${matches.length}`);
    return matches;
}

function writePDFReport(affectedItemsArray, timeArg, outputArg) {
    var doc = new PDFDocument;
    doc.pipe(fs.createWriteStream(`${outputArg}.pdf`));
    doc.fontSize(16);
    doc.text(`NVD ${timeArg} Vulnerability Check Report ${new Date().toDateString()}`, { align: 'center', stroke: true });
    doc.fontSize(12);
    doc.text(`\n\nCVE data version: ${globalNVDJSON.CVE_data_version}`);
    doc.text(`CVE count: ${globalNVDJSON.CVE_data_numberOfCVEs}`);
    doc.text(`Last Updated: ${globalNVDJSON.CVE_data_timestamp}`);
    doc.text(`Number of Vulnerabilites Matched: ${affectedItemsArray.length}`);
    doc.fontSize(14);
    doc.moveDown();
    // get each affected item's data and format it
    affectedItemsArray.forEach((entry, index) => {
        doc.text(`\n${capitalizeFirstLetter(entry.vendorName)} ${capitalizeFirstLetter(entry.productName)} (${entry.ID})`, { stroke: true });
        doc.text(`Published: ${entry.publishedDate}    Modified: ${entry.lastModifiedDate}`);
        doc.text(`Versions Affected: ${entry.versionsAffected.join(', ')}`);
        doc.text(`Attack Vector: ${entry.attackVector}`);
        doc.text(`\nDescription: ${entry.vulnerabilityDescription}`);
        doc.text(`\nV3 Score: ${entry.v3SeverityScore.severity} (${entry.v3SeverityScore.scoreString})`);
        doc.text(`V2 Score: ${entry.v2SeverityScore.severity} (${entry.v2SeverityScore.scoreString})`);
        doc.text(`\nReferences:`);
        doc.fillColor('blue');                                      // color ref URLs blue
        doc.text(`${entry.referenceURLs.join('\n')}`);
        doc.fillColor('black');                                     // reset the color
        doc.moveDown();                                             // Allow for some whitespace in between entries
    });
    doc.text('\n\nEnd of File');
    doc.end();
    return console.log(`Wrote report as ${outputArg}.pdf`);
}

function wait() {
    return new Promise((resolve) => {
        setTimeout(function () {
            console.log('Waiting for file to be ready..')
            resolve('Promise resolved!!');
        }, 5 * 1000);
    });
}

