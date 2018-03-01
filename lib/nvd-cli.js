#!/usr/bin/env node
'use strict';
const nvd = require('./nvd-exports');
const program = require('commander');

program
    .version('0.6.0')
    .option('-f --full [year_to_search]', 'Execute a FULL check on products and vendors for a given year based on the passed search term')
    .option('-r --recent', 'Execute a recent search on products and vendors based on the passed search term')
    .option('-t --term [search_term]', 'The term to check NVD product and vendor vulnerabilities against')
    .parse(process.argv);

if (program.full) {
    console.log(program.full);
}

if (program.term) {
    console.log(program.term);
}

nvd.executeNVDCheck({
    searchYear: '2018',
    executeType: 'full',
    searchTerm: 'linux'
})