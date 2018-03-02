#!/usr/bin/env node
'use strict';
const nvd = require('./nvd-exports');
const program = require('commander');

const validSearchYears = ['2007', '2008', '2009', '2010', '2011', '2012', '2013', '2014', '2015', '2016', '2017', '2018'];

program
    .version('0.6.0')
    .option('-f --full [year_to_search]', 'Execute a FULL check on products and vendors for a given year based on the passed search term')
    .option('-r --recent', 'Execute a recent search on products and vendors based on the passed search term')
    .option('-t --term [search_term]', 'The term to check NVD product and vendor vulnerabilities against')
    .parse(process.argv);

if (!program.term) {
    console.log('Please provide a valid search term using -t or --term');
    return process.exit(0);
} else {
    if (program.full) {
        // Full search by year for the term
        if (validSearchYears.includes(program.full)) {
            return nvd.executeNVDCheck({
                searchYear: program.full,
                executeType: 'full',
                searchTerm: program.term
            })
                .then(() => {
                    return nvd.cleanTempDir();
                })
        } else {
            console.log(`Invalid year to fully search for: ${program.full}`, '\n\nPlease give a valid year between 2007 and 2018');
            return process.exit(0);
        }
    } else if (program.recent) {
        return nvd.executeNVDCheck({
            searchYear: 'recent',
            executeType: 'recent',
            searchTerm: program.term
        })
            .then(() => {
                return nvd.cleanTempDir();
            })
    }
}




