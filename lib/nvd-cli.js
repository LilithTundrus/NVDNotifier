'use strict';

const nvd = require('./nvd-exports');

nvd.executeNVDCheck({
    searchYear: '2018',
    executeType: 'full',
    searchTerm: 'linux'
})