
/**
 *  Class used to generate NVD file names and URLs for getting NVD data to the main script
 * @class NVDJSON
 */
class NVDJSON {
    /**
     * Creates an instance of NVDJSON.
     * @param {number | string} NVDYear 
     * @memberof NVDJSON
     */
    constructor(NVDYear) {
        this.NVDURL = `https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-${NVDYear}.json.zip`;
        this.zipFileLocation = `./temp/nvdfullzip${NVDYear}.zip`;
        this.NVDJSONFileName = `./temp/nvdcve-1.0-${NVDYear}.json`;
    }
}

module.exports = NVDJSON;