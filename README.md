# nvd-cli

This project is designed to assist with searching the National Vulnerability Database 
([NVD](https://nvd.nist.gov/)) and getting vulnerability info for the products that matter to **you**

If there's errors or anything like that, feel free to put up and issue or contact me personally.

Please be patient since this will be the first npm cli-type project I've worked on. I'll be testing as I can


## Installation

You can install this cli program via npm:
```
npm install -g nvd-cli
```

### Checking your nvd-cli version

Standard `--version` arg is supported to check which version of this npm app you have:
```
$ nvd-cli --version

0.6.7
```

## Usage

```
$ nvd-cli  -t search_term -f [year] || -r

-f, --full            Conduct a full search against for a given <year> arg

-r, --recent, recent  Search for vulnerabilaties in the NVD recent category using default 

-t, --term            Search term to check the NVD database against
```

## History

- **0.6.8**
    - Improved `commander` functionality


- **0.6.5**
    - Fixed the annoying PATH errors with Windows
    - Tested in Linux/UNIX environment
    - Removed some debugging code


- **0.5.5**
    - Completely changed how this CLI tool operates
    - Streamlined usage and removed a lot of unused code
    - Using `commander` for processing args instead of custom code
    - Removing files on script completeion


- **0.5.0**
    - Added `--vendor` option to `-s` and `--search` primary flags
    - Cleaned up the documentation so it made a bit more sense after some feedback
    - Minor fixes


- **0.4.9**
    - Set PDKit to default font to avoid issues


- **0.4.8**
    - Fixed checklist issue that popped up that testing didn't catch


- **0.4.7**
    - `--search` command now actually does something (accidentally left code commented when testing)


- **0.4.5**
    - Updated some legacy code involving checklist files that was causing issues if it was not found
    - Minor changes


- **0.4.1**
    - Fixed the npm install issue


- **0.4.0**
    - Added the `help <command>` functionality. There's likely typos/errors. If you find any let me know
    - Updated the `-h (--help)` information
    - Project is now up on `npm`


- **0.3.5**
    - Added the `-t (--type)` optional flag for changing the output type
    - Changed the arg validations slightly, reducing the number of pre-run checks


- **0.3.2**
    - Updated help info to be actually useful


- **0.3.1**
    - `-s` now requires at least 3 characters to search by
    - fixed HUGE issue where `-s` flag wasn't actually searching the passed year


- **0.3.0**
    - `-s` functionality has been (mostly) implimented
    - `-v` flag will now show the version of nvd-cli installed
    - Major improvment to code layout
    - Much more validation has been put in place


- **0.2.0**
    - A new (better) argument handler is now in place
    - `-f` and `-r` args work as before if not better than before
    - `-c` and `-o` commands for setting a custom checklist and output location have been added


- **0.1.2**
    - Added help command/arg handler.  `help <command>` not yet working


- **0.1.0**
    - -r and -f functionality are partially implimented


- **0.0.1**
    - Initial minimum viable product


## License

See LICENSE file in the root directory