# vulnersify
```
__     __     _                     _  __
\ \   / /   _| |_ __   ___ _ __ ___(_)/ _|_   _
 \ \ / / | | | | '_ \ / _ \ '__/ __| | |_| | | |
  \ V /| |_| | | | | |  __/ |  \__ \ |  _| |_| |
   \_/  \__,_|_|_| |_|\___|_|  |___/_|_|  \__, |
                                          |___/
```
**Vulnersify** is a script which optimizes searches for vulnerabilities

**vulnersify.py** is the python script ( python3 )

**config.conf** is a file that contains the configuration necessary to run the vulnersify.py script

**note**: both files ***vulnersify.py*** and ***config.conf*** must be in the same directory

## install
```
git clone https://github.com/benmeddah/vulnersify.git
cd vulnersify
```
`pip3 install -r requirements.txt` ( or : `python3 -m pip install -r requirements.txt` )

## first use
```
python3 vulnersify.py --input 'bootstrap 4.0.0' --api_key <your_key> --path $YOUR_PATH/vulners-lookup.py
```
*or you can put the api key and the path directly in the config.conf file*

## examples
```
python3 vulnersify.py --help
python3 vulnersify.py -i 'joomla 3.3.1'
python3 vulnersify.py -i 'joomla 3.3.1' --mode table
python3 vulnersify.py -i 'apache 2.2.0' --type exploitdb --score '7-10'
```
### developed by: BENMEDDAH Mohamed
