# import library
import subprocess
import colored
import configparser
import argparse
import vulners
import sys

# declare table
tech = []
all = []
verb = False
save = False

#declare conf
inp = ""
mode = ""
type = "cve"
score = ''
path = ""
api_key = ""

#parse config
try:
    f = open('config.conf','r')
    params = f.read()
    f.close() #err file [config.conf] not found
except: print('error: file [config.conf] not found')

try :
    config = configparser.ConfigParser()
    config.read_string(params)
    mode = config['OPTIONS']['MODE']
    type = config['OPTIONS']['TYPE']
    score = config['OPTIONS']['SCORE']
    api_key = config['REQUIRED']['API_KEY']
    path = config['REQUIRED']['PATH'] #err can't parsing params from file [config.conf]
except : print('error can\'t parsing params from file [config.conf]')

#getting input & argparse
DESCRIPTION = ''' Vulnersify : tool which optimizes searches for vulnerabilities
requires : install vulners lookup and get api key from vulners
vulners lookup : https://github.com/koutto/vulners-lookup
api key : https://vulners.com/
first use : python3 vulnersify.py --input 'benmeddah 1.0' --api_key <your_key> --path $YOUR_PATH/vulners-lookup.py
you can directly input the 'path' of vulners lookup and the 'api key' into [config.conf] file
developed by: BENMEDDAH Mohamed
https://github.com/benmeddah/vulnersify
'''
parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter, epilog=DESCRIPTION  )
parser.add_argument(
    "--input",'-i',
    help="Input (Example: 'wordpress 5.2.5')\n",
    action="store",
    metavar="<Technology Version>",
    required=True,
    dest="inp",
)
parser.add_argument(
    "--mode",'-m',
    help="Mode [simple or table]\n",
    action="store",
    dest="mode",
)
parser.add_argument(
    "--type",'-t',
    help="Type [cve by default]\n",
    action="store",
    dest="type",
)
parser.add_argument(
    "--score",'-s',
    help="Score cvss (Default: '0-10')\n",
    metavar="<MIN-MAX>",
    action="store",
    dest="score",
)
parser.add_argument(
    "--api_key",'-k',
    help="API Key from vulners.com\n",
    action="store",
    dest="api_key",
)
parser.add_argument(
    "--path",'-p',
    help="path of vulners lookup (Example: Vulners/vulners-lookup.py)\n",
    action="store",
    metavar="<path>",
    dest="path",
)
parser.add_argument(
    "--verbose",'-v',
    help="Activing the verbose mode\n",
    action="store_true",
    dest="verb",
)

args = parser.parse_args()
if(verb) : print('parsing params..')

if not args.inp:
    print('Wrong Usage: --input is required')
    sys.exit(0)

inp = args.inp
verb = args.verb
if args.mode : mode = args.mode
if args.type : type = args.type
if args.score : score = args.score
if args.path : path = args.path ; save = True
if args.api_key : api_key = args.api_key ; save = True

#processing ...
sc = score.replace("'", "")
scor = sc.split('-')
if len(scor) != 2:
    print('format of score not valid, ex: \'0-10\'')
    sys.exit(0)
else :
    try:
        casting = int(scor[0])
        casting = int(scor[1])
    except :
        print('format of score not valid, try with --help')
        sys.exit(0)


try : api = vulners.Vulners(api_key=api_key)
except : print('API key must be provided. You can obtain one for free at https://vulners.com'); sys.exit(0)
print('looking for '+inp+' ...')

def result(query):
    if not isinstance(query,str) :
        return api.search("(affectedSoftware.name:{} AND affectedSoftware.version:{} AND type:{} AND cvss.score:[{} TO {}]) order:cvss.score".format(query[0],query[1],type,scor[0],scor[1]), limit=200)
    return api.search("({} AND type:{} AND cvss.score:[{} TO {}]) order:cvss.score".format(query,type,scor[0],scor[1]), limit=200)
#tables
ttech = result(inp.split(' '))

if len(ttech) > 0:
    for x in ttech :
        if x['title'].find('CVE-20') > -1 :
            tech.append(x['title'])
            if(verb) : print(colored.stylize(x['title']+' checked ...',colored.fg('green')))
#mode simple
if mode == 'simple':
    if(verb) : print('\nMODE SIMPLE...\n')
    tall = result(inp)
    if len(tall) > 0:
        for x in tall :
            if x['title'].find('CVE-20') > -1 :
                all.append(x['title'])

        for x in tech :
            try :
                found = all.index(x)
                all[found] = colored.stylize(x,colored.fg('red'))
            except :
                print('the script not work normally .. use vulners lookup')
    else :
        print('no result founded, try with -h')
    print('\n---  done.  ----\n'+str(len(all))+' results found.')
    print(colored.stylize('\ncheck the white results only\n',colored.fg('yellow')))
    for item in all : print(item)
#mode table
if mode == 'table':
    if(verb) : print('MODE TABLE\ncalling vulners Lookup')
    cmd = 'python3 {} all --apikey "{}" "{} AND type:{} AND cvss.score:[{} TO {}]"'.format(path,api_key,inp,type,scor[0],scor[1])
    if(verb) : print('command used:\n'+cmd)
    else : print('calling vulners Lookup...')
    xall = subprocess.getoutput(cmd)
    if xall.find("can't find") > -1:
        print('can\'t find vulners lookup, try -h')
        sys.exit(0)
    for xi in tech :
        xall = xall.replace(xi,colored.stylize(xi,colored.fg('red')),2)
    nb =  xall.find('\n',xall.find('available...'))
    print('\n---  done.   ---\n')
    print(colored.stylize('check the white results only\n',colored.fg('yellow')))
    print(xall[nb+1:])

#save
if save :
    answer = str(input('do you want to save this configuration ? y/n : '))
    if answer[0] == 'y' or answer[0] == 'Y':
        try:
            f = open('config.conf','w')
            context ='''[REQUIRED]
API_KEY = {}
PATH = {}
[OPTIONS]
#MODE = simple | table
MODE = {}
#TYPE = cve | openwrt | typo3 | hackapp | openbugbounty | nessus | openvas | nmap | exploitdb etc ..
TYPE = {}
#SCORE = \'0-10\'
SCORE = {}'''.format(api_key,path,mode,type,score)
            f.write(context)
        except: prinit('can\'t save configurition! try : nano conf.config')
#developed by: BENMEDDAH Mohamed
#github.com/benmeddah/vulnersify
