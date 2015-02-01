import os, datetime, requests

version_file = os.path.splitext(__file__)[0] + '.txt'
__version__  = file(version_file).read()

version_url  = 'https://api.github.com/repos/binjitsu/binjitsu/git/refs/heads/master'
iso8601      = '%Y-%m-%dT%H:%M:%SZ'

def check_version():
    # Find when the pwnlib directory was created
    installed = os.path.split(__file__)[0]
    installed = datetime.fromtimestamp(modified)

    # Find when binjitsu was last updated
    try:
        response  = requests.get(version_url).json()
        response  = requests.get(response['object']['url']).json()
    except:
        return

    # Extract the date
    date = response['committer']['date']
    date = time.strptime(date, iso8601)
    date = datetime.datetime(*date[:6])

    # Find offset from GMT
    local, gmt = time.localtime(), time.gmtime()
    local      = datetime.datetime(*local[:6])
    gmt        = datetime.datetime(*gmt[:6])
    offset     = -(gmt - local)

    # Fix the reported date
    date = date + offset
