'''
Parse some ELB logs and load them into duckdb
'''
import datetime
import functools
import gzip
import logging
import os
import re

import click
import boto3
import IP2Location
import sqlite3
import ua_parser.user_agent_parser


DATA_DIR = "logs"
ANALYSIS_DIR = "analysis"
ANALYSIS_DB = os.path.join(os.path.abspath(ANALYSIS_DIR),"logs.sqlite3")
LOG_BUCKET = "igsn.org-logs"
GEO_DB = os.path.abspath(os.path.join("geo","IP2LOCATION-LITE-DB1.BIN"))

logging.basicConfig(level=logging.INFO)
L = logging.getLogger("igsnmet")

def ts_to_id(ts_str):
    ts_str = ts_str.replace("Z","+00:00")
    d = datetime.datetime.fromisoformat(ts_str)
    return int(d.timestamp()*1E6)

def toint(v):
    try:
        return int(v)
    except:
        pass
    return 0

def tostr(v):
    if v is None:
        return ''
    v = v.strip()
    return v.strip('"')


class LogFileReader():
    def __init__(self, filename):
        self.filename = filename
        self._file = None

    def __enter__(self):
        if self.filename.endswith(".gz"):
            self._file = gzip.open(self.filename, "rt")
        else:
            self._file = open(self.filename, "rt")
        return self._file

    def __exit__(self, exc_type, exc_value, exc_traceback):
        self._file.close()


class ELBLogManager():
    def __init__(self, analysis_db=ANALYSIS_DB):
        self._data = os.path.abspath(DATA_DIR)
        self._bucket = LOG_BUCKET
        self._s3_prefix = "production/AWSLogs/666091722659/elasticloadbalancing/us-east-1/"
        os.makedirs(self._data, exist_ok=True)
        os.makedirs(ANALYSIS_DIR, exist_ok=True)
        self.s3 = boto3.client("s3")
        #self.cn = duckdb.connect(database=analysis_db, read_only=False)
        self.cn = sqlite3.connect(analysis_db)
        self.ipdb = IP2Location.IP2Location(GEO_DB)

    @functools.cache
    def to_country(self, ip):
        rec = self.ipdb.get_country_short(ip)
        return rec

    def list_logfiles(self, filter="", offline_only=False):
        '''Filter is added to the end of the prefix, like "2022/08/24/"
        '''
        res = []
        if offline_only:
            import glob
            g_path = os.path.join(self._data, filter + "*.gz")
            return glob.glob(g_path)
        paginator = self.s3.get_paginator("list_objects_v2")
        pages = paginator.paginate(
            Bucket=self._bucket,
            PaginationConfig={"PageSize":1000},
            Prefix=os.path.join(self._s3_prefix, filter)
        )
        for page in pages:
            objects = page.get("Contents")
            for o in objects:
                res.append(o['Key'])
            L.info("Entries: %s", len(res))
        return res

    def s3_path_to_local(self, s3_path):
        if s3_path.startswith(self._s3_prefix):
            fpath = s3_path.replace(self._s3_prefix,"")
            return os.path.join(self._data, fpath)
        return s3_path

    def download_logfile(self, s3_path, overwrite=False):
        L.info("s3_path = %s", s3_path)
        fndest = self.s3_path_to_local(s3_path)
        dest_dir = os.path.dirname(fndest)
        os.makedirs(dest_dir, exist_ok=True)
        if overwrite or not os.path.exists(fndest):
            with open(fndest, "wb") as fdest:
                self.s3.download_fileobj(self._bucket, s3_path, fdest)
        return fndest


    def initialize_database(self):
        sql = '''CREATE TABLE IF NOT EXISTS logs(
            id BIGINT PRIMARY KEY,
            t DATETIME,
            client_ip VARCHAR,
            backend_ip VARCHAR,
            status INTEGER,
            bstatus INTEGER,
            request_url VARCHAR,
            redirect_url VARCHAR,
            user_agent VARCHAR,
            country_code VARCHAR,
            browser_family VARCHAR,
            browser_major VARCHAR,
            device_brand VARCHAR,
            device_family VARCHAR,
            device_model VARCHAR,
            os_family VARCHAR,
            os_major VARCHAR
        );'''
        csr = self.cn.cursor()
        csr.execute(sql)
        self.cn.commit()

    def process_matches(self, groups):
        # add 7 for the ua parsed fields
        lg = len(groups)
        res = list(groups) + ['']*(lg+7)
        try:
            ua = ua_parser.user_agent_parser.Parse(res[17])
            res[29] = ua.get('user_agent',{}).get('family', '')
            res[30] = ua.get('user_agent',{}).get('major', '')
            res[31] = ua.get('device',{}).get('brand', '')
            res[32] = ua.get('device',{}).get('family', '')
            res[33] = ua.get('device',{}).get('model', '')
            res[34] = ua.get('os',{}).get('family', '')
            res[35] = ua.get('os',{}).get('major', '')
        except Exception as e:
            L.error(e)
        return res

    def day_summary(self, year, month, day):
        '''

        '''
        pass

    def addrows(self, rows):
        sql = 'INSERT INTO logs VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
        csr = self.cn.cursor()
        try:
            csr.executemany(sql, rows)
            self.cn.commit()
            return
        except sqlite3.IntegrityError as e:
            L.warning(e)
        for row in rows:
            try:
                csr.execute(sql, row)
                self.cn.commit()
            except sqlite3.IntegrityError as e:
                L.warning("Duplicate row for %s", row[1])

    def parse_logfile(self, fname):
        fields = [
            "type",                     # 00
            "timestamp",                # 01
            "alb",                      # 02
            "client_ip",                # 03
            "client_port",              # 04
            "backend_ip",               # 05
            "backend_port",             # 06
            "request_processing_time",  # 07
            "backend_processing_time",  # 08
            "response_processing_time", # 09
            "alb_status_code",          # 10
            "backend_status_code",      # 11
            "received_bytes",           # 12
            "sent_bytes",               # 13
            "request_verb",             # 14
            "request_url",              # 15
            "request_proto",            # 16
            "user_agent",               # 17
            "ssl_cipher",               # 18
            "ssl_protocol",             # 19
            "target_group_arn",         # 20
            "trace_id",                 # 21
            "domain_name",              # 22
            "chosen_cert_arn",          # 23
            "matched_rule_priority",    # 24
            "request_creation_time",    # 25
            "actions_executed",         # 26
            "redirect_url",             # 27
            "new_field",                # 28
        ]
        cols = (
            (1, ts_to_id),
            (1,tostr),
            (3,tostr),
            (5,tostr),
            (10,toint),
            (11,toint),
            (15,tostr),
            (27,tostr),
            (17,tostr),
            (3, self.to_country),
            (29,tostr),
            (30,tostr),
            (31,tostr),
            (32,tostr),
            (33,tostr),
            (34,tostr),
            (35,tostr),
        )
        # Note: for Python 2.7 compatibility, use ur"" to prefix the regex and u"" to prefix the test string and substitution.
	    # REFERENCE: https://docs.aws.amazon.com/athena/latest/ug/application-load-balancer-logs.html#create-alb-table
        regex = r"([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) \"([^ ]*) ([^ ]*) (- |[^ ]*)\" \"([^\"]*)\" ([A-Z0-9-]+) ([A-Za-z0-9.-]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^\"]*)\" ([-.0-9]*) ([^ ]*) \"([^\"]*)\" ($|\"[^ ]*\")(.*)"
        rows = []
        with LogFileReader(fname) as _file:
            for line in _file:
                matches = re.search(regex, line)
                if matches:
                    data = self.process_matches(matches.groups())
                    drow = [None]*len(cols)
                    for i in range(0,len(cols)):
                        cnv = cols[i][1]
                        #drow[i] = cnv(matches.group(cols[i][0]+1))
                        drow[i] = cnv(data[cols[i][0]])
                    rows.append(drow)
        return rows

@click.group()
def main():
    pass


@main.command()
@click.option('-y', '--year', default="2022", help="Year of log file")
@click.option('-m', '--month', default=None, help="Month of log file")
@click.option('-d', '--day', default=None, help="Day of log file")
def load(year, month, day):
    lm = ELBLogManager()
    lm.initialize_database()
    if month is None or day is None:
        d = datetime.datetime.utcnow()
        if month is None:
            month = f"{d.month:02d}"
        if day is None:
            day = f"{d.day:02d}"
    filter = f"{year}/{month}/{day}"
    print(filter)
    res = lm.list_logfiles(filter=filter)
    for r in res:
        fname = lm.download_logfile(r)
        lm.addrows(lm.parse_logfile(fname))


@click.option('-y', '--year', default="2022", help="Year of log file")
@click.option('-m', '--month', default=None, help="Month of log file")
@click.option('-d', '--day', default=None, help="Day of log file")
def daystat(year, month, day):
    if month is None or day is None:
        d = datetime.datetime.utcnow()
        if month is None:
            month = f"{d.month:02d}"
        if day is None:
            day = f"{d.day:02d}"
    lm = ELBLogManager()


if __name__ == "__main__":
    main()