import os
import sys

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
app_path = os.path.join(THIS_DIR, "..")
sys.path.append(app_path)

import pytest
import igsnmet

def _getdb():
    db = os.path.join(THIS_DIR,"test.sqlite3")
    if os.path.exists(db):
        os.unlink(db)
    return db

def test_reader():
    fname = os.path.join(THIS_DIR, "test_log.log")
    lm = igsnmet.ELBLogManager(analysis_db=_getdb())
    rows = lm.parse_logfile(fname)
    assert len(rows) == 6

def test_dbload():
    lm = igsnmet.ELBLogManager(analysis_db=_getdb())
    lm.initialize_database()
    fname = os.path.join(THIS_DIR, "test_log.log")
    rows = lm.parse_logfile(fname)
    lm.addrows(rows)
    lm.addrows(rows)
