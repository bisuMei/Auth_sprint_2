from gevent import monkey

monkey.patch_all()

from psycogreen import gevent

gevent.patch_psycopg()

from run import app
