import os

DB_ADDRESS = os.environ.get('OCSP_DB_ADDRESS', '')
DB_PORT = os.environ.get('OCSP_DB_PORT', '')
DB_NAME = os.environ.get('OCSP_DB_NAME', '')
DB_USER = os.environ.get('OCSP_DB_USER', '')
DB_PASSWORD = os.environ.get('OCSP_DB_PASSWORD', '')
DB_DRIVER = 'postgresql+psycopg2'
DB_OPTIONS = '?use_batch_mode&client_encoding=utf8'
SQLALCHEMY_DATABASE_URI = f'{DB_DRIVER}://{DB_USER}:{DB_PASSWORD}@{DB_ADDRESS}:{DB_PORT}/{DB_NAME}{DB_OPTIONS}'
