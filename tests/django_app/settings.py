DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'db.sqlite3',
    }
}
INSTALLED_APPS = ["django_app.app"]
DEBUG = True
SECRET_KEY = "not_secret"
ROOT_URLCONF = 'django_app.urls'
