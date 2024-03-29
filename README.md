# Top Talkers

A web interface to a Cisco router's Top Talkers table, for simple
bandwidth usage monitoring.

## Getting Started

Edit settings.py and change the following settings to match your site:

* `TOPTALKERS_ROUTER` (the IP address of the Cisco router with Top
Talkers enabled)
* `TOPTALKERS_COMMUNITY` (the community string for read-only access to
the Top Talkers table on the router)

Then run:

	deploy/tasks.py deploy:dev
	django/website/manage.py update_ve
	django/website/manage.py runserver

For Apache web server integration, look at the sample configuration
files in the `apache` directory.

## Automated Deployment

If you're not Aptivate and you want to use automated deployment, you'll
most likely need to change some files and settings. The server which you
deploy to will need to pull a copy of the source, *with* your changes,
from a Git repository somewhere. Therefore, you'll need to put a fork of
the project into your own repository, change the settings, and deploy
that.

After cloning this project, go into the deploy directory, edit fabfile.py
and check the repository settings:

	env.repo_type = "git" or "svn"
	env.repository = 'https://' or 'git://...' or 'git@...'
	env.svnuser = '<username>' and env.svnpass = '<password>' for Subversion repositories

And the server name settings:

	env.hosts = ['server-hostname']

For servers that are configured, remove the abort() line to make
deployment work:

	utils.abort('remove this line when server is setup')

In the same directory, edit `project_settings.py` and change the project
name to something unique:

	project_name = "acme_widgets"

In the `django/website` directory, edit the `local_settings.py.*` files
and choose appropriate database settings. For example, you might well
want to use SQLite databases for development, because they require
minimal setup, and MySQL in production. You may also want to configure
SOLR instead of Whoosh as the search engine.

All of these settings are used as overrides of settings.py, so any
settings which apply to all environments can be made there. If your
production server lives in a different timezone, you may wish to
override `TIME_ZONE` in `local_settings.py.production`.

Now run these commands to generate a secret key and database password,
symlink `local_settings.py` to an environment such as `dev`, create the
database, tables and virtualenv, and download any dependent packages:

	cd deploy
	tasks.py deploy:dev
	cd ..

You'll need to create a super user to log into the django-cms admin
interface:

	cd django/website
	./manage.py createsuperuser

And then start the webserver:

	./manage.py runserver

And start hacking!
