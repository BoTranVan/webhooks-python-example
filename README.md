Scalr Example Webhook App
=========================

This Python web application is meant to serve as a base for you to build a Scalr Webhook Handler.

The application integrates the following:

  + Endpoint validation
  + Signature validation
  + Request parsing

To add your own logic, all you have to do is extend the `webhook_post_handler` function in `app.py`.


Usage
=====

To deploy the app, you can:

   + Add it to an instance you own, install its dependencies
   + Use a PaaS, either deployed on your own infrastructure (CloudFoundry), or on public infrastructure (e.g. Heroku)


Installing Dependencies
-----------------------

To install the app's dependencies, do the following:

  + Ensure that you have the [Python Pip installer][0] available on your system
  + Run `pip install -r requirements.txt`, from the root of the project


Configuring the app
-------------------

The application is configured by passing its configuration through environment variables.

If you are using Honcho or Foreman (as suggested below), you can simply input those environment variables in the `.env`
file.

The following variables are used:

  + `VALIDATION_TOKEN`: This should be the validation token provided by Scalr, used to validate your endpoint.
  + `SIGNING_KEY`: This should be the signing key provided by Scalr, used to authenticate requests.


Running the app
---------------

Once you have installed and configured the app, you can launch it by running `honcho start web`. The app will listen on
port `5000` by default.

If you're launching the app on an instance, you'll probably want to daemonize it. To do so, navigate to the app
directory, and then run:

    gunicorn --daemon --bind 0.0.0.0:5000 app:app

Bear in mind that `gunicorn` will not read your `.env` file, so you have to pass the `VALIDATION_TOKEN` and
`SIGNING_KEY` environment variables through other means.

One option is:

    VALIDATION_TOKEN=xxxx SIGNING_KEY=yyyy gunicorn --daemon --bind 0.0.0.0:5000 app:app

For further information, you should check the [Gunicorn documentation][3].



Further reading
===============

For more information, you should refer to our [Webhooks Documentation][1].


Issues
======

Please report issues and ask questions on the project's Github repository, in the [issues section][2].


License
=======

View `LICENSE`.


  [0]: http://www.pip-installer.org/
  [1]: https://scalr-wiki.atlassian.net/wiki/x/FYBe
  [2]: https://github.com/scalr-tutorials/webhooks-python-example/issues
  [3]: http://gunicorn-docs.readthedocs.org/en/latest/configure.html
