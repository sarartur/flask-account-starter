# Flask-Account-Starter
<img src="https://img.shields.io/github/issues/sarartur/flask-account-starter">  <img src="https://img.shields.io/github/forks/sarartur/flask-account-starter">   <img src="https://img.shields.io/github/stars/sarartur/flask-account-starter">   <img src="https://img.shields.io/github/license/sarartur/flask-account-starter">


Flask-Account-Starter is a flexible and extensible Flask boilerplate template that contains essential functions required of an application with user accounts.

### Features
The application comes out of the box with the following features:
- Account Creation
- Account Verification (enabled / disabled)
- New Login IP detection / verification
- Block after `x` Login Attempts
- Password Reset
- User Activity Log
- Automated Emails
- Slick [Bootstrap 5](https://getbootstrap.com/docs/5.0/getting-started/introduction/) and [FontAwesome 6](https://fontawesome.com/) responsive templates.
- Custom CLI extensions for user management


To achieve this functionality the application leverages the following popular extensions and packages:
- Flask-Login
- Flask-Bcrypt
- Flask-SQLAlchemy
- Flask-Migrate
- flask-Mail
- authlib

The code is written using the application factory pattern and is neat and extensible. The project contains some responsive templates and pages styled with [Bootstrap 5](https://getbootstrap.com/docs/5.0/getting-started/introduction/) 
written using Jinja2 and HTML best practices. 

<p align="center">
  <img src="/.images/login_page.png" width="400px" height='100%'>
  <img src="/.images/reg_page.png" width="400px" height='100%'>
  <img src="/.images/account_log_page.png" width="400px" height='100%'>
  <img src="/.images/password_reset_page.png" width="400px" height='100%'>
</p>

### Getting Started

The application requires `python3.8` or higher.

```
git clone https://github.com/sarartur/flask-account-starter
```

```
pip install -r requirements.txt
```

The configuration is set through **environment variables**. The configuration file contains defaults which should be overwritten accordingly. Start by exporting the application it self:

```
export FLASK_APP='app.wsgi'
```

Additionally you may want to right away configure the database and the environment:

```
export FLASK_ENV='development'
export SQLALCHEMY_DATABASE_URI='postgresql://postgres:123@localhost:5432/app'
```

Run the migrations using `Flask-Migrate`:

```
flask db init
flask db migrate
flask db upgrade
```

At this point the application should be good to launch in development mode with:

```
flask run
```

### Next Steps
To enable email verification and password verification functionality you will need to connect an email account to ```Flask-Mail``` (see [documentation](https://pythonhosted.org/Flask-Mail/)) and also create an generate an ```JWT RS256``` key pair:

```
ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.key
openssl rsa -in jwtRS256.key -pubout -outform PEM -out jwtRS256.key.pub
```
and export variables pointing to the files and set `ACCOUNT_VERIFICATION` to `True`:
```
export JWT_PRIVATE_KEY='/path/to/jwtRS256.key'
export JWT_PUBLIC_KEY='/path/to/public/jwtRS256.key.pub'
export ACCOUNT_VERIFICATION='True'
```
The application also supports new IP login verification and account block due to unsuccessful attempts.
```
export LOGIN_MAX_RETIRES=4
export LOGIN_NEW_IP_VERIFY='True'
```

At this point all of the apps functionality is activated. You can continue building on top of the code using the general principles of `Flask` factory patter design.

### Layout
```
app
├── __init__.py                               #Application factory. 
├── auth                                    
│   ├── forms.py                              #Login, Register and Password Reset forms.
│   ├── __init__.py                           #Authentication Blueprint, login_required func.
│   ├── routes.py                             #Login, logout, register, etc. routes.
|   ├── handlers.py                           #Handlers for authentication logic.
│   ├── templates                             #Auth templates for routes above.
│   │   └── auth
│   │       ├── _header.html
│   │       ├── login.html
│   │       ├── password_reset.html
│   │       ├── password_reset_request.html
│   │       └── register.html
│   └── utils.py
├── config.py                                 #Configuration File. See README.MD.
├── core                                      
│   ├── __init__.py                           #Core Blueprint.
│   ├── models.py                             #BaseMixin class.
│   ├── routes.py                             #Home route.
│   └── templates
│       └── core
│           ├── components                    #Components for `include` with Jinja.
│           │   ├── inputs
│           │   │   ├── _field_errs.html
│           │   │   └── floating_label.html
│           │   └── pagination.html
│           └── layout.html                   #Application layout.
├── email                                         
│   ├── __init__.py                           #Email Blueprint and send func.
│   └── templates
│       └── email                             #Email templates.
|           ├── login_verification.html
│           ├── account_verification.html
│           └── password_reset.html
├── extensions                                #Application extensions
│   ├── bcrypt.py                             #Flask-Bcrypt
│   ├── database.py                           #Flask-SQLAlchemy, Flask-Migrate
│   ├── flask_login.py                        #Flask-Login
│   ├── flask_mail.py                         #Flask-Mail
│   └── __init__.py
├── static             
│   ├── css
│   │   └── main.css
│   └── images
│       ├── logo_full.png
│       └── logo.png
├── user
│   ├── cli.py                                #Cli for user model: add user, get passwd reset link.
│   ├── enums.py                              #UserAccountLog action types and Block reasons types.
│   ├── forms.py                              #Verification email request form.
│   ├── __init__.py                           #User Blueprint.
│   ├── models.py                             #UserAccount and UserAccountLog models.
│   ├── routes.py                             #User profile routes.
│   └── templates                             #User templates.
│       └── user
│           ├── _header.html
│           ├── profile.html
│           └── profile_not_verified.html
└── wsgi                                         
    └── __init__.py                           #Application instance.

```

### Contact
 - Email me at sarartur.ruk@gmail.com or open a new [Issue](https://github.com/sarartur/flask-account-starter) on Github.


