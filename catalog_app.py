#!/usr/bin/env python
from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
from database_setup import Base, User, Category, Item

from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker

from flask import session as login_session
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2

import json
from flask import make_response
import requests

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog App"

engine = create_engine('sqlite:///item_catalog.db', connect_args={'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
database = DBSession()

app = Flask(__name__)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    This function connects the user to the app using google oauth sign in. It handles all communications with the
    server in order to validate the user through safe protocols.
    :return:
    """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)  # gives error
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'% access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print ("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: ' \
              '150px;-moz-border-radius: 150px;"> '
    flash("You are now logged in as %s" % login_session['username'])
    print ("done!")
    return output


@app.route('/gdisconnect')
def gdisconnect():
    """
    This method disconnects the user if they have signed in through google. It deletes all current information
    that the app needs about the user so that user privacy is maintained.
    :return:
    """
    access_token = login_session.get('access_token')
    if access_token is None:
        print ('Access Token is None')
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print ('In gdisconnect access token is %s', access_token)
    print ('User name is: ')
    print (login_session['username'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print ('result is ')
    print (result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/disconnect')
def disconnect():
    """
    This method disconnects the user from the app. It calls the gdisconnect method necessary for logging the user out
    of the application.
    :return:
    """
    if 'username' in login_session:
        gdisconnect()
        flash("You have successfully been logged out.")
        return redirect(url_for('show_catalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('show_catalog'))


@app.route('/login')
def showLogin():
    """
    This method is what is called when the user accesses the login page. A state token is created within this
    function, and the HTML template for login is rendered within the web browser.
    :return:
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/catalog/<int:category_id>/item/JSON')
def catalog_JSON(category_id):
    """
    This method returns the JSON representations for the category items within a specific category. This function takes
    a parameter of category_id so that the category for which the items are to be accessed can be found.
    :param category_id:
    :return:
    """
    categories = database.query(Category).filter_by(id=category_id).one()
    items = database.query(Item).filter_by(category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/catalog/categories/JSON')
def categories_JSON():
    """
    This function returns the JSON representations for the categories themselves. Users can see the list of categories
    as JSON representations through this route.
    :return:
    """
    categories = database.query(Category).all()
    return jsonify(Categories=[i.serialize for i in categories])


@app.route('/')
@app.route('/catalog')
def show_catalog():
    """
    This function allows users to access the home page of the application. Depending on whether or not the user has
    logged in to the app, either a public or specific HTML file is loaded within the web browser. All categories are
    displayed.
    :return:
    """
    categories = database.query(Category).all()
    if 'username' not in login_session:
        return render_template('public_home.html', categories=categories)
    return render_template('home.html', categories=categories)


@app.route('/create', methods=['GET', 'POST'])
def create_item():
    """
    This method allows for the create operation within the application. Users that have logged in have access to this
    method, and they are allowed to create items as they please.
    :return:
    """
    categories = database.query(Category).all()
    if 'username' not in login_session:
        flash('You must log in to create an item')
        return render_template('public_home.html', categories=categories)
    if request.method == 'POST':
        print('Category: ' + request.form['category'])
        if request.form['category'] == 'other':
            newCategory = Category(name=request.form['other'])
            database.add(newCategory)
            database.commit()
            newItem = Item(name=request.form['name'], description=request.form['description'], 
                price=request.form['price'], category=newCategory, user_id=login_session['user_id'])
            database.add(newItem)
            database.commit()
            flash('New Category %s Successfully Created' % newCategory.name)
        else:
            category = database.query(Category).filter_by(id=request.form['category']).one()
            newItem = Item(name=request.form['name'], description=request.form['description'], 
                price=request.form['price'], category=category, user_id=login_session['user_id'])
            database.add(newItem)
            database.commit()
        flash('New Item %s Successfully Created' % newItem.name)
        return redirect(url_for('show_catalog'))
    else:
        return render_template('create_item.html', categories=categories)


@app.route('/catalog/<int:category_id>/<int:item_id>/delete/', methods=['GET', 'POST'])
def delete_item(category_id, item_id):
    """
    This is the method that allows to delete the item within the application. It ensures that the user is logged in
    in order to delete the item and that they are the creator of the item in order to delete it.
    :param category_id:
    :param item_id:
    :return:
    """
    item = database.query(Item).filter_by(id=item_id).one()
    categories = database.query(Category).all()
    if 'username' not in login_session:
        flash('You must log in to create an item')
        return render_template('public_home.html', categories=categories)
    if getUserInfo(item.user_id).name != login_session['username']:
        flash('You are not able to edit this item')
        return render_template('home.html', categories=categories)
    if request.method == 'POST':
        database.delete(item)
        database.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('show_category', category_id=category_id))
    else:
        return render_template('delete_item.html', item=item)


@app.route('/catalog/<int:category_id>/<int:item_id>/edit/', methods=['GET', 'POST'])
def edit_item(category_id, item_id):
    """
    This is the method to edit the item. It ensures that the user is logged in
    in order to edit the item and that they are the creator of the item in order to edit it.
    :param category_id:
    :param item_id:
    :return:
    """
    item = database.query(Item).filter_by(id=item_id).one()
    categories = database.query(Category).all()
    if 'username' not in login_session:
        flash('You must log in to edit an item')
        return render_template('public_home.html', categories=categories)
    if getUserInfo(item.user_id).name != login_session['username']:
        flash('You are not able to edit this item')
        return render_template('home.html', categories=categories)
    if request.method == 'POST':
        if request.form['name']:
            item.name = request.form['name']
        if request.form['description']:
            item.description = request.form['description']
        if request.form['price']:
            item.price = request.form['price']
        if request.form['category']:
            item.course = request.form['category']
        database.add(item)
        database.commit()
        flash('Item Successfully Edited') 
        return redirect(url_for('show_item_description', category_id=category_id, item_id=item_id))
    else:
        return render_template('edit_item.html', item=item, categories=categories)


@app.route('/catalog/<int:category_id>/', methods=['GET', 'POST'])
def show_category(category_id):
    """
    This is the method that is meant to show the items within the category. It takes a category id in order to specify
    the items which are meant to be viewed.
    :param category_id:
    :return:
    """
    category = database.query(Category).filter_by(id=category_id).one()
    items = database.query(Item).filter_by(category_id=category.id).all()
    return render_template('category.html', category=category, items=items)


@app.route('/catalog/<int:category_id>/<int:item_id>/', methods=['GET', 'POST'])
def show_item_description(category_id, item_id):
    """
    This is the method that shows the description of the item. Given the item id, it will rennder the information for
    that item.
    :param category_id:
    :param item_id:
    :return:
    """
    item = database.query(Item).filter_by(id=item_id).one()
    creator = getUserInfo(item.user_id)
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('public_show_item.html', item=item)
    else:
        return render_template('show_item.html', item=item)


def createUser(login_session):
    """
    This helper method is used to create a user within the database. It takes in the login_session dictionary so that
    the user can be added to the database.
    :param login_session:
    :return:
    """
    newUser = User(name=login_session['username'], email=login_session[
                    'email'], picture=login_session['picture'])
    database.add(newUser)
    database.commit()
    user = database.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """
    This is the helper method that returns the user information. It takes in the user id so that the user can be
    returned
    :param user_id:
    :return:
    """
    user = database.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    """
    This is the helper method that is able to get the user id given the email information. It is used when the email
    is given within the login_session dictionary.
    :param email:
    :return:
    """
    try:
        user = database.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8001)
