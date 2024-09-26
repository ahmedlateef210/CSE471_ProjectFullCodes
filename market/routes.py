from market import app, login_manager
from flask import render_template, redirect, url_for, flash, request
from market.models import Trade, User, ShopInventory, TradeHistory
from market.forms import RegisterForm, LoginForm, GetBookForm, AddToShopForm, AddTradeForm
from market import db
from flask_login import login_user, logout_user, login_required, current_user


@app.route('/')
@app.route('/home')
def home_page():
    return render_template('home.html')


@app.route('/inventory')
@login_required
def inventory_page():
    inventory = ShopInventory.query.all()
    return render_template('inventory.html', inventory=inventory)


@app.route('/tradehistory')
@login_required
def trade_history_page():
    trade_history = TradeHistory.query.all()
    return render_template('history.html', trade_history=trade_history)


@app.route('/market', methods=['GET', 'POST'])
@login_required
def market_page():
    get_form = GetBookForm()
    if request.method == "POST":
#       Get Book Logic
        get_item = request.form.get('get_item')
        g_item_object = Trade.query.filter_by(name=get_item).first()
        if g_item_object:
            if current_user.can_get(g_item_object):
                history_to_add = TradeHistory(isbn=g_item_object.isbn, name=g_item_object.name,
                                              traded_from=g_item_object.owner, traded_to=current_user.id)
                g_item_object.get(current_user)
                flash(f"Congratulations! You received {g_item_object.name}", category='success')
                db.session.add(history_to_add)
                db.session.commit()
            else:
                flash(f"Unfortunately, you cannot trade for your own book!", category='danger')

        return redirect(url_for('home_page'))

    if request.method == "GET":
        books = Trade.query.all()
        owned_items = Trade.query.filter_by(owner=current_user.id)
        return render_template('market.html', books=books, get_form=get_form, owned_items=owned_items)


@app.route('/addtoinventory', methods=['GET', 'POST'])
@login_required
def insert_inventory_page():
    form = AddToShopForm()
    if form.validate_on_submit():    
        inventory_to_add = ShopInventory(isbn=form.isbn.data, name=form.name.data, description=form.description.data)
        db.session.add(inventory_to_add)
        db.session.commit()
        flash(f'Success! You have added: {inventory_to_add.name}', category='success')
        return redirect(url_for('inventory_page'))
    else:
        flash('Error! Fill the forms in correctly.', category='danger')
        
    return render_template('addinventory.html', form=form)


@app.route('/addtrade', methods=['GET', 'POST'])
@login_required
def insert_trade_page():
    form = AddTradeForm()
    if form.validate_on_submit():    
        trade_to_add = Trade(isbn=form.isbn.data, name=form.name.data, description=form.description.data, owner=form.owner.data)
        db.session.add(trade_to_add)
        db.session.commit()
        flash(f'Success! You have added: {trade_to_add.name}', category='success')
        return redirect(url_for('market_page'))
    else:
        flash('Error! Fill the forms in correctly.', category='danger')
    return render_template('addtrade.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        user_to_create = User(username=form.username.data, email_address=form.email_address.data, password=form.password1.data)
        db.session.add(user_to_create)
        db.session.commit()
        login_user(user_to_create)
        flash(f"Account created successfully! You are now logged in as {user_to_create.username}", category='success')
        return redirect(url_for('home_page'))
    if form.errors != {}:  # If there are no errors from the validations
        for err_msg in form.errors.values():
            flash(f'There was an error with creating a user: {err_msg}', category='danger')

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    form = LoginForm()
    if form.validate_on_submit():
        attempted_user = User.query.filter_by(username=form.username.data).first()
        if attempted_user and attempted_user.check_password_correction(
                attempted_password=form.password.data
        ):
            login_user(attempted_user)
            flash(f'Success! You are logged in as: {attempted_user.username}', category='success')
            return redirect(url_for('home_page'))
        else:
            flash('Username and password are not match! Please try again', category='danger')

    return render_template('login.html', form=form)


@app.route('/logout')
def logout_page():
    logout_user()
    flash("You have been logged out!", category='info')
    return redirect(url_for("home_page"))
