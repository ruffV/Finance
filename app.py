import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

import datetime

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    transactions = db.execute(
        "SELECT symbol, SUM(shares) AS shares, price FROM transactions WHERE user_id = ? GROUP BY symbol",
        user_id,
    )
    cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"]

    return render_template("index.html", transactions=transactions, cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        quote = lookup(symbol)

        if not request.form.get("symbol"):
            return apology("missing symbol")
        if quote == None:
            return apology("Need to provide symbol")
        if not shares:
            return apology("Need to provide valid shares")

        if not str.isdigit(shares):
            return apology("invalid shares")
        if int(shares) <= 0:
            return apology("invalid shares")

        symbol = symbol.upper()
        shares = int(shares)
        price = float(quote["price"]) * shares

        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        balance = balance[0]["cash"]

        new_balance = balance - price

        if new_balance < 0:
            return apology("You cannot afford this transaction")

        row = db.execute(
            "SELECT * FROM transactions WHERE user_id = :id AND symbol = :symbol",
            id=session["user_id"],
            symbol=symbol,
        )

        if len(row) != 1:
            db.execute(
                "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                session["user_id"],
                symbol,
                0,
                usd(quote["price"]),
            )

        oldshares = db.execute(
            "SELECT shares FROM transactions WHERE user_id = ? AND symbol = ?",
            session["user_id"],
            symbol,
        )
        oldshares = oldshares[0]["shares"]

        newshares = oldshares + shares

        db.execute(
            "UPDATE transactions SET shares = :newshares WHERE user_id = :id AND symbol = :symbol",
            newshares=newshares,
            id=session["user_id"],
            symbol=symbol,
        )

        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?", new_balance, session["user_id"]
        )

        date = datetime.datetime.now()
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price, date) VALUES (?, ?, ?, ?, ?)",
            session["user_id"],
            quote["symbol"],
            shares,
            usd(quote["price"]),
            date,
        )
        flash("Bought!")
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", user_id)
    return render_template("history.html", transactions=transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/add_cash")
def add_cash():
    """Add 1000$ to account"""
    balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0][
        "cash"
    ]
    new_balance = balance + 1000
    db.execute(
        "UPDATE users SET cash = ? WHERE id = ?", new_balance, session["user_id"]
    )
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "GET":
        return render_template("quote.html")
    elif request.method == "POST":
        stock = lookup(request.form.get("symbol"))
        if not stock:
            return apology("Please provide symbol")
        return render_template(
            "quoted.html",
            name=stock["name"],
            symbol=stock["symbol"],
            price=usd(stock["price"]),
        )


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    session.clear()
    if request.method == "GET":
        return render_template("register.html")
    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirmation")

        if not username:
            return apology("Must probvide username")
        if not password:
            return apology("Must provide password")

        # require password to have capital
        if password.lower() == password:
            return apology("Password must have capital letter")
        if not any(char.isdigit() for char in password):
            return apology("Passowrd must have a number")

        if not confirm:
            return apology("Must provide confirmation")

        if password != confirm:
            return apology("Password and Confirmation must match")

        hashp = generate_password_hash(password)

        if len(db.execute("SELECT * FROM users WHERE username = ?", username)) != 0:
            return apology("username already exists :(")

        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hashp)

        rows = db.execute("SELECT * FROM users WHERE username=?", username)

        session["user_id"] = rows[0]["id"]

        return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        user_id = session["user_id"]
        symbols = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = ?  GROUP BY symbol HAVING SUM(shares) > 0",
            user_id,
        )
        return render_template("sell.html", symbols=[row["symbol"] for row in symbols])
    else:
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        user_id = session["user_id"]

        if not symbol:
            return apology("Need to provide symbol")
        if not shares or int(shares) < 0:
            return apology("Need to provide valid shares")
        stock = lookup(symbol)
        if stock == None:
            return apology("Symbol not found")
        if shares < 0:
            return apology("Share not allowed")

        price = shares * stock["price"]
        balance = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[
            0
        ]["cash"]

        user_shares = db.execute(
            "SELECT shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol",
            user_id,
            symbol,
        )[0]["shares"]

        if int(shares) > int(user_shares):
            return apology("You do not have enough shares to sell")

        new_balance = balance + price
        new_user_shares = int(user_shares) - int(shares)

        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?", new_balance, session["user_id"]
        )
        db.execute(
            "UPDATE transactions SET shares = ? WHERE id = ?",
            new_user_shares,
            session["user_id"],
        )

        date = datetime.datetime.now()
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price, date) VALUES (?, ?, ?, ?, ?)",
            session["user_id"],
            stock["symbol"],
            (-1) * shares,
            usd(stock["price"]),
            date,
        )
        flash("Sold!")
        return redirect("/")

    return apology("TODO")
