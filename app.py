import os
import re # regex

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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

db.execute("""
            CREATE TABLE IF NOT EXISTS owned_stocks (
                userId INTEGER NOT NULL,
                Symbol TEXT NOT NULL,
                Name TEXT NOT NULL,
                Amount INTEGER NOT NULL,
                Price NUMERIC NOT NULL,
                PRIMARY KEY (userId, Symbol)
            )
        """)

db.execute("""
            CREATE TABLE IF NOT EXISTS history (
                userId INTEGER NOT NULL,
                Symbol TEXT NOT NULL,
                Record INTEGER NOT NULL,
                Price NUMERIC NOT NULL,
                Timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

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
    stocks = db.execute("SELECT * from owned_stocks WHERE userId = ?", session["user_id"])
    if stocks:
        users_cash = db.execute("SELECT cash from users WHERE id = ?", session["user_id"])[0]["cash"]
        # 突然發現金額應該要用即期的？也就是要 lookup(symbol)
        stock_values = db.execute("SELECT SUM(Amount * Price) AS stock_values From owned_stocks WHERE userId = ?", session["user_id"])[0]["stock_values"] # 在這裡處理，而不是 template/ jinja 端
        total = users_cash + stock_values
        return render_template("index.html", owned_stocks=stocks, stock_values=stock_values, users_cash=users_cash, total=total)
    return apology("CLICK buy and GO SHOPPING", 200) # bug，沒加 code 會出事～


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("symbol is blank")

        shares = request.form.get("shares")
        if not shares.isdigit() or int(shares) < 0:
            return apology("not a positive integer")

        quote = lookup(symbol)
        if not quote:
            return apology("fill in the correct symbol")

        price = quote.get("price")
        name = quote.get("name")
        id = session["user_id"]
        # 如果 quote.price * shares < users.cash 的錢
        cash = db.execute("SELECT cash FROM users WHERE id = ?", id)
        if price * int(shares) > cash[0]["cash"]:
            return apology("can not afford")

        existing_stock = db.execute("SELECT * from owned_stocks WHERE userId = ? AND Symbol = ?", id, symbol)
        if existing_stock:
            # price = (舊價格*舊數量 + 新價格＊新數量)/(新＋舊數量) # 不用管價格？因為每次都會更改、若要長期分析才需要管舊價格
            db.execute("UPDATE owned_stocks SET Amount = Amount + ?, Price = ? WHERE userId = ? AND Symbol = ?", int(shares), price, id, symbol)
        else:
            db.execute("INSERT INTO owned_stocks (userId, Symbol, Name, Amount, Price) VALUES(?, ?, ?, ?, ?)", id, symbol, name, shares, price)
        # primary key 很重要，弄錯的話會跳 valueError: unique constraint
        db.execute("INSERT INTO history (userId, Symbol, Record, Price) VALUES(?, ?, ?, ?)", id, symbol, shares, price)
        db.execute("UPDATE users SET cash = cash - ? WHERE id = ?", price * int(shares), id)
        return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT * from history WHERE userId = ? ORDER BY Timestamp DESC", session["user_id"])
    if history:
        return render_template("history.html", history=history)
    return apology("No transaction yet")


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        # notice how login “remembers” that a user is logged
        # in by storing his or her user_id, an INTEGER, in session.

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")

        # 利用 lookup function 回傳一個 dic => 存在 quote
        quote = lookup(symbol)
        # 若回傳 none (即鍵入錯誤/查找不到)
        if not quote:
            return apology("wrong symbol")
        # show the symbol price
        return render_template("quoted.html", quote=quote)

    return render_template("quote.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not (username and password and confirmation):
            return apology("Please fill in all fields")

        existing_user = db.execute("SELECT * FROM users WHERE username = ?", username)
        if existing_user:
            return apology("Username already exists")

        if password != confirmation:
            return apology("Passwords do not match")


        # regex
        pattern = "^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$"
        result = re.findall(pattern, password)
        if (result):
            # store data
            hash = generate_password_hash(password)
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)
        else:
            return apology("Password is too simple")

        # register success & immediate log in
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]
        return redirect("/") # 302 for redirect (但自從 / 正確處理 200 後就沒問題了)

    return render_template("register.html")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    id = session["user_id"]
    stocks = db.execute("SELECT * from owned_stocks WHERE userId = ?", id)
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("you don't own any stocks yet")

        current_shares = db.execute("SELECT Amount from owned_stocks WHERE userId = ? AND Symbol = ?", id, symbol)[0]["Amount"]
        if int(current_shares) < 1:
            return apology("You didn't own this stock") # rare condition (hack?)

        minus_shares = request.form.get("shares")
        if not minus_shares.isdigit() or int(minus_shares) < 0:
            return apology("not a positive integer")
        if int(minus_shares) > int(current_shares):
            return apology("You sold more than you owned.")

        quote = lookup(symbol)
        if not quote:
            return apology("fill in the correct symbol")
        price = quote.get("price") # 新價格

        existing_stock = db.execute("SELECT * from owned_stocks WHERE userId = ? AND Symbol = ?", id, symbol)
        if existing_stock:
            db.execute("UPDATE owned_stocks SET Amount = Amount - ? WHERE userId = ? AND Symbol = ?", int(minus_shares), id, symbol)
        else:
            return apology("you don't own any stocks yet")
        # 儲存這次的價格以及返回金額
        db.execute("INSERT INTO history (userId, Symbol, Record, Price) VALUES(?, ?, -CAST(? AS NUMERIC), ?)", id, symbol, minus_shares, price)
        db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", price * int(minus_shares), id)
        return redirect("/") # TODO 設計一個顯示 sold TSLA 3 的一條文字
    return render_template("sell.html", owned_stocks=stocks)
