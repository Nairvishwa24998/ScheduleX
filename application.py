import os
import re
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_mail import Mail, Message
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, date
import requests
import sqlalchemy

app = Flask(__name__)

app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER")
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")

mail = Mail(app)

app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

lis = {"CR": "Cases Received", "BG": "Bills Given", "PR": "Payment Received"}

db = SQL("sqlite:///schedule.db")


def error(msg):
    value = ""

    def convert(msg):
        if " " in msg:
            value = msg.replace(" ", "_")
        else:
            value = msg
        return value

    a = convert(msg)
    return render_template("error.html", msg=msg, a=a)


def error1(msg):
    value = ""

    def convert(msg):
        if " " in msg:
            value = msg.replace(" ", "_")
        else:
            value = msg
        return value

    a = convert(msg)
    return render_template("error1.html", msg=msg, a=a)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not request.form.get("username") or not request.form.get("password"):
            return error("Need to fill both the blanks!")
        else:
            username = request.form.get("username")
            password = request.form.get("password")
            if len(db.execute("SELECT username FROM users WHERE username == ?", username)) == 0:
                return error("Incorrect Username or Password entered")
            else:
                storedpass = db.execute("SELECT password FROM users WHERE username == ?", username)[0]["password"]
                if len(db.execute("SELECT username FROM users WHERE username == ?",
                                  username)) != 0 and check_password_hash(storedpass, password) == True:
                    session["user_id"] = db.execute("SELECT id FROM users WHERE username == ?", username)[0]["id"]
                    return render_template("loggedin.html", username=username, lis=lis)
                else:
                    return error("Incorrect Username or Password entered")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email = request.form.get("email")
        confirmation = request.form.get("confirmation")
        if not username or not password or not email or not confirmation:
            return error("Need to fill all the blanks!")
        elif len(db.execute("SELECT username from users WHERE username == ?", username)) != 0:
            return error("Username already exists")
        elif len(db.execute("SELECT email from users WHERE email == ?", email)) != 0:
            return error("Email already registered")
        else:
            if confirmation != password:
                return error("passwords don't match")
            elif requests.get("https://isitarealemail.com/api/email/validate", params={'email': email}).json()[
                'status'] != "valid":
                return error("invalid email id")
            else:
                dates = date.today()
                message = Message("Successful Registration!", recipients=[email])
                message.body = "You have succesfully registered to ScheduleX, {}.This email was sent to {} automatically. Please do not reply to this.".format(
                    username, email)
                mail.send(message)
                hashed = generate_password_hash(password)
                db.execute("INSERT INTO users (username,password,email,registrationdate) VALUES(?,?,?,?)", username,
                           hashed, email, dates)
                return redirect('/login')
    else:
        return render_template("register.html")


@app.route("/loggedin", methods=["GET", "POST"])
def loggedin():
    if request.method == "POST":
        if not request.form.get("casename") or not request.form.get("choice") or not request.form.get("fees"):
            return error1("You need to fill the required areas! ")
        elif (request.form.get("fees")).isdigit() == False:
            return error1("Fees has to be a positive number")
        else:
            casename = request.form.get("casename")
            chosen = str(request.form["choice"]).lower()
            userid = session["user_id"]
            fees = int(request.form.get("fees"))
            if fees < 0:
                return error1("Fees cannot be a negative number")

            transacted = str(datetime.now())[:-7]
            db.execute("INSERT INTO ?(user_id, name, transacted, fees) VALUES(?,?,?,?)", chosen, userid, casename,
                       transacted, fees)
            chosen = lis[chosen.upper()]
            return render_template("loggedinc.html", casename=casename, chosen=chosen, transacted=transacted)


@app.route("/mainpage", methods=["GET"])
def mainpage():
    username = db.execute("SELECT username FROM users WHERE id == ?", session["user_id"])[0]["username"]
    return render_template("loggedin.html", username=username, lis=lis)


@app.route("/casesreceived", methods=["GET", "POST"])
def casesreceived():
    cr = db.execute("SELECT name,transacted,fees FROM cr WHERE user_id == ?", session["user_id"])
    if request.method == "GET":
        return render_template("casesreceived.html", cr=cr)
    else:
        case = request.form.get("casesr")
        db.execute("DELETE FROM cr WHERE name ==  ? and user_id == ?", case, session["user_id"])
        cr = db.execute("SELECT name,transacted,fees FROM cr WHERE user_id == ?", session["user_id"])
        return render_template("casesreceived.html", cr=cr)


@app.route("/billsgiven", methods=["GET", "POST"])
def billsgiven():
    bg = db.execute("SELECT name,transacted,fees FROM bg WHERE user_id == ?", session["user_id"])
    if request.method == "GET":
        return render_template("billsgiven.html", bg=bg)
    else:
        case = request.form.get("casesb")
        db.execute("DELETE FROM bg WHERE name ==  ? and user_id == ?", case, session["user_id"])
        bg = db.execute("SELECT name,transacted,fees FROM bg WHERE user_id == ?", session["user_id"])
        return render_template("billsgiven.html", bg=bg)


@app.route("/paymentreceived", methods=["GET", "POST"])
def paymentreceived():
    pr = db.execute("SELECT name, transacted, fees FROM pr WHERE user_id == ?", session["user_id"])
    if request.method == "GET":
        return render_template("paymentreceived.html", pr=pr)
    else:
        case = request.form.get("casesp")
        db.execute("DELETE FROM pr WHERE name ==  ? and user_id == ?", case, session["user_id"])
        pr = db.execute("SELECT name,transacted,fees FROM pr WHERE user_id == ?", session["user_id"])
        return render_template("paymentreceived.html", pr=pr)


@app.route("/crbnb", methods=["GET"])
def casesreceivedbutnotbilled():
    userid = session["user_id"]
    lis1 = db.execute("SELECT name,transacted FROM cr WHERE name NOT IN (SELECT name FROM bg) AND user_id == ?",
                      userid)
    return render_template("crbnb.html", lis1=lis1)


@app.route("/bgbnp", methods=["GET"])
def billsgivenbutnotpaid():
    userid = session["user_id"]
    lis2 = db.execute("SELECT name,transacted FROM bg WHERE name NOT In (SELECT name FROM pr) AND user_id == ?",
                      userid)
    return render_template("bgbnp.html", lis2=lis2)


@app.route("/additionalinsights", methods=["GET"])
def additionalinsights():
    if request.method == "GET":
        return render_template("additionalinsights.html")


@app.route("/emailinsights", methods=["GET"])
def emailinsights():
    userid = session["user_id"]
    namemail = db.execute("SELECT username,email FROM users WHERE id == ?", userid)
    lis1 = db.execute("SELECT name,transacted FROM cr WHERE name NOT IN (SELECT name FROM bg) AND user_id == ?",
                      userid)
    lis2 = db.execute("SELECT name,transacted FROM bg WHERE name NOT In (SELECT name FROM pr) AND user_id == ?",
                      userid)
    message = Message("Your updates!", recipients=[namemail[0]["email"]])
    message.body = "Please find your updates below."
    message.html = render_template("mailbody.html", lis1=lis1, lis2=lis2)
    mail.send(message)
    name = namemail[0]["username"]
    email = namemail[0]["email"]
    return render_template("emailinsights.html", name=name, email=email)


@app.route('/edit', methods=["POST", "GET"])
def editinfo():
    if request.method == "POST":
        password = request.form.get("password")
        if not password:
            return error1("You need to enter your password!")
        else:
            userid = session["user_id"]
            hpassword = db.execute("SELECT password FROM users WHERE id == ?", userid)[0]["password"]
            if check_password_hash(hpassword, password) == True:
                return redirect("/edit1")
            else:
                return error1("Incorrect Password")
    else:
        return render_template("editinformation.html")


@app.route('/edit1', methods=["POST", "GET"])
def editinfo1():
    if request.method == "POST":
        password = request.form.get("password")
        userid = session["user_id"]
        hpassword = db.execute("SELECT password FROM users WHERE id == ?", userid)[0]["password"]
        if not password:
            return error1("You need to have something as your password!")
        else:
            name = db.execute("SELECT username FROM users WHERE id == ?", userid)[0]["username"]
            if check_password_hash(hpassword, password) == True:
                return error1("New Password cannot be old password")
            else:
                hashpass = generate_password_hash(password)
                db.execute("UPDATE users SET password = ? WHERE id == ?", hashpass, userid)
                return render_template("passwordchange.html", name=name)
    if request.method == "GET":
        return render_template("editinformation1.html")


if __name__ == "__main__":
    app.run(debug=True)