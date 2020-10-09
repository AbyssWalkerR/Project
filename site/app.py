import mysql.connector
import re
import threading
import time
import yaml
import daw as WQ
from flask import (Flask, request, session, g, redirect, url_for, abort,
                   render_template, flash, make_response)
from flask_mail import Mail, Message
from flask_paginate import Pagination, get_page_args
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
conf = yaml.load(open('pass.yml'),Loader=yaml.FullLoader)
gemail = conf['user']['email']
gpwd = conf['user']['password']
dhost = conf['mysq']['user']
dpwd = conf['mysq']['pass']
datab = conf['mysq']['database']
dip = conf['mysq']['ip']
app = Flask(__name__)
app.config.from_object(__name__)
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = gemail
app.config['MAIL_DEFAULT_SENDER'] = gemail
app.config['MAIL_PASSWORD'] = gpwd
app.secret_key = 'development key'
mail = Mail(app)
chos ={
        'cnews': "Cnews",
        'dnewshard': "3Dnews",
        'dnewssoft': "3Dnews новости ПО",
        'itworld': "Itworld"
    }

sitess=['Cnews','3Dnews','3Dnews новости ПО','Itworld']

ip_ban_list = ['46.188.24.96','43.254.151.94','45.83.64.219']

@app.before_request
def before_request():
    g.db = mysql.connector.connect(host="localhost",
          user=dhost,
          passwd=dpwd,
          database=datab)
    ip = request.environ.get('REMOTE_ADDR')
    if ip in ip_ban_list:
        abort(403)
    cur = g.db.cursor()
    if request.cookies.get('remember2'):
        cur.execute("""select *
                from users where id=%s""",(request.cookies.get('remember'),))
        account=cur.fetchone()
        if account and request.cookies.get('remember2')==account[3]:
            session['loggedin'] = True
            session['id'] = account[0]
            session['name']=account[1]

@app.teardown_request
def teardown_request(exception):
    g.db.close()


@app.route('/profile')
def profile():
    if 'loggedin' in session:
        cur = g.db.cursor()
        cur.execute("""select *
                from users where id=%s""",(session['id'],))
        account=cur.fetchone()
        return render_template('acc/profile.html',account=account)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if not 'loggedin' in session:
        if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
            email = request.form.get('email')
            password = request.form.get('password')
            remember=False
            if request.form.get('remember'):
                remember=True

            cur = g.db.cursor()
            cur.execute("""select *
                    from users where email=%s""",(email,))
            account=cur.fetchone()
            if account and check_password_hash(account[3], password):

                session['loggedin'] = True
                session['id'] = account[0]
                session['name']=account[1]
                if remember:
                    co=make_response(redirect(url_for('profile')))
                    co.set_cookie('remember', str(account[0]),max_age=60*60*24*365*2)
                    co.set_cookie('remember2', str(account[3]),max_age=60*60*24*365*2)
                    return co
                return redirect(url_for('profile'))
            else:
                flash('Неверное имя пользователя или пароль')

        return render_template('acc/login.html')
    return redirect(url_for('profile'))

def async_send_mail(app, msg):
    with app.app_context():
        mail.send(msg)


def send_mail(subject, recipient, template, **kwargs):
    msg = Message(subject, sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[recipient])
    msg.html = render_template(template,  **kwargs)
    thr = threading.Thread(target=async_send_mail,  args=[app,  msg])
    thr.start()
    return thr

@app.route('/reset', methods=['GET','POST'])
def reset():
    if not 'loggedin' in session:
        if request.method == 'POST':
            email = request.form.get('email')
            valid=True
            if not email:
                valid=False
                flash('Ведите почту')
            if valid:
                cur = g.db.cursor()
                cur.execute("""select *
                        from users where email=%s""",(email,))
                account=cur.fetchone()
                if account:
                    password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
                    reset_link = url_for('forgotpass',token = password_reset_serializer.dumps(email, salt='sswqqda'),
            _external=True)
                    send_mail("Восстановление пароля на agreg.zapto.org",email,'mail/pass.html',link=reset_link)
                    flash('Сообщение отправлено')
                    return redirect(url_for('login'))
        return render_template('acc/reset.html')
    return redirect(url_for('profile'))

@app.route('/reset/<token>', methods=['GET','POST'])
def forgotpass(token):
    password_reset_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    email = password_reset_serializer.loads(token, salt='sswqqda', max_age=600)
    if email:
        if request.method == 'POST' :
            new_pass=request.form.get('new_password')
            valid=True
            if not new_pass:
                valid=False
                flash('Введите новый пароль')
            if valid:
                cur = g.db.cursor()
                cur.execute("""update users set password_hash=%s
                    where email=%s""",(generate_password_hash(new_pass, method='sha256'),email,))
                g.db.commit()
                flash('Пароль был изменен')
                return redirect(url_for('login'))
    else:
        flash('Ссылка истекла')
        return redirect(url_for('login'))
    return render_template('acc/passforgot.html', token=token)

@app.route('/logout')
def logout():
    if 'loggedin' in session:
        res=make_response(redirect(url_for('login')))
        res.set_cookie('remember',max_age=0 )
        res.set_cookie('remember2',max_age=0 )
        session.pop('loggedin', None)
        session.pop('id', None)
        session.pop('name', None)
        return res
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET','POST'])
def signup():
    if not 'loggedin' in session:
        if request.method == 'POST':
            email = request.form.get('email')
            name=request.form.get('name')
            password = request.form.get('password')
            valid = True
            if not name:
                valid = False
                flash('Нужно ввести имя/свой никнейм')
            if not password:
                valid = False
                flash('Нужно ввести пароль')
            if not email:
                valid = False
                flash('Нужно ввести почту')
            if valid:
                cur = g.db.cursor()
                cur.execute("""select *
                    from users where email=%s""",(email,))
                user=cur.fetchone()
                if user:
                    flash('Пользователь с такой почтой уже существует')
                elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                    flash('Неправильно была введена почта')
                elif not re.match(r'[А-Яа-яA-Za-z0-9]+', name):
                    flash('Имя должно содержать только буквы и цифры')
                elif not name or not password or not email:
                    flash('Заолните поля')
                else:
                    cur.execute("""insert into users(name, email, password_hash)
                 values(%s,%s,%s)""",(name,email,generate_password_hash(password, method='sha256'),))
                    g.db.commit()
                    flash('Вы зарегистрировались')
                    return redirect(url_for('login'))
        return render_template('acc/signup.html')
    return redirect(url_for('profile'))


@app.route('/edit/<id>', methods=['GET', 'POST'])
def edit(id = None):
    if 'loggedin' in session:
        if request.form:
            valid = True
            validpass=True
            cur = g.db.cursor()
            cur.execute("""select *
                from users where id=%s""",(id,))
            pers=cur.fetchone()
            name = request.form.get('name')
            email = request.form.get('email')
            parol = request.form.get('password')
            new_parol = request.form.get('new_password')
            if not name:
                valid = False
                flash('Поле имени не должно быть пустым')
            if not email:
                valid = False
                flash('Поле почты не должно быть пустым')
            if parol and not new_parol:
                valid = False
                flash('Введитье новый пароль')
            if not parol and new_parol:
                valid = False
                flash('Введитье старый пароль')
            if parol and new_parol and not check_password_hash(pers[3],parol):
                valid = False
                flash('Старый пароль не верен')
            if parol and new_parol and check_password_hash(pers[3],parol):
                validpass=False
            if valid and validpass:
                cur = g.db.cursor()
                cur.execute("""update users set name=%s, email=%s 
                where id=%s""",(name,email,id,))
                g.db.commit()
                return redirect(url_for('profile'))
            elif valid and not validpass:
                cur = g.db.cursor()
                cur.execute("""update users set name=%s,email=%s, password_hash=%s
                where id=%s""",(name,email,
                                generate_password_hash(new_parol, method='sha256'),id,))
                g.db.commit()
                flash('Пароль был изменен, ввойдите в аккаунт')
                return redirect(url_for('logout'))
            else:
                cur = g.db.cursor()
                cur.execute("""select *
                from users where id=%s""",(id,))
                row= cur.fetchone()
                user = { 'name': row[1],
                    'email': row[2],
                    'password_hash': row[3],
                    }

        else:
            if id:
                cur = g.db.cursor()
                cur.execute("""select *
                from users where id=%s""",(id,))
                row= cur.fetchone()
                user = { 'name': row[1],
                    'email': row[2],
                    'password_hash': row[3],
                    }
        return render_template('acc/edit.html', user=user)
    return redirect(url_for('login'))

@app.route('/<id>,<path:url>')
def recent(url,id):
    if 'loggedin' in session:
        id2=id+';'
        cur = g.db.cursor()
        cur.execute("""select *
                from users where id=%s""",(session['id'],))

        user=cur.fetchone()
        if user[4] is None:
            cur.execute("""update users set recent= %s
                where id=%s""",(id2,session['id'],))
            g.db.commit()
        else:
            a=user[4].split(';')
            a=list(filter(None,a))
            for w in a:
                if id==w:
                    a.remove(w)
                    break
            a.append(id)
            id2=';'.join(a)
            cur.execute("""update users set recent= %s
                where id=%s""",(id2,session['id'],))
            g.db.commit()
        return redirect(url,code=302)
    return redirect(url,code=302)



@app.route('/recent')
def recentacc():
    if 'loggedin' in session:
        cur = g.db.cursor()
        cur.execute("""select *
                from users where id=%s""",(session['id'],))
        user=cur.fetchone()
        news=[]
        if user[4] is not None:
            newsid=user[4].split(';')
            newsid=list(filter(None,newsid))
            newsid.reverse()
            page, per_page, offset = get_page_args(page_parameter='page',
                                               per_page_parameter='per_page')
            per_page = 20

            for k in newsid:
                cur.execute("""select *
                        from general where id=%s """,(k,))
                for row in cur.fetchall():
                    aq={
                        'id': row[0],
                        'title': row[1],
                        'link': row[2],
                        'description': row[3],
                        'image': row[4],
                        'date': row[5],
                        'source': row[6],
                        }
                news.append(aq.copy())

            pagination_news = get_news(page=page, per_page=per_page,news=news)
            pagination = Pagination(page=page, per_page=per_page, total=len(news),
                            css_framework='bootstrap4')
            return render_template('acc/recentacc.html', news=pagination_news,pagination=pagination)
        else:
            return render_template('acc/recentacc.html')
    else:
        return redirect(url_for('login'))

def get_news(page,news, per_page):
    offset = (page-1) * per_page
    return news[offset: offset + per_page]

@app.route('/s/<name>')
def delsource(name,url=None):
    if 'loggedin' in session:
        if not 'site' in session:
            sites=[]
            for q in sitess:
                sites.append(q)

            k=0
            for ke, val in chos.items():
                if val==name:
                    sites.remove(val)
                    k=0
                    break
                else:
                    k=1
            if k==1:
                flash('Не делай так больше')
                return render_template('main/index.html')
            else:
                session['site']=sites
                return redirect(url_for('index'))
        else:
            sites=session['site']
            if len(sites)!=1:
                k=0
                for ke, val in chos.items():
                    if val==name:
                        sites.remove(val)
                        k=0
                        break
                    else:
                        k=1
                if k==1:
                    flash('Не делай так больше')
                    return render_template('main/index.html')
                else:
                    session['site']=sites
                    return redirect(url_for('index'))
            else:
                flash('Количество источников 1')
                return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))

@app.route('/resetsource')
def ressource():
    if 'loggedin' in session:
        session.pop('site', None)
        return redirect(url_for('index'))
    return redirect(url_for('index'))

@app.route('/')
def index():
    page, per_page, offset = get_page_args(page_parameter='page',
                                           per_page_parameter='per_page')
    per_page = 20
    cur = g.db.cursor()
    if not 'site' in session:
        cur.execute("""select id, title, link, description, image, date, source
            from general order by date desc""")
        news = [ {
                'id': row[0],
                'title': row[1],
                'link': row[2],
                'description': row[3],
                'image': row[4],
                'date': row[5],
                'source': row[6],
                } for row in cur.fetchall() ]
    elif  'site' in session:
        sites=session['site']
        news=[]
        for i in sites:
            cur.execute("""select id, title, link, description, image, date,source
                from general where source=%s order by date desc """,(i,))
            for row in cur.fetchall():
                aq={
                    'id': row[0],
                    'title': row[1],
                    'link': row[2],
                    'description': row[3],
                    'image': row[4],
                    'date': row[5],
                    'source': row[6],
                    }
                news.append(aq.copy())
        news.sort(key=lambda x:x['date'],reverse=True)
    recomend={}
    if 'loggedin' in session:
        cur.execute("""select *
                from users where id=%s""",(session['id'],))
        user=cur.fetchone()
        recom=[]
        if user[4] is not None:
            newsid=user[4].split(';')
            newsid=list(filter(None,newsid))
            for k in newsid:
                cur.execute("""select *
                        from general where id=%s """,(k,))
                for row in cur.fetchall():
                    recom.append(row[1])
                    recom.append(row[3])
            recom = list(filter(None,(' '.join(recom).split(' '))))
            newrecom=[]
            for ele in recom:
                if ele not in newrecom:
                    newrecom.append(ele.replace(':',''))
            cur.execute("""select id, title, link, description, image, source
                        from general order by date desc """)
            dictrecom={}
            for rowe in cur.fetchall():
                    for rw in newrecom:
                        for x in rowe:
                            if isinstance(x, int):
                                x= str(x)
                                if rw in x:
                                    if rowe[0] not in dictrecom and str(rowe[0]) not in newsid:
                                       dictrecom[rowe[0]] = 1
                                    elif rowe[0] in dictrecom and str(rowe[0]) not in newsid:
                                        dictrecom[rowe[0]] += 1
                            else:
                                if rw.lower() in x.lower():
                                    if rowe[0] not in dictrecom and str(rowe[0]) not in newsid:
                                       dictrecom[rowe[0]] = 1
                                    elif rowe[0] in dictrecom and str(rowe[0]) not in newsid:
                                        dictrecom[rowe[0]] += 1

            v=list(dictrecom.values())
            k=list(dictrecom.keys())
            cur.execute("""select *
                    from general where id=%s """,(k[v.index(max(v))],))
            rec=cur.fetchone()
            recomend={
                    'id': rec[0],
                    'title': rec[1],
                    'link': rec[2],
                    'description': rec[3],
                    'image': rec[4],
                    'date': rec[5],
                    'source': rec[6],
                    }

    if recomend:
        pagination_news = get_news(page=page, per_page=per_page,news=news)
        pagination = Pagination(page=page, per_page=per_page, total=len(news),
                                css_framework='bootstrap4')
        return render_template('main/index.html',  naw="Главное",news=pagination_news,
                               pagination=pagination, recomend=recomend)
    else:
        pagination_news = get_news(page=page, per_page=per_page,news=news)
        pagination = Pagination(page=page, per_page=per_page, total=len(news),
                                css_framework='bootstrap4')
        return render_template('main/index.html',  naw="Главное",news=pagination_news,
                               pagination=pagination)



@app.route('/index2/<neww>')
def index2(neww):
    if neww in chos:
        page, per_page, offset = get_page_args(page_parameter='page',
                                           per_page_parameter='per_page')
        w=chos.get(neww)
        per_page = 20
        cur = g.db.cursor()
        cur.execute("""select id, title, link, description, image, date,source
                from general where source=%s order by date desc """,(w,))
        news = [ {
            'id': row[0],
            'title': row[1],
            'link': row[2],
            'description': row[3],
            'image': row[4],
            'date': row[5],
            'source': row[6],
            } for row in cur.fetchall() ]


        pagination_news = get_news(page=page, per_page=per_page,news=news)
        pagination = Pagination(page=page, per_page=per_page, total=len(news),
                            css_framework='bootstrap4')
        return render_template('main/index2.html', news=pagination_news,
                           pagination=pagination, naw=w)
    else:
        flash('Не делай так больше')
        return render_template('main/index.html')

@app.route('/books')
def books():
    page, per_page, offset = get_page_args(page_parameter='page',
                                               per_page_parameter='per_page')
    per_page = 20
    cur = g.db.cursor()
    cur.execute("""select *
            from itebook order by date desc """)
    news = [ {
        'id': row[0],
        'title': row[1],
        'link': row[2],
        'description': row[3],
        'image': row[4],
        'date': row[5],
        } for row in cur.fetchall() ]

    pagination_news = get_news(page=page, per_page=per_page,news=news)
    pagination = Pagination(page=page, per_page=per_page, total=len(news),
                                css_framework='bootstrap4')
    return render_template('main/books.html', news=pagination_news,
                               pagination=pagination,naw="Itebooks главное")

@app.route('/search')
def search():
    if request.args.get('search') and  request.args.get('search2'):
        a=request.args.get('search')
        c=request.args.get('search2')
        b=a.split()

        k=0
        for ke, val in chos.items():
            if val==c:
                g.w=ke
                k=0
                break
            else:
                k=1
                g.w=None

        if k==1:
            if c!='Главное' and c!='Itebooks главное':
                flash('Не делай так больше')
                return render_template('main/index.html')

        if c!='Itebooks главное':
            page, per_page, offset = get_page_args(page_parameter='page',
                                               per_page_parameter='per_page')
            per_page = 20
            cur = g.db.cursor()
            if g.w is not None:
                cur.execute("""select title, description, source
                    from general where source=%s order by date desc """, (c,))
            else:
                cur.execute("""select title, description, source
                    from general order by date desc """)
            news=[]
            res = []
            for rowe in cur.fetchall():
                for rw in b:
                    for x in rowe:
                        if rw.lower() in x.lower():
                            res.append(x)
                            if len(res)>0:
                                if g.w is not None:
                                    cur.execute("""select *
                                        from general where source=%s and title=%s order by date desc """,(c,rowe[0],))
                                else:
                                    cur.execute("""select *
                                        from general where title=%s order by date desc """, (rowe[0],))
                                for row in cur.fetchall():
                                    aq={
                                        'id': row[0],
                                        'title': row[1],
                                        'link': row[2],
                                        'description': row[3],
                                        'image': row[4],
                                        'date': row[5],
                                        'source': row[6],
                                        }
                                    news.append(aq.copy())
                                res=[]

                                # news.append( [ {
                                #     'id': row[0],
                                #     'title': row[1],
                                #     'link': row[2],
                                #     'description': row[3],
                                #     'image': row[4],
                                #     'date': row[5],
                                #     'source': row[6],
                                #     } for row in cur.fetchall()].copy())

            if len(news)>0:
                # aw=[dict(t) for t in {tuple(d[0].items()) for d in news}]
                aw=[]
                seen=set()
                for d in news:
                    t= tuple(d.items())
                    if t not in seen:
                        seen.add(t)
                        aw.append(d)
                pagination_news = get_news(page=page, per_page=per_page,news=aw)
                pagination = Pagination(page=page, per_page=per_page, total=len(aw),
                                css_framework='bootstrap4')
                return render_template('main/search.html', news=pagination_news,pagination=pagination, naw=c)
            else:
                flash('Ничего не найдено')
                return render_template('main/search.html', naw=c)
        elif c=='Itebooks главное':
            page, per_page, offset = get_page_args(page_parameter='page',
                                               per_page_parameter='per_page')
            per_page = 20
            cur = g.db.cursor()
            g.b=c
            cur.execute("""select title, description
                from itebook order by date desc """)
            news=[]
            res = []
            for rowe in cur.fetchall():
                for rw in b:
                    for x in rowe:
                        if rw.lower() in x.lower():
                            res.append(x)
                            if len(res)>0:
                                cur.execute("""select *
                                    from itebook where title=%s order by date desc """, (rowe[0],))
                                for row in cur.fetchall():
                                    aq={
                                        'id': row[0],
                                        'title': row[1],
                                        'link': row[2],
                                        'description': row[3],
                                        'image': row[4],
                                        'date': row[5],
                                        }
                                    news.append(aq.copy())
                                res=[]


            if len(news)>0:
                # aw=[dict(t) for t in {tuple(d[0].items()) for d in news}]
                aw=[]
                seen=set()
                for d in news:
                    t= tuple(d.items())
                    if t not in seen:
                        seen.add(t)
                        aw.append(d)
                pagination_news = get_news(page=page, per_page=per_page,news=aw)
                pagination = Pagination(page=page, per_page=per_page, total=len(aw),
                                css_framework='bootstrap4')
                return render_template('main/search.html', news=pagination_news,pagination=pagination, naw=c)
            else:
                flash('Ничего не найдено')
                return render_template('main/search.html', naw=c)
    else:
        c=request.args.get('search2')
        if c!='Главное' and c!='Itebooks главное':
            for ke, val in chos.items():
                if val==c:
                    g.w=ke
            flash('Ошибка в поиске')
            return redirect(url_for('index2', neww=g.w))
        elif c=='Главное':
            flash('Ошибка в поиске')
            return redirect(url_for('index', naw=c))
        elif c=='Itebooks главное':
            g.b=c
            flash('Ошибка в поиске')
            return redirect(url_for('books', naw=c))



def async_download():
    while thw.is_alive():
        for ke in WQ.miltiplefunc:
            getattr(WQ.Agreg,WQ.miltiplefunc.get(ke, 'waw'))()
        time.sleep(180)



if __name__ == '__main__':

    thw=threading.Thread(target=async_download)
    thw.start()
    # домен сайта - hrkq.ddns.net
    app.run(host=dip,port='80')
    # app.run(debug=True)


