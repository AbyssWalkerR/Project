import mysql.connector
import requests
import datetime
import time
import yaml
from bs4 import BeautifulSoup
from pip._vendor.distlib.compat import raw_input

conf = yaml.load(open('pass.yml'),Loader=yaml.FullLoader)
dhost = conf['mysq']['user']
dpwd = conf['mysq']['pass']
datab = conf['mysq']['database']
mydb=mysql.connector.connect(
host="localhost",
user=dhost,
passwd=dpwd,
database=datab)
mycursor = mydb.cursor(buffered=True)

class Agreg:

    @staticmethod
    def cnewsdata():
          r=requests.get('https://cnews.ru/inc/rss/news.xml')
          soup = BeautifulSoup(r.text,'xml')
          item = soup.findAll('item')
          # mycursor.execute("""CREATE TABLE IF NOT EXISTS `cnews` (id int(11) NOT NULL AUTO_INCREMENT KEY,
          #                      title VARCHAR(255),link VARCHAR(255),description VARCHAR(8000),image VARCHAR(255),date DATETIME)""")
          for getfeed in item:
                sql="INSERT INTO general (title,link,description,image,date,source) VALUES (%s,%s,%s,%s,%s,%s)"
                a=getfeed.title.text
                b=getfeed.link.text
                c=(getfeed.description.text).replace('<p>','').replace('</p>','').replace('<br>','').replace('\n','')\
                    .replace('<p class="normal">','').replace('<div>','').replace('<p class="western">','').replace('</div>','')\
                    .replace('<strong mso-bidi-font-weight:normal""="">','').replace('</strong>','')\
                    .replace('«<a href="https://events.cnews.ru/events/ikt_v_finansovom_sektore_2020.shtml">','')\
                    .replace('</a>»','')
                #if len(c) >= 255:
                   # c= c[:-(len(c)-255)]

                #print(c.replace(c[len(c)-3:],'...'), len(c))
                d=getfeed.enclosure['url']
                e = (getfeed.pubDate.text)[5:][:-6]
                w = e[:-9]
                e = (getfeed.pubDate.text)[:-6][-9:]
                w2=w[:2]
                w3=w[3:]
                w4=w3[:3].replace('Jan','01').replace('Feb','02').replace('Mar','03').replace('Apr','04')\
                    .replace('May','05').replace('Jun','06').replace('Jul','07').replace('Aug','08').replace('Sep','09')\
                    .replace('Oct','10').replace('Nov','11').replace('Dec','12')
                w5=w3[4:]+"-"+w4+"-"+w2
                e=w5+e
                f='Cnews'
                val = (a,b,c,d,e,f)
                mycursor.execute(
                "SELECT title FROM general WHERE title = %s GROUP BY title",
                (a,))
                rw=mycursor.rowcount
                if rw == 0:
                    mycursor.execute("alter table general auto_increment=1")
                    mycursor.execute(sql,val)
                    mydb.commit()
                    print('cnews inserted')
          print('All cnews data inserted')

    @staticmethod
    def dnewshard():
          r=requests.get('https://3dnews.ru/news/rss/')
          soup = BeautifulSoup(r.text,'xml')
          item = soup.findAll('item')
          # mycursor.execute("""CREATE TABLE IF NOT EXISTS `dnewshard` (id int(11) NOT NULL AUTO_INCREMENT KEY,
          #                      title VARCHAR(255),link VARCHAR(255),description VARCHAR(8000),image VARCHAR(255),date DATETIME)""")
          for getfeed in item:
                sql="INSERT INTO general (title,link,description,image,date,source) VALUES (%s,%s,%s,%s,%s,%s)"
                a=getfeed.title.text
                b=getfeed.link.text
                if (getfeed.description.text).replace('<p>','').replace('</p>','').replace('<br>','').replace('\n','')\
                    .replace('<div>','').replace('</div>','').replace('</strong>','').replace('</a>»','').replace('&mdash;','')\
                    .replace('&nbsp;','').replace('&laquo;','').replace('&raquo;','').replace('&raquo;','')\
                    .replace('&middot;','').replace('&amp;','').replace('								','').startswith('<img align'):
                    c=(getfeed.description.text).replace('<p>','').replace('</p>','').replace('<br>','').replace('\n','')\
                    .replace('<div>','').replace('</div>','').replace('</strong>','').replace('</a>»','').replace('&mdash;','')\
                    .replace('&nbsp;','').replace('&laquo;','').replace('&raquo;','').replace('&raquo;','')\
                    .replace('&middot;','').replace('&amp;','').replace('								','')[138:].replace('>','')
                else:
                    c=(getfeed.description.text).replace('<p>','').replace('</p>','').replace('<br>','').replace('\n','')\
                    .replace('<div>','').replace('</div>','').replace('</strong>','').replace('</a>»','').replace('&mdash;','')\
                    .replace('&nbsp;','').replace('&laquo;','').replace('&raquo;','').replace('&raquo;','')\
                    .replace('&middot;','').replace('&amp;','').replace('								','')
                d=getfeed.enclosure['url']
                e = (getfeed.pubDate.text)[5:][:-6]
                w = e[:-9]
                e = (getfeed.pubDate.text)[:-6][-9:]
                w2=w[:2]
                w3=w[3:]
                w4=w3[:3].replace('Jan','01').replace('Feb','02').replace('Mar','03').replace('Apr','04')\
                    .replace('May','05').replace('Jun','06').replace('Jul','07').replace('Aug','08').replace('Sep','09')\
                    .replace('Oct','10').replace('Nov','11').replace('Dec','12')
                w5=w3[4:]+"-"+w4+"-"+w2
                e=w5+e
                f='3Dnews'
                val = (a,b,c,d,e,f)
                mycursor.execute(
                "SELECT title FROM general WHERE title = %s GROUP BY title",
                (a,))
                rw=mycursor.rowcount
                if rw == 0:
                    mycursor.execute("alter table general auto_increment=1")
                    mycursor.execute(sql,val)
                    mydb.commit()
                    print('dnewshard inserted')
          print('All dnewshard data inserted')

    @staticmethod
    def dnewssoft():
          r=requests.get('https://3dnews.ru/software/rss')
          soup = BeautifulSoup(r.text,'xml')
          item = soup.findAll('item')
          # mycursor.execute("""CREATE TABLE IF NOT EXISTS `dnewssoft` (id int(11) NOT NULL AUTO_INCREMENT KEY,
          #                      title VARCHAR(255),link VARCHAR(255),description VARCHAR(8000),image VARCHAR(255),date DATETIME)""")
          for getfeed in item:
                sql="INSERT INTO general (title,link,description,image,date,source) VALUES (%s,%s,%s,%s,%s,%s)"
                a=getfeed.title.text
                b=getfeed.link.text
                c=(getfeed.description.text).replace('<p>','').replace('</p>','').replace('<br>','').replace('\n','')\
                    .replace('<div>','').replace('</div>','').replace('</strong>','').replace('</a>»','').replace('&mdash;','')\
                    .replace('&nbsp;','').replace('&laquo;','').replace('&raquo;','').replace('&raquo;','')\
                    .replace('&middot;','').replace('&amp;','').replace('								','')[138:].replace('>','')
                d=getfeed.enclosure['url']
                e = (getfeed.pubDate.text)[5:][:-6]
                w = e[:-9]
                e = (getfeed.pubDate.text)[:-6][-9:]
                w2=w[:2]
                w3=w[3:]
                w4=w3[:3].replace('Jan','01').replace('Feb','02').replace('Mar','03').replace('Apr','04')\
                    .replace('May','05').replace('Jun','06').replace('Jul','07').replace('Aug','08').replace('Sep','09')\
                    .replace('Oct','10').replace('Nov','11').replace('Dec','12')
                w5=w3[4:]+"-"+w4+"-"+w2
                e=w5+e
                f='3Dnews новости ПО'
                val = (a,b,c,d,e,f)
                mycursor.execute(
                "SELECT title FROM general WHERE title = %s GROUP BY title",
                (a,))
                rw=mycursor.rowcount
                if rw == 0:
                    mycursor.execute("alter table general auto_increment=1")
                    mycursor.execute(sql,val)
                    mydb.commit()
                    print('dnewssoft inserted')
          print('All dnewssoft data inserted')

    @staticmethod
    def itebooks():
          a=["1","2","3","4"]
          for i in a:
              r=requests.get('http://it-ebooks.ru/publ/?page'+str(i))
              soup = BeautifulSoup(r.text,'lxml')
              item = soup.findAll(class_='eBlock')
              for getfeed in item:
                    sql="INSERT INTO itebook (title,link,description,image,date) VALUES (%s,%s,%s,%s,%s)"
                    a=getfeed.find(class_='eTitle').text
                    b='http://it-ebooks.ru'+getfeed.find(class_='eTitle').find('a').get('href')
                    c=getfeed.find(class_='MsoNormal').text
                    d='http://it-ebooks.ru'+getfeed.find(class_='eMessage').find('img').get('src')
                    e=getfeed.find(class_='eDetails').find(class_="e-date").find(class_='ed-value').text
                    if e=='Сегодня':
                        e=datetime.date.today().strftime('%Y-%m-%d')
                    elif e=='Вчера':
                        e=(datetime.date.today()-datetime.timedelta(days=1)).strftime('%Y-%m-%d')
                    else:
                        year=e[-4:]
                        e=e[:-5]
                        day=e[:2]
                        mounth=e[-2:]
                        e=year+"-"+mounth+"-"+day
                    val = (a,b,c,d,e)
                    mycursor.execute(
                    "SELECT title FROM itebook WHERE title = %s GROUP BY title",
                    (a,))
                    rw=mycursor.rowcount
                    if rw == 0:
                        mycursor.execute("alter table itebook auto_increment=1")
                        mycursor.execute(sql,val)
                        mydb.commit()
                        print('itbooks inserted')
          print('All itbooks data inserted')

    @staticmethod
    def itworld():
          a=["1","21","41","61"]
          for i in a:
              r=requests.get('https://www.cio.com/category/technology-business/?start='+str(i))
              soup = BeautifulSoup(r.text,'lxml')
              item = soup.findAll(class_='river-well article')
              # mycursor.execute("""CREATE TABLE IF NOT EXISTS `itworld` (id int(11) NOT NULL AUTO_INCREMENT KEY,
              #                  title VARCHAR(500),link VARCHAR(1000),description VARCHAR(8000),image VARCHAR(1000),date DATETIME)""")
              for getfeed in item:
                    sql="INSERT INTO general (title,link,description,image,date,source) VALUES (%s,%s,%s,%s,%s,%s)"
                    a=getfeed.h3.text.replace('\n','')
                    if 'www' not in getfeed.find('a').get('href'):
                        b='https://www.cio.com'+getfeed.find('a').get('href')
                    else:
                        b=getfeed.find('a').get('href')
                    c=getfeed.h4.text
                    if getfeed.find(itemprop='image'):
                        d=getfeed.find(itemprop='image').get('data-original')
                    else:
                        d=''
                    qr=requests.get(b)
                    soup2 = BeautifulSoup(qr.text,'lxml')
                    e = soup2.find(itemprop='datePublished').get('content').replace('-0700','').replace('-0800','').replace('+01:00','').replace('T',' ')
                    f='Itworld'
                    val = (a,b,c,d,e,f)
                    mycursor.execute(
                    "SELECT title FROM general WHERE title = %s GROUP BY title",
                    (a,))
                    rw=mycursor.rowcount
                    if rw == 0:
                        mycursor.execute("alter table general auto_increment=1")
                        mycursor.execute(sql,val)
                        mydb.commit()
                        print('itworld inserted')
          print('All itworld data inserted')
    @staticmethod
    def waw():
        print("no in agreg")



miltiplefunc ={
        'cnews': "cnewsdata",
        '3dnews-hard': "dnewshard",
        '3dnews-soft': "dnewssoft",
        'it-ebooks': "itebooks",
        'itworld': "itworld"
    }


def main():
    print('Список доступных ресурсов')
    for key in miltiplefunc:
        print (key)
    inp=['']
    print('Введите нужный ресурс, или exit для выхода')
    while inp!='exit':
        inp=raw_input()
        if inp!='exit':
            getattr(Agreg,miltiplefunc.get(inp, 'waw'))()
            print('Список доступных ресурсов')
            for key in miltiplefunc:
                print (key)
            print('Введите нужный ресурс, или exit для выхода')
    else:
        print('end')


if __name__ == '__main__':

  main()


